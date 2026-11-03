#!/usr/bin/env python3
"""Private Waze realtime server, stage 1: mitmproxy addon that answers
rtserver/distrib/login and /command itself instead of forwarding to Waze.

How it answers
  * Every captured request/response pair in ~/waze_capture is a template, keyed
    by the request's "signature" (which legacy commands + which typed commands).
  * A new request with a known signature gets that template's response, with
    timestamps moved to "now".
  * Real drivers (add_wazer 2004) and alerts (add_alert_action 2708) from the
    capture are DROPPED and replaced by the entries in ~/waze_private/world.json
    that fall inside the map area the app reports.

    "Get started" in the app sends rtserver/distrib/static with an empty `register` command. This
    server answers it by creating a guest account in auth.py's store (random name + password, hashed)
    and returning it as register_successful, like Waze does. Startup syncs the capture has no template
    for (favorites, preferences, token, gaming status) get best-effort replies; the log says which.

    mitmdump -s ~/Downloads/pserver.py            # serve (PSERVER_STRICT=1 blocks unknown rtserver paths)
    python3 pserver.py --init-world LON LAT       # write a synthetic world.json near you
    python3 pserver.py --signatures               # list what the capture can answer
    python3 pserver.py --init-marketplace         # sample custom cars: ~/waze_private/marketplace.json + files/
    python3 pserver.py --selftest                 # replay captured requests, compare to captured replies
"""
import argparse
import base64
import collections
import copy
import gzip
import json
import mimetypes
import os
import pathlib
import re
import secrets
import struct
import sys
import time
import urllib.parse
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import auth  # noqa: E402
import decode as D  # noqa: E402
from google.protobuf import descriptor_pb2  # noqa: E402

try:
    from mitmproxy import http
except ImportError:  # selftest / CLI work without mitmproxy
    http = None

HOME = pathlib.Path.home()
CAP = pathlib.Path(os.environ["WAZE_CAPTURE_DIR"]) if os.environ.get("WAZE_CAPTURE_DIR") else HOME / "waze_capture"
DESC = HOME / "waze_protos" / "descriptors.desc"
WORLD = HOME / "waze_private" / "world.json"
WORLD_ELEMS = {2004: "add_wazer", 2708: "add_alert_action"}
TIME_ELEMS = {2150, 2168}          # response_timestamp, sync_config_response
DROP_HEADERS = {"content-length", "content-encoding", "transfer-encoding", "connection"}


PRIV = HOME / "waze_private"
UNSEEN = PRIV / "unseen"


def log(msg):
    print(f"[pserver] {msg}", file=sys.stderr, flush=True)
    try:
        PRIV.mkdir(parents=True, exist_ok=True)
        with (PRIV / "pserver.log").open("a") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except OSError:
        pass


def save_unseen(tag, body):
    """Keep a request we have no template for. It is exactly what the app sent (a sign-in can contain a password)."""
    try:
        UNSEEN.mkdir(parents=True, exist_ok=True, mode=0o700)
        p = UNSEEN / f"{int(time.time() * 1000)}_{tag}.bin"
        p.write_bytes(body)
        os.chmod(p, 0o600)
        return str(p)
    except OSError:
        return "(could not save)"


# ---------- wire encoding ----------

def vint(n):
    n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(num, wt):
    return vint(num << 3 | wt)


def ld(num, payload):
    return tag(num, 2) + vint(len(payload)) + payload


class PassThrough(Exception):
    """This request has nothing private in it and no captured answer: let real Waze answer it (logged)."""


class Codec:
    """dict -> protobuf bytes, by field name (extensions included)."""

    FMT = {D.DOUBLE: "<d", D.FIXED64: "<Q", D.SFIXED64: "<q",
           D.FLOAT: "<f", D.FIXED32: "<I", D.SFIXED32: "<i"}

    def __init__(self, sc):
        self.sc, self._names = sc, {}

    def field(self, msg, name):
        idx = self._names.get(msg)
        if idx is None:
            m = self.sc.msgs.get(msg)
            idx = {f.name: f for f in (m.field if m else [])}
            for x in self.sc.exts.get(msg, {}).values():
                idx.setdefault(x.name, x)
            self._names[msg] = idx
        return idx.get(name)

    def enum_num(self, type_name, name):
        e = self.sc.enums.get(type_name)
        for v in (e.value if e else []):
            if v.name == name:
                return v.number
        raise KeyError(f"enum {type_name[1:]} has no value {name!r}")

    def encode(self, msg, obj):
        out = bytearray()
        for name, val in obj.items():
            f = self.field(msg, name)
            if f is None:
                raise KeyError(f"{msg[1:]} has no field {name!r}")
            for v in (val if isinstance(val, list) else [val]):
                out += self.encode_field(f, v)
        return bytes(out)

    def encode_field(self, f, v):
        t, n = f.type, f.number
        if t == D.MESSAGE:
            if isinstance(v, dict):
                if f.type_name not in self.sc.msgs:
                    raise ValueError(f"{f.name}: type {f.type_name} isn't in the schemas; give hex instead")
                return ld(n, self.encode(f.type_name, v))
            return ld(n, bytes.fromhex(v) if isinstance(v, str) else bytes(v))
        if t == D.STRING:
            return ld(n, str(v).encode())
        if t == D.BYTES:
            return ld(n, bytes.fromhex(v) if isinstance(v, str) else bytes(v))
        if t in D.VARINT:
            if t == D.ENUM and isinstance(v, str):
                v = self.enum_num(f.type_name, v)
            if t == D.BOOL:
                v = int(bool(v))
            if t in (D.SINT32, D.SINT64):
                v = (v << 1) ^ (v >> 63)
            return tag(n, 0) + vint(v)
        return tag(n, 1 if t in D.FIX64 else 5) + struct.pack(self.FMT[t], v)


def retime(sc, msg, buf, now, depth=0):
    """Move any timestamp-looking integer field (seconds or ms, within ~400 days of now) to now."""
    out = bytearray()
    for num, wt, v in D.parse_wire(buf):
        hit = sc.lookup(msg, num)
        f = hit[0] if hit else None
        if wt == 0:
            if f is not None and f.type in (D.INT32, D.INT64, D.UINT32, D.UINT64):
                if abs(v - now) < 400 * 86400:
                    v = int(now)
                elif abs(v - now * 1000) < 400 * 86400 * 1000:
                    v = int(now * 1000)
            out += tag(num, 0) + vint(v)
        elif wt == 2:
            if f is not None and f.type == D.MESSAGE and f.type_name in sc.msgs and depth < 8:
                try:
                    v = retime(sc, f.type_name, v, now, depth + 1)
                except ValueError:
                    pass
            out += ld(num, v)
        else:
            out += tag(num, wt) + v
    return bytes(out)


# ---------- request / batch helpers ----------

def unz(data):
    return gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data


def batch_elems(buf):
    return [v for n, w, v in D.parse_wire(buf) if n == 1001 and w == 2]


def cmd_of(elem):
    f = D.parse_wire(elem)
    return f[0][0] if f else 0


def make_batch(elems):
    return b"".join(ld(1001, e) for e in elems)


def parse_request(body):
    lines, protos = [], []
    if D.looks_like_lines(body) is None:          # raw protobuf Batch, not text lines
        try:
            elems = batch_elems(body)
        except ValueError:
            elems = []
        if elems:
            protos.append(body)
            for e in elems:
                f = D.parse_wire(e)
                if f and f[0][0] == 2001 and f[0][1] == 2:   # legacy text command inside the batch
                    lines += f[0][2].decode("utf-8", "replace").strip().splitlines()
            return lines, protos
    for ln in body.decode("utf-8", "replace").splitlines():
        if ln.startswith("ProtoBase64,"):
            try:
                protos.append(base64.b64decode(ln.split(",", 1)[1]))
            except Exception:
                pass
        elif ln.strip():
            lines.append(ln)
    return lines, protos


def signature(lines, protos):
    names = sorted({l.split(",", 1)[0] for l in lines})
    cmds = sorted({cmd_of(e) for p in protos for e in batch_elems(p)} - {2001})
    return "+".join(names) + " | " + ",".join(map(str, cmds))


def area_of(lines):
    """-> (lon0, lat0, lon1, lat1) or None, from MapDisplayed / Location lines."""
    for l in lines:
        if l.startswith("MapDisplayed,"):
            nums = [float(t) for t in l.split(",")[1:] if "." in t]
            xs, ys = nums[0::2], nums[1::2]
            if xs and ys:
                px = max((max(xs) - min(xs)) * 0.25, 0.01)
                py = max((max(ys) - min(ys)) * 0.25, 0.01)
                return min(xs) - px, min(ys) - py, max(xs) + px, max(ys) + py
    for l in lines:
        if l.startswith("Location,"):
            try:
                _, x, y = l.split(",")[:3]
                return float(x) - 0.05, float(y) - 0.05, float(x) + 0.05, float(y) + 0.05
            except ValueError:
                pass
    return None


def inside(pos, area):
    if area is None:
        return True
    x, y = pos["lon_times_1000000"] / 1e6, pos["lat_times_1000000"] / 1e6
    return area[0] <= x <= area[2] and area[1] <= y <= area[3]


# ---------- the server ----------

class Server:
    def __init__(self, cap=CAP, desc=DESC, world=WORLD):
        self.sc = D.Schema(descriptor_pb2.FileDescriptorSet.FromString(pathlib.Path(desc).read_bytes()))
        self.codec = Codec(self.sc)
        hit = self.sc.lookup(D.BATCH, 1001)
        if hit is None:
            sys.exit(f"{D.BATCH} field 1001 not in {desc}")
        self.elem_type = hit[0].type_name
        self.world_path = pathlib.Path(world)
        self.recs, self.login, self.cmd, self.last_area, self.geo = [], None, {}, None, None
        self._load(pathlib.Path(cap))

    def _load(self, cap):
        flows = cap / "flows.jsonl"
        if not flows.exists():
            sys.exit(f"{flows} not found; capture first")
        for line in flows.read_text().splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("ev") != "http" or r.get("status") != 200 or not r.get("req_body") or not r.get("res_body"):
                continue
            url = r["url"]
            kind = "login" if "rtserver/distrib/login" in url else \
                   "command" if "rtserver/distrib/command" in url else None
            if kind is None:
                continue
            req = unz((cap / r["req_body"]).read_bytes())
            res = unz((cap / r["res_body"]).read_bytes())
            if kind == "login" and b"GetGeoServerConfig" in req:      # server-discovery, not a login: keep its answer
                self.geo = dict(res=res, headers=r.get("res_headers", {}), t=r["t"])
                continue
            if D.looks_like_lines(res):
                continue
            try:
                elems = batch_elems(res)
            except ValueError:
                continue
            sig = signature(*parse_request(req)) if kind == "command" else None
            rec = dict(kind=kind, sig=sig, req=req, res=res, elems=elems,
                       headers=r.get("res_headers", {}), t=r["t"])
            self.recs.append(rec)
            if kind == "login":
                self.login = rec
            else:
                self.cmd[sig] = rec
        log(f"templates: login={'yes' if self.login else 'NO'}, command signatures={len(self.cmd)}, "
            f"geo-server answer={'yes' if self.geo else 'NO'}")

    # ----- replies for requests with no captured template -----

    def _ext_name(self, num):
        hit = self.sc.lookup(self.elem_type, num)          # regular fields AND extensions
        return hit[0].name if hit else None

    def _captured(self, num):
        """First element with this command number in any captured reply (or None)."""
        for r in self.recs:
            for e in r["elems"]:
                if cmd_of(e) == num:
                    return e
        return None

    def _enc(self, name, obj):
        f = self.codec.field(self.elem_type, name)
        if f is None:
            return None
        try:
            return self.codec.encode(self.elem_type, {name: obj})
        except (KeyError, ValueError):
            return ld(f.number, b"")

    def _stamp(self, now):
        try:
            return self._enc("response_timestamp", {"now_ms": int(now * 1000)}) if \
                self.codec.field(self.elem_type, "response_timestamp") else None
        except (KeyError, ValueError):
            return None

    def sync_default(self):
        """The real server answers a guest's sync_config_request with 4 default settings + last_synced (no echo of the
        request). Take the smallest real sync_config_response (2168): from the loaded capture, else ~/waze_capture_guest."""
        if getattr(self, "_sd", 0) == 0:
            cands = [e for r in self.recs for e in r["elems"] if cmd_of(e) == 2168]
            gdir = HOME / "waze_capture_guest"
            if gdir.exists() and gdir.resolve() != CAP.resolve() and (gdir / "flows.jsonl").exists():
                for line in (gdir / "flows.jsonl").read_text().splitlines():
                    try:
                        r = json.loads(line)
                        if r.get("ev") == "http" and "rtserver/distrib/command" in r["url"] and r.get("res_body") \
                                and r.get("status") == 200:
                            cands += [e for e in batch_elems(unz((gdir / r["res_body"]).read_bytes())) if cmd_of(e) == 2168]
                    except (ValueError, OSError, KeyError):
                        pass
            self._sd = min(cands, key=len) if cands else None
            log(f"sync_config default reply: {'real one copied (%d bytes)' % len(self._sd) if self._sd else 'NOT FOUND (ack only)'}")
        return self._sd

    @staticmethod
    def new_token():
        """The real server's auth tokens are 133 characters (register_successful.token == client_auth_token.token shape)."""
        return secrets.token_urlsafe(100)[:133]

    def answer_for(self, num, now):
        """-> (element bytes or None, note). X_request is answered with an empty X_response (or X_successful)."""
        name = self._ext_name(num) or f"?{num}"
        if name == "generate_token":                       # best guess: a ClientAuthToken
            e = self._enc("client_auth_token", {"token": self.new_token()})
            return e, f"{name}->client_auth_token (133-char token)" if e else f"{name}: no known reply"
        if name == "sync_config_request":                  # a preference push/poll: the 4 real defaults, not the captured account's items
            d = self.sync_default()
            if d is not None:
                try:
                    d = retime(self.sc, self.elem_type, d, now)
                except ValueError:
                    pass
                return d, "sync_config_request->sync_config_response (real defaults, retimed)"
            e = self._enc("sync_config_response", {"last_synced": int(now * 1000)})
            if e is not None:
                return e, "sync_config_request->sync_config_response (ack only, last_synced=now)"
        base = name[:-8] if name.endswith("_request") else name
        # no obvious name: look through all Element fields for one that mentions the same topic and sounds like a reply
        skip = {"get", "set", "sync", "check", "request", "update", "create"}
        stem = next((t for t in base.split("_") if t and t not in skip), "")
        if stem:
            m = self.sc.msgs.get(self.elem_type)
            allnames = [f.name for f in (m.field if m else [])] + \
                       [x.name for x in self.sc.exts.get(self.elem_type, {}).values()]
            found = sorted((n for n in allnames if stem.rstrip("s") in n and
                            any(k in n for k in ("response", "reply", "result", "successful"))), key=len)
            if found:
                log(f"{name}: reply candidates by name search: {', '.join(found[:6])}")
        else:
            found = []
        for cand in (base + "_response", base + "_successful", base + "_reply", *found[:1]):
            e = self._enc(cand, {})
            if e is not None:
                if cand == "sync_config_response":      # the app waits on this one: reuse a real captured answer
                    cap = self._captured(self.codec.field(self.elem_type, cand).number)
                    if cap is not None:
                        try:
                            cap = retime(self.sc, self.elem_type, cap, now)
                        except ValueError:
                            pass
                        return cap, f"{name}->{cand} (captured, retimed)"
                return e, f"{name}->{cand} (empty)"
        return None, f"{name}: no known reply"

    def _envelope(self):
        """get_takeovers_response + old_command, copied from the smallest captured reply that is only those two (+ timestamp).
        The real server ends every reply with them; replies we make up must too."""
        if getattr(self, "_env", None) is None:
            best = None
            for r in self.recs:
                if r["kind"] != "command":
                    continue
                names = [self._ext_name(cmd_of(e)) for e in r["elems"]]
                if len(names) == 3 and set(names) == {"response_timestamp", "get_takeovers_response", "old_command"} \
                        and (best is None or len(r["res"]) < len(best["res"])):
                    best = r
            self._env = [e for e in best["elems"] if self._ext_name(cmd_of(e)) != "response_timestamp"] if best else []
            log(f"reply envelope (get_takeovers_response, old_command): {'copied from capture' if self._env else 'NOT FOUND in capture'}")
        return self._env

    def fallback(self, protos, now):
        elems, notes = [], []
        for p in protos:
            for el in batch_elems(p):
                c = cmd_of(el)
                if c in (2001, 2184):                      # legacy text lines / client_info need no answer
                    continue
                e, note = self.answer_for(c, now)
                notes.append(note)
                if e is not None:
                    elems.append(e)
        stamp = self._stamp(now)
        return ([stamp] if stamp is not None else []) + elems + self._envelope(), notes

    def _base_tpl(self):
        return next(iter(self.cmd.values()), self.login)

    def _installation_id(self, protos):
        for p in protos:
            for el in batch_elems(p):
                if cmd_of(el) == 2184:
                    for n, w, v in D.parse_wire(D.parse_wire(el)[0][2]):
                        if n == 17 and w == 2:
                            return v.decode("utf-8", "replace")
        return ""

    def register_guest(self, protos):
        """A fresh guest account in auth.py's store; the random password goes to the device, only its hash is kept."""
        name, pw = "w" + secrets.token_hex(7)[:13], secrets.token_urlsafe(6)      # 14 / 8 chars, like the real ones
        uid = auth.add_user(name, pw)
        token = self.new_token()
        e = self._enc("register_successful", {"username": name, "password": pw, "token": token, "user_id": uid})
        cat = self._enc("client_auth_token", {"token": token})       # the real reply sends this right after
        log(f"registered guest {name} uid={uid} installation={self._installation_id(protos)[:8]}...")
        return [x for x in (e, cat) if x is not None] or None

    def is_geo(self, body):
        """The app asks rt.waze.com which regional server to use (GetGeoServerConfig). No credentials in it."""
        try:
            return b"GetGeoServerConfig" in unz(body) and self.login_creds(body) is None
        except Exception:
            return False

    def login_creds(self, body):
        """(username, password) from the app's login_request (2744 > password_credential), else None."""
        try:
            _, protos = parse_request(unz(body))
            for p in protos:
                for el in batch_elems(p):
                    for n, w, v in D.parse_wire(el):
                        if n == 2744 and w == 2:
                            for n2, w2, v2 in D.parse_wire(v):
                                if n2 == 1 and w2 == 2:
                                    f = {a: b for a, _, b in D.parse_wire(v2)}
                                    return f[1].decode(), f[2].decode()
        except (ValueError, KeyError, UnicodeDecodeError):
            pass
        return None

    def _shape(self, buf, depth=0):
        """Structure of a protobuf message with every value masked: 1{1:s11,2:s24},3:5  (sN = string of N chars, bN = N bytes)."""
        try:
            fields = D.parse_wire(buf)
        except ValueError:
            return f"b{len(buf)}"
        out = []
        for n, w, v in fields[:12]:
            if w == 0:
                out.append(f"{n}:{v if v < 1000 else 'i%dd' % len(str(v))}")
            elif w == 2:
                if v and D.valid_text(v):
                    out.append(f"{n}:s{len(v)}")
                elif v and depth < 4 and self._shape(v, depth + 1)[0] != "b":
                    out.append(f"{n}{{{self._shape(v, depth + 1)}}}")
                else:
                    out.append(f"{n}:b{len(v)}")
            else:
                out.append(f"{n}:f")
        return ",".join(out) + ("..." if len(fields) > 12 else "")

    def _describe(self, raw):
        """What kind of body is this? Names and lengths only, never values."""
        if not raw:
            return "(empty body)"
        printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in raw) / len(raw)
        if printable > 0.9:
            out = []
            for ln in raw.decode("utf-8", "replace").splitlines()[:6]:
                if "," not in ln:
                    out.append(f"<line {len(ln)} chars, no comma>")
                    continue
                name, _, rest = ln.partition(",")
                name = name if re.fullmatch(r"[A-Za-z0-9_]{1,30}", name) else f"<{len(name)} chars>"
                if name == "ProtoBase64":
                    try:
                        out.append("ProtoBase64[" + self._shape(base64.b64decode(rest)) + "]")
                    except Exception:
                        out.append(f"ProtoBase64[not base64, {len(rest)} chars]")
                else:
                    out.append(f"{name},<{len(rest)} chars, {rest.count(',') + 1} fields>")
            return "text lines: " + " | ".join(out)
        return f"binary, first bytes {raw[:4].hex()}, {printable:.0%} printable"

    HOSTISH = re.compile(r"(https?://)?[a-z0-9-]+(\.[a-z0-9-]+)*\.(waze|google|googleapis|gstatic)\.com(:\d+)?(/[A-Za-z0-9_./-]{0,60})?", re.I)

    def describe_reply(self, raw):
        """Safe summary of a reply from real Waze: command names, counts, and waze/google host names. Never other values."""
        if not raw:
            return "(empty)"
        raw = unz(raw)
        try:
            if D.looks_like_lines(raw):
                out = []
                for ln in raw.decode("utf-8", "replace").splitlines()[:25]:
                    if "," not in ln:
                        out.append(f"<line {len(ln)} chars>")
                        continue
                    name, _, rest = ln.partition(",")
                    name = name if re.fullmatch(r"[A-Za-z0-9_]{1,40}", name) else f"<{len(name)}>"
                    flds = [f if self.HOSTISH.fullmatch(f) else f"<{len(f)}>" for f in rest.split(",")[:8]]
                    out.append(f"{name}[{','.join(flds)}]")
                return "text lines: " + " | ".join(out)
            c = collections.Counter(self._ext_name(cmd_of(e)) or str(cmd_of(e)) for e in batch_elems(raw))
            if c:
                return "batch: " + ",".join(f"{k}x{v}" if v > 1 else k for k, v in c.most_common(14))
        except ValueError:
            pass
        return self._describe(raw)

    def login_denied(self, cred, body=None):
        et = ".linqmap.proto.rt.LoginError.LoginErrorType"
        names = [v.name for v in self.sc.enums[et].value] if et in self.sc.enums else []
        pick = next((n for n in names if any(k in n for k in ("PASS", "CRED", "INVALID", "AUTH", "WRONG", "BAD"))),
                    names[0] if names else None)
        e = self._enc("login_response", {"login_error": {"error_type": pick} if pick else {}})
        log(f"LOGIN REFUSED for {repr(cred[0][:32]) if cred else '(unreadable request)'}; error_type={pick}")
        if cred is None and body is not None:        # values masked: only field numbers, lengths and small numbers
            try:
                raw = unz(body)
                log(f"LOGIN request shape (masked): {self._shape(raw)[:300] if raw and D.looks_like_lines(raw) is None else ''} "
                    f"| {self._describe(raw)[:400]} [{len(raw)} bytes]")
            except Exception as ex:
                log(f"LOGIN request shape unavailable: {type(ex).__name__}")
        return make_batch([e] if e else []), "login refused", self.login

    def handle_static(self, body, now=None):
        now = now or time.time()
        _, protos = parse_request(unz(body))
        elems, notes = [], []
        for p in protos:
            for el in batch_elems(p):
                c = cmd_of(el)
                if c in (2001, 2184):              # legacy text / client_info: nothing to answer
                    continue
                if c == 2219:                      # register: "Get started" -> guest account
                    es = self.register_guest(protos)
                    notes.append("register->guest account + client_auth_token" if es
                                 else "register: register_successful not in schemas")
                    elems += es or []
                    continue
                e, note = self.answer_for(c, now)
                notes.append(note)
                if e is not None:
                    elems.append(e)
        stamp = self._stamp(now)
        if stamp is not None and elems:
            elems.insert(0, stamp)
        return make_batch(elems), "static -> " + "; ".join(notes or ["nothing to answer"]), self._base_tpl()

    def world(self):
        """world.json, parsed once and re-read only when the file changes (it can be 20+ MB)."""
        try:
            mt = self.world_path.stat().st_mtime
            if getattr(self, "_w", None) and self._w[0] == mt:
                return self._w[1]
            data = json.loads(self.world_path.read_text())
            self._w = (mt, data)
            self._enc_cache = {}
            return data
        except (OSError, ValueError):
            return {"wazers": [], "alerts": []}

    MAX_WAZERS = int(os.environ.get("PSERVER_MAX_WAZERS", "300"))
    MAX_ALERTS = int(os.environ.get("PSERVER_MAX_ALERTS", "500"))

    def _overlay(self, area, now):
        """Wazers/alerts inside the map area, nearest the centre first, capped so a reply stays small and fast.
        A bad entry (unknown enum value, missing field) is skipped and logged once; it never fails the request."""
        w, out = self.world(), {2004: [], 2708: []}
        cx = (area[0] + area[2]) / 2 if area else 0
        cy = (area[1] + area[3]) / 2 if area else 0

        def near(items, posf, cap):
            c = []
            for i, it in enumerate(items):
                try:
                    p = posf(it)
                    if inside(p, area):
                        d = (p["lon_times_1000000"] / 1e6 - cx) ** 2 + (p["lat_times_1000000"] / 1e6 - cy) ** 2
                        c.append((d, i))
                except (KeyError, TypeError):
                    continue
            c.sort()
            return [items[i] for _, i in c[:cap]]

        cache = getattr(self, "_enc_cache", None)
        if cache is None:
            cache = self._enc_cache = {}
        bad = getattr(self, "_bad", set())
        self._bad = bad
        for z in near(w.get("wazers", []), lambda z: z["gps_sample"]["position"], self.MAX_WAZERS):
            key = ("z", id(z))
            if key not in cache:
                try:
                    zz = {k: v for k, v in z.items() if not k.startswith("_")}
                    cache[key] = self.codec.encode(self.elem_type, {"add_wazer": zz})
                except (KeyError, ValueError, TypeError) as ex:
                    cache[key] = None
                    if str(ex) not in bad:
                        bad.add(str(ex))
                        log(f"world: skipping a wazer ({ex})")
            if cache[key] is not None:
                out[2004].append(cache[key])
        for a in near(w.get("alerts", []), lambda a: a["realtime_alert"]["alert_info"]["position"], self.MAX_ALERTS):
            try:
                a = copy.deepcopy(a)
                age = a.pop("_age_sec", 300)
                a["realtime_alert"]["alert_reporting_info"]["report_time"] = int(now - age)
                out[2708].append(self.codec.encode(self.elem_type, {"add_alert_action": a}))
            except (KeyError, ValueError, TypeError) as ex:
                if str(ex) not in bad:
                    bad.add(str(ex))
                    log(f"world: skipping an alert ({ex})")
        return out

    # ----- accounts: who is asking, profile, signup -----

    @staticmethod
    def session_of(headers):
        """server_session_id from the `uid` request header (a base64 protobuf whose field 1 is the session id)."""
        try:
            u = headers.get("uid") if headers is not None else None
            if not u:
                return None
            raw = base64.urlsafe_b64decode(u + "=" * (-len(u) % 4))
            for n, w, v in D.parse_wire(raw):
                if n == 1 and w == 0:
                    return v
        except Exception:
            pass
        return None

    def user_of(self, headers):
        sid = self.session_of(headers)
        return auth.by_session(sid) if sid else None

    def login_reply_for(self, tpl_elem, user):
        """The captured login_response with session id / global_user_id swapped for this account's."""
        sess = auth.new_session(user)
        out = b""
        for n, w, v in D.parse_wire(tpl_elem):
            if n == 2745 and w == 2:
                inner = b""
                for n1, w1, v1 in D.parse_wire(v):
                    if n1 == 1 and w1 == 2:
                        ls = b""
                        for n2, w2, v2 in D.parse_wire(v1):
                            if n2 == 1:
                                ls += tag(1, 0) + vint(sess["session_id"])
                            elif n2 == 2:
                                ls += ld(2, auth.waze_user_id(user["uid"]).encode())
                            else:
                                ls += ld(n2, v2) if w2 == 2 else tag(n2, 0) + vint(v2)
                        v1 = ls
                    inner += ld(n1, v1)
                v = inner
            out += ld(n, v)
        return out

    def profile_elem(self, user):
        rec = auth.get_user(user["name"]) or {}
        return self._enc("my_profile", {
            "basic_info": {"email": rec.get("email", ""), "email_verified": bool(rec.get("email")),
                           "join_date_sec": int(rec.get("created", time.time())), "points": int(rec.get("points", 0)),
                           "last_login_sec": int(time.time()), "public_user_name": user["name"],
                           "anonymous": False, "is_registered": True, "is_aadc_restricted": False,
                           "is_u18_restricted": False, "addon": 0, "is_u16_restricted": False},
            "social_info": {"gender": "UNDEFINED"},
            "favorites_info": {"num_favorites": 0},
            "user_id": user["uid"], "completed_percent": 100,
            "picture_id": auth.waze_user_id(user["uid"]),
            "mood_id": int(rec.get("mood", 1)), "username": user["name"]})

    def update_fields(self, protos, user):
        """Signup / rename / password change (update_user_fields_request 2499) -> update_user_fields_response element."""
        fields = {}
        for p in protos:
            for el in batch_elems(p):
                if cmd_of(el) != 2499:
                    continue
                for n, w, v in D.parse_wire(el):
                    if n == 2499 and w == 2:
                        for n0, w0, v0 in D.parse_wire(v):
                            if n0 != 1 or w0 != 2:                        # UpdateUserFieldsRequest.request
                                continue
                            for n1, w1, v1 in D.parse_wire(v0):
                                if n1 == 2 and w1 == 2:                   # UpdateUserRequest.fields
                                    for n2, w2, v2 in D.parse_wire(v1):
                                        if w2 == 2:
                                            fields[n2] = v2.decode("utf-8", "replace")
        if user is None:
            return self._enc("update_user_fields_response", {"status": {"code": "ERROR"}}), "update fields: no session"
        try:
            auth.update_user(user["name"], new_name=fields.get(1), new_pw=fields.get(2), email=fields.get(3))
            log(f"account update for uid={user['uid']}: set {sorted(k for k in fields)}"
                f"{' (renamed to ' + fields[1] + ')' if 1 in fields else ''}")
            return self._enc("update_user_fields_response", {"status": {"code": "OK"}}), "update fields ok"
        except ValueError as ex:
            msg = str(ex)
            ft = "USER_NAME_ALREADY_EXISTS" if "taken" in msg else "INVALID_PASSWORD" if "password" in msg else "INVALID_USER_NAME"
            log(f"account update refused: {msg}")
            return self._enc("update_user_fields_response", {"status": {"code": "ERROR", "additional_info": msg}, "failure_type": ft}), "update fields refused"

    def handle(self, kind, body, now=None, headers=None):
        now = now or time.time()
        lines = []
        who, rq = "", ""
        user, login_user, upd = None, None, None
        if kind == "login" and self.is_geo(body):
            if self.geo is None:
                raise PassThrough
            return self.geo["res"], "geo-server discovery (captured answer)", {"headers": self.geo["headers"]}
        if kind == "login":
            cred = self.login_creds(body)
            user = auth.verify(*cred) if cred else None
            if user is None:                      # private login: only accounts in auth.py get in
                return self.login_denied(cred, body)
            who = f" as {user['name']}"
            login_user = user
            tpl = self.login
        else:
            lines, protos = parse_request(unz(body))
            user = self.user_of(headers)
            for l in lines:
                if l.startswith('SetMood,') and user:
                    try:
                        auth.set_field(user['name'], 'mood', int(l.split(',')[1]))
                    except (ValueError, IndexError):
                        pass
            sig = signature(lines, protos)
            rq = ",".join(self._ext_name(c) or str(c) for c in sorted(
                {cmd_of(e) for p in protos for e in batch_elems(p)} - {2001}))
            if any(cmd_of(e) == 2499 for p in protos for e in batch_elems(p)):
                ue, note = self.update_fields(protos, user)
                st = self._stamp(now)
                return make_batch(([st] if st else []) + ([ue] if ue else []) + self._envelope()), note, self._base_tpl()
            mp = self.marketplace(protos, now)
            if mp is not None:
                els, note = mp
                log(f"marketplace: {note}")
                return make_batch(els), f"command marketplace: {note}", self._base_tpl()
            tpl = self.cmd.get(sig)
            if tpl is None:
                fe, notes = self.fallback(protos, now)
                tpl = dict(self._base_tpl(), sig=sig, elems=fe)
                log(f"UNSEEN request shape {sig!r}; saved to {save_unseen('command', unz(body))}; "
                    f"replied: {'; '.join(notes) or 'empty batch'}")
        if tpl is None:
            raise RuntimeError(f"no captured {kind} template")
        has_loc = any(l.startswith(("MapDisplayed,", "Location,")) for l in lines)
        tpl_world = any(cmd_of(e) in WORLD_ELEMS for e in tpl["elems"])
        area = area_of(lines)
        if area is not None:
            self.last_area = area
        want_world = kind == "command" and (has_loc or tpl_world)
        ov = self._overlay(area or self.last_area, now) if want_world else {2004: [], 2708: []}
        elems, placed = [], set()
        for e in tpl["elems"]:
            c = cmd_of(e)
            if c in WORLD_ELEMS:
                if c not in placed:
                    elems += ov[c]
                    placed.add(c)
                continue
            if c == 2745 and login_user is not None:
                e = self.login_reply_for(e, login_user)
            if c == 2383 and user is not None:
                e = self.profile_elem(user) or e
            if c == 2168 and self.sync_default() is not None:
                e = self.sync_default()
            if c in TIME_ELEMS:
                try:
                    e = retime(self.sc, self.elem_type, e, now)
                except ValueError:
                    pass
            elems.append(e)
        for c in WORLD_ELEMS:
            if c not in placed:
                elems += ov[c]
        rp = collections.Counter(self._ext_name(cmd_of(e)) or str(cmd_of(e)) for e in elems)
        rp = ",".join(f"{k}x{v}" if v > 1 else k for k, v in rp.most_common(6))
        info = f"{kind}{who} sig={tpl['sig']!r} req=[{rq}] reply=[{rp}] -> {len(elems)} elements, {len(ov[2004])} wazers, {len(ov[2708])} alerts"
        return make_batch(elems), info, tpl

    # ----- marketplace: custom cars -----

    MP = PRIV / "marketplace.json"
    FILES = PRIV / "files"

    def mp_config(self):
        try:
            c = json.loads(self.MP.read_text())
            return c if c.get("cars") or c.get("include_real", True) else None
        except (OSError, ValueError):
            return None

    def _base_car(self):
        """A real CarAsset (raw bytes) from a captured get_copilot_assets_response (2718)."""
        for r in self.recs:
            for e in r["elems"]:
                if cmd_of(e) != 2718:
                    continue
                for n, w, v in D.parse_wire(D.parse_wire(e)[0][2]):
                    if n == 1 and w == 2:
                        for n2, w2, v2 in D.parse_wire(v):
                            if n2 == 4 and w2 == 2:
                                return v2
        return None

    @staticmethod
    def _preview_url(p):
        return p if "://" in p else "https://cres.waze.com/private/" + urllib.parse.quote(os.path.basename(p))

    def _clone_car(self, base, car):
        """The real car with our id / name / preview image swapped in (3D model download and textures unchanged)."""
        out = b""
        for n, w, v in D.parse_wire(base):
            if n == 1 and w == 0:
                v = int(car["id"])
                out += tag(1, 0) + vint(v)
            elif n == 2 and w == 2:
                out += ld(2, str(car["name"]).encode())
            elif n == 5 and w == 2 and car.get("preview"):
                out += ld(5, ld(1, self._preview_url(car["preview"]).encode()))
            elif w == 0:
                out += tag(n, 0) + vint(v)
            elif w == 2:
                out += ld(n, v)
            else:
                out += tag(n, w) + v
        return out

    def custom_assets(self, protos, now):
        """get_copilot_assets_request (2717) that names a custom mood or car -> one asset per requested item:
        ours for custom ids/names, the captured real one otherwise. None if nothing asked for is custom.
        marketplace.json: {"moods":[{"id":9100,"name":"MOOD_X","preview":"x.png","zip":"x.zip"}], "cars":[...]}"""
        try:
            cfg = json.loads(self.MP.read_text())
        except (OSError, ValueError):
            return None
        moods, cars = cfg.get("moods", []), cfg.get("cars", [])
        infos = []
        for p in protos:
            for e in batch_elems(p):
                if cmd_of(e) == 2717:
                    for n, w, v in D.parse_wire(D.parse_wire(e)[0][2]):
                        if n == 1 and w == 2:
                            d = {}
                            for n2, w2, v2 in D.parse_wire(v):
                                d[n2] = v2.decode("utf-8", "replace") if w2 == 2 else v2
                            infos.append(d)
        if not infos:
            return None
        real = [v for r in self.recs for e in r["elems"] if cmd_of(e) == 2718
                for n, w, v in D.parse_wire(D.parse_wire(e)[0][2]) if n == 1 and w == 2]
        base, out, hit = self._base_car(), [], False
        for d in infos:
            m = next((m for m in moods if d.get(2) == m["name"] or (d.get(1) is not None and d[1] == int(m["id"]))), None)
            c = next((c for c in cars if d.get(4) == c["name"] or (d.get(3) is not None and d[3] == int(c["id"]))), None)
            if m:
                hit = True
                dl = tag(1, 0) + vint(int(now)) + (ld(2, self._preview_url(m["zip"]).encode()) if m.get("zip") else b"")
                mood = tag(1, 0) + vint(int(m["id"])) + ld(2, m["name"].encode()) + ld(3, dl) + \
                    ld(4, ld(1, self._preview_url(m["preview"]).encode()) if m.get("preview") else b"")
                out.append(tag(1, 0) + vint(1) + ld(2, mood))
            elif c and base is not None:
                hit = True
                out.append(tag(1, 0) + vint(1) + ld(4, self._clone_car(base, c)))
            else:
                for r in real:                              # the captured answer for a real car / voice / mood
                    f = {n: v for n, w, v in D.parse_wire(r) if w == 2}
                    names = set()
                    for k in (2, 3, 4):
                        if k in f:
                            for n3, w3, v3 in D.parse_wire(f[k]):
                                if w3 == 2 and n3 in (1, 2) and D.valid_text(v3):
                                    names.add(v3.decode())
                    if (d.get(4) and d[4] in names) or (d.get(5) and d[5] in names) or (d.get(2) and d[2] in names):
                        out.append(r)
                        break
        if not hit:
            return None
        stamp = self._stamp(now)
        return ([stamp] if stamp else []) + [ld(2718, b"".join(ld(1, a) for a in out))] + self._envelope(), \
            f"custom assets: {len(out)} item(s)"

    def marketplace(self, protos, now):
        ca = self.custom_assets(protos, now)
        if ca is not None:
            return ca
        """Answer the car picker (2748) and a request for one of our custom cars (2717); None = not ours."""
        cfg = self.mp_config()
        base = self._base_car() if cfg else None
        if not cfg or base is None:
            return None
        cmds = {cmd_of(e) for p in protos for e in batch_elems(p)} - {2001, 2184}
        customs = cfg.get("cars", [])
        stamp = self._stamp(now)
        head = [stamp] if stamp is not None else []
        if cmds == {2748}:
            cars = ([base] if cfg.get("include_real", True) else []) + [self._clone_car(base, c) for c in customs]
            el = ld(2749, b"".join(ld(1, c) for c in cars))
            return head + [el] + self._envelope(), f"car picker: {len(cars)} cars ({len(customs)} custom)"
        if cmds == {2717}:
            asked_name, asked_id = None, None
            for p in protos:
                for e in batch_elems(p):
                    if cmd_of(e) == 2717:
                        for n, w, v in D.parse_wire(D.parse_wire(e)[0][2]):
                            if n == 1 and w == 2:
                                for n2, w2, v2 in D.parse_wire(v):
                                    if n2 == 4 and w2 == 2:
                                        asked_name = v2.decode("utf-8", "replace")
                                    if n2 == 3 and w2 == 0:
                                        asked_id = v2
            hit = next((c for c in customs if (asked_name and c["name"] == asked_name) or
                        (asked_id is not None and int(c["id"]) == asked_id)), None)
            if hit is None:
                return None                                  # a real car: the captured answer already covers it
            tpl = next((e for r in self.recs for e in r["elems"] if cmd_of(e) == 2718), None)
            if tpl is None:
                return None
            clone, out = self._clone_car(base, hit), b""
            for n, w, v in D.parse_wire(D.parse_wire(tpl)[0][2]):
                if n == 1 and w == 2 and any(n2 == 4 for n2, _, _ in D.parse_wire(v)):
                    v = b"".join(ld(n2, clone) if n2 == 4 else (tag(n2, 0) + vint(v2) if w2 == 0 else ld(n2, v2))
                                 for n2, w2, v2 in D.parse_wire(v))
                out += ld(n, v) if w == 2 else tag(n, w) + (vint(v) if w == 0 else v)
            return head + [ld(2718, out)] + self._envelope(), f"copilot assets: custom car {hit['name']!r}"
        return None

    def resp_headers(self, tpl):
        h = {k: v for k, v in tpl["headers"].items() if k.lower() not in DROP_HEADERS}
        gz = tpl["headers"].get("content-encoding", tpl["headers"].get("Content-Encoding", "")) == "gzip"
        return h, gz


# ---------- marketplace gallery injection (the "pick a sidekick" web page) ----------

def inject_custom_gallery(raw):
    """Add one custom card to the real gallery JSON. None = left alone (not JSON, or no categories)."""
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    cats = data.get("categories")
    if not isinstance(cats, list):
        return None
    custom_card = {
        "themeCard": {
            "campaignId": "custom-1",
            "title": "My Custom Sidekick",
            "imageUrl": "https://cres.waze.com/private/red.png",
        }
    }
    cats.insert(0, {"title": "Custom", "cards": [custom_card]})
    data["categories"] = cats
    return json.dumps(data).encode()


def custom_theme_campaign(campaign_id):
    """Fabricated 'theme-campaign' detail reply for one of our custom gallery cards, or None (not ours).
    The character/voice/car/mood ids here are REAL ones captured from SpongeBob (8791): this only tests
    whether our own detail page loads and applies correctly, reusing assets already known to work."""
    if campaign_id != "custom-1":
        return None
    return {
        "campaign": {
            "id": "custom-1",
            "name": "My Custom Sidekick",
            "title": "My Custom Sidekick",
            "subtitle": "A custom drive buddy.",
            "description": "A custom sidekick bundle, for testing a private marketplace server.",
            "mainImageUrl": "https://cres.waze.com/private/red.png",
            "characters": [{
                "characterId": "custom-char-1",
                "characterName": "Custom",
                "iconUrl": "https://cres.waze.com/private/red.png",
                "voices": [{
                    "voiceId": "16455",
                    "title": "SpongeBob SquarePants",
                    "iconUrl": "https://dexter.waze.com/8/6455/Voice/x3.png",
                    "sampleAssetUrl": "https://dexter.waze.com/8/6455/Voice/voices/StartDrive/1.mp3",
                    "locale": "en",
                }],
                "cars": [{
                    "carId": "16454",
                    "carName": "Patty Blaster",
                    "title": "Patty Blaster",
                    "iconUrl": "https://dexter.waze.com/3/6454/$car.carId/2D/x3.png",
                }],
                "moods": [{
                    "moodId": "16453",
                    "moodName": "MOOD_SPONGEBOB_EN_BRAVE",
                    "title": "Brave",
                    "iconUrl": "https://dexter.waze.com/4/6453/$mood.mood_id/x3_ui.png",
                }],
            }],
            "shareTitle": "My Custom Sidekick",
            "shareBody": "A custom sidekick bundle, for testing a private marketplace server.",
        },
        "status": "SUCCESS",
    }


# ---------- mitmproxy hooks ----------

_SRV = None


def request(flow):
    global _SRV
    if http is None or "waze" not in flow.request.pretty_host:
        return
    url = flow.request.pretty_url
    if flow.request.path.startswith("/webviews/copilot-marketplace/api/theme-campaign/"):
        cid = flow.request.path.rstrip("/").rsplit("/", 1)[-1]
        custom = custom_theme_campaign(cid)
        if custom is not None:
            body = json.dumps(custom).encode()
            flow.response = http.Response.make(200, body, {"Content-Type": "application/json"})
            log(f"theme-campaign: answered {cid!r} with custom bundle (real Waze never asked)")
            return
    if flow.request.pretty_host == "www.waze.com" and (flow.request.path.startswith("/webviews/copilot-marketplace/api/")
                                                       or flow.request.path.startswith("/api/config/CopilotWeb")):
        for h in ("If-None-Match", "If-Modified-Since"):      # ask for a full copy, not a 304, so the body can be saved
            flow.request.headers.pop(h, None)
        flow.metadata["pserver_web"] = True
    if flow.request.path.startswith("/private/"):          # our own images for custom cars/moods
        name = urllib.parse.unquote(os.path.basename(flow.request.path.split("?")[0]))
        f = Server.FILES / name
        if name and f.is_file():
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
            flow.response = http.Response.make(200, f.read_bytes(), {"Content-Type": ctype, "Cache-Control": "no-cache"})
            log(f"served private file {name}")
        else:
            flow.response = http.Response.make(404, b"", {})
            log(f"private file not found: {name} (put it in {Server.FILES})")
        return
    kind = "login" if "rtserver/distrib/login" in url else \
           "command" if "rtserver/distrib/command" in url else \
           "static" if "rtserver/distrib/static" in url else None
    if kind is None:
        host = flow.request.pretty_host
        if "rtserver" not in url and not host.startswith(("cres", "ctiles", "tts-assets", "adsassets")) \
                and not url.split("?")[0].lower().endswith((".png", ".jpg", ".webp", ".zip", ".json")):
            # everything the server does not answer goes to real Waze; make that visible (no query strings)
            log(f"PASS {flow.request.method} {host}{flow.request.path.split('?')[0]}")
        if "rtserver" in url:
            where = save_unseen(url.rstrip("/").rsplit("/", 1)[-1], flow.request.content or b"")
            if os.environ.get("PSERVER_STRICT"):
                flow.response = http.Response.make(404, b"", {})
                log(f"blocked {url} (body saved to {where})")
            else:
                log(f"PASSING THROUGH to real Waze: {url} (body saved to {where})")
        return
    try:
        _SRV = _SRV or Server()
        body = flow.request.content or b""
        data, info, tpl = _SRV.handle_static(body) if kind == "static" else _SRV.handle(kind, body, headers=flow.request.headers)
        hdr, gz = _SRV.resp_headers(tpl)
        r = http.Response.make(200, data, hdr)
        if gz:
            r.encode("gzip")
        flow.response = r
        log(info)
    except PassThrough:
        flow.metadata["pserver_geo"] = True        # so response() below can describe what real Waze answers
        if os.environ.get("PSERVER_STRICT"):
            flow.response = http.Response.make(404, b"", {})
            log(f"blocked geo-server discovery on {flow.request.pretty_host} (strict mode; no captured answer)")
        else:
            log(f"PASSING geo-server discovery on {flow.request.pretty_host} to real Waze "
                f"(no credentials in it, no captured answer)")
    except Exception as ex:  # fail closed: never leak to the real server because of a bug
        log(f"ERROR {type(ex).__name__}: {ex}")
        # a 500 leaves the app stuck on "loading map"; answer with a valid empty batch (timestamp + envelope) instead
        try:
            now = time.time()
            st = _SRV._stamp(now)
            data = make_batch(([st] if st else []) + _SRV._envelope())
            hdr, gz = _SRV.resp_headers(_SRV._base_tpl())
            r = http.Response.make(200, data, hdr)
            if gz:
                r.encode("gzip")
            flow.response = r
        except Exception:
            flow.response = http.Response.make(500, b"private server error", {})


def response(flow):
    """Describe (and keep) what real Waze answered to the one request we let through."""
    if http is not None and flow.metadata.get("pserver_web") and flow.response is not None and flow.response.status_code == 200:
        path = flow.request.path.split("?")[0]
        seg = path.rstrip("/").rsplit("/", 1)[-1] or "root"
        raw = flow.response.content or b""
        if path.endswith("/webviews/copilot-marketplace/api/gallery"):
            patched = inject_custom_gallery(raw)
            if patched is not None:
                flow.response.content = patched          # mitmproxy re-encodes/re-lengths to match headers
                raw = patched
                log("gallery: injected custom card")
            else:
                log("gallery: could not parse reply, left unmodified")
        where = save_unseen("web_" + re.sub(r"[^A-Za-z0-9_-]", "", seg)[:30], raw) if raw else "(empty)"
        log(f"saved web reply {path} ({len(raw)} bytes) to {where}")
        return
    if http is None or not flow.metadata.get("pserver_geo") or flow.response is None or _SRV is None:
        return
    raw = flow.response.content or b""
    where = save_unseen("geo_reply", raw) if raw else "(nothing to save)"
    log(f"geo-server reply from real Waze: HTTP {flow.response.status_code}, {len(raw)} bytes, "
        f"{_SRV.describe_reply(raw)[:700]}; saved to {where}")


# ---------- CLI ----------

def init_world(lon, lat):
    pos = lambda dx, dy: {"lon_times_1000000": int((lon + dx) * 1e6), "lat_times_1000000": int((lat + dy) * 1e6)}
    wazers = [{
        "mode": "DELETE_IF_NOT_UPDATE", "id": {"session_id": 900000 + i},
        "gps_sample": {"position": pos(dx, dy), "azymuth": az, "speed_millis_per_second": 0},
        "mood": 1, "addon": "NONE", "rank": 0, "points": 100 * i,
        "join_date_sec": 1700000000, "capabilities": 7, "can_ping": False, "can_private_message": False,
    } for i, (dx, dy, az) in enumerate([(0.004, 0.002, 90), (-0.006, 0.001, 180), (0.002, -0.005, 270)], 1)]
    alerts = [{
        "_age_sec": 600 * i,
        "realtime_alert": {
            "id": 990000 + i,
            "alert_info": {
                "type": "HAZARD", "sub_type": "HAZARD_ON_ROAD_POT_HOLE", "position": pos(dx, dy),
                "segment_direction_id": {"from_node": 176677667, "to_node": 163356063},
                "seg_direction": "FORWARDS", "azymuth": 90, "on_route": False, "priority": 1000,
                "alert_details": {"hazard_on_road": {"type": "HAZARD_POTHOLE"}},
            },
            "alert_reporting_info": {
                "primary_alert_id": -1, "kind": "PRIMARY", "report_time": 0,
                "reporter_username": f"TestWazer{i}", "current_user_is_reporter": False,
                "report_image_id": "",
                "alert_address": {"location_near_by_report": "", "street": "Test St", "city": "Testville"},
                "thumbs_up_count": i, "current_user_thumbed_up": False, "seconds_to_report": -1,
                "beepInfo": {}, "chatInfo": {"private": False},
            },
            "alert_uuid": f"00000000-0000-4000-8000-00000000000{i}",
        },
    } for i, (dx, dy) in enumerate([(0.003, 0.004), (-0.004, -0.003)], 1)]
    WORLD.parent.mkdir(parents=True, exist_ok=True)
    WORLD.write_text(json.dumps({"wazers": wazers, "alerts": alerts}, indent=2))
    print(f"wrote {WORLD}: {len(wazers)} wazers, {len(alerts)} alerts around {lon},{lat}")


def _png(rgb, size=128):
    row = b"\x00" + bytes(rgb) * size
    raw = zlib.compress(row * size)
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)) \
        + chunk(b"IDAT", raw) + chunk(b"IEND", b"")


def init_marketplace():
    Server.FILES.mkdir(parents=True, exist_ok=True)
    (Server.FILES / "red.png").write_bytes(_png((220, 40, 40)))
    (Server.FILES / "blue.png").write_bytes(_png((40, 90, 220)))
    if Server.MP.exists():
        return print(f"{Server.MP} already exists; left alone (sample images written to {Server.FILES})")
    Server.MP.write_text(json.dumps({
        "include_real": True,
        "cars": [{"id": 9001, "name": "Red Square", "preview": "red.png"},
                 {"id": 9002, "name": "Blue Square", "preview": "blue.png"}],
    }, indent=2))
    print(f"wrote {Server.MP} and two sample images in {Server.FILES}")
    print("preview: a file name in that folder (served by the proxy) or a full https URL. id: any unused number.")


def add_mood(name, rgb=(150, 60, 220), mood_id=None):
    """Register a custom mood: writes a preview image and adds it to marketplace.json (moods list)."""
    Server.FILES.mkdir(parents=True, exist_ok=True)
    try:
        cfg = json.loads(Server.MP.read_text())
    except (OSError, ValueError):
        cfg = {"include_real": True, "cars": []}
    moods = cfg.setdefault("moods", [])
    if any(m["name"] == name for m in moods):
        return print(f"mood {name} already exists")
    mid = mood_id or max([m["id"] for m in moods] + [9099]) + 1
    img = f"{name}.png"
    (Server.FILES / img).write_bytes(_png(rgb))
    moods.append({"id": mid, "name": name, "preview": img})
    Server.MP.write_text(json.dumps(cfg, indent=2))
    print(f"added mood {name} id={mid}, preview {Server.FILES / img}")


def selftest(srv):
    bad = 0
    for r in srv.recs:
        out, info, _ = srv.handle(r["kind"], r["req"], now=r["t"])
        names = lambda es: collections.Counter(cmd_of(e) for e in es)
        got, want = names(batch_elems(out)), names(r["elems"])
        diff = {k: (want[k], got[k]) for k in set(got) | set(want) if got[k] != want[k]}
        out_lines = []
        ok, unexp = D.decode_msg(srv.sc, D.BATCH, out, 0, out_lines)
        status = "same shape" if not diff else f"differs (cmd: captured,ours) {diff}"
        if unexp:
            bad += 1
        print(f"{r['kind']:8s} {status}; re-decode explained={ok} unexplained={unexp}")
    print("OK" if not bad else f"{bad} reply(ies) did not re-decode cleanly")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--init-world", nargs=2, type=float, metavar=("LON", "LAT"))
    ap.add_argument("--signatures", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--add-mood", metavar="NAME", help="register a custom mood (id auto-assigned, solid-colour preview)")
    ap.add_argument("--init-marketplace", action="store_true", help="write a sample custom-cars config and images")
    a = ap.parse_args()
    if a.add_mood:
        return add_mood(a.add_mood)
    if a.init_marketplace:
        return init_marketplace()
    if a.init_world:
        return init_world(*a.init_world)
    if a.signatures or a.selftest:
        srv = Server()
        if a.signatures:
            for s, r in srv.cmd.items():
                print(f"{len(r['elems']):5d} elements  {s}")
        if a.selftest:
            selftest(srv)
        return
    print(__doc__)


if __name__ == "__main__":
    main()
