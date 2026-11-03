#!/usr/bin/env python3
"""Decode captured Waze realtime bodies using the schemas pulled from the app.

    python3 decode.py --flow rtserver/distrib/login --side res --summary
    python3 decode.py --flow rtserver/distrib/command --index 2 --side res --summary
    python3 decode.py --flow rtserver/distrib/command --index 2 --side res --max-lines 200
    python3 decode.py --hex ca3e06caac01020801
    python3 decode.py --file body.bin --root linqmap.proto.rt.Batch

Every rtserver body is a `linqmap.proto.rt.Batch` (repeated Element at field
1001; each Element carries one command, identified by a field number in the
2000s). That is the default root; use --auto to search all message types.

This reads the raw schema definitions directly (no protobuf descriptor pool),
so a schema file that depends on something the app doesn't embed can't stop
anything from loading: a type that isn't available just shows its contents as
?N fields.
"""
import argparse
import base64
import collections
import gzip
import json
import pathlib
import struct
import sys

from google.protobuf import descriptor_pb2

HOME = pathlib.Path.home()
CAP = HOME / "waze_capture"
BATCH = ".linqmap.proto.rt.Batch"
(DOUBLE, FLOAT, INT64, UINT64, INT32, FIXED64, FIXED32, BOOL, STRING, GROUP, MESSAGE, BYTES,
 UINT32, ENUM, SFIXED32, SFIXED64, SINT32, SINT64) = range(1, 19)
VARINT = {INT32, INT64, UINT32, UINT64, BOOL, ENUM, SINT32, SINT64}
FIX64 = {DOUBLE, FIXED64, SFIXED64}
FIX32 = {FLOAT, FIXED32, SFIXED32}
REPEATED = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED


# ---------- raw wire format ----------

def rv(buf, i):
    shift = val = 0
    while True:
        if i >= len(buf) or shift > 63:
            raise ValueError("bad varint")
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def parse_wire(buf):
    i, out = 0, []
    while i < len(buf):
        tag, i = rv(buf, i)
        num, wt = tag >> 3, tag & 7
        if num == 0:
            raise ValueError("field 0")
        if wt == 0:
            v, i = rv(buf, i)
        elif wt in (1, 5):
            n = 8 if wt == 1 else 4
            v = buf[i:i + n]
            if len(v) < n:
                raise ValueError("short fixed")
            i += n
        elif wt == 2:
            ln, i = rv(buf, i)
            if i + ln > len(buf):
                raise ValueError("short bytes")
            v = buf[i:i + ln]
            i += ln
        else:
            raise ValueError(f"wire type {wt}")
        out.append((num, wt, v))
    return out


def valid_text(v):
    try:
        t = v.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(c.isprintable() or c in "\r\n\t" for c in t)


# ---------- schema index (raw FileDescriptorProtos, no pool) ----------

class Schema:
    def __init__(self, fds):
        self.msgs = {}      # ".pkg.Msg" -> DescriptorProto
        self.enums = {}     # ".pkg.Enum" -> EnumDescriptorProto
        self.exts = collections.defaultdict(dict)   # extendee -> {number: FieldDescriptorProto}
        self._byfield = {}
        for f in fds.file:
            self._walk("." + f.package if f.package else "", f.message_type, f.enum_type)
            for x in f.extension:
                self.exts[x.extendee][x.number] = x

    def _walk(self, prefix, msgs, enums):
        for e in enums:
            self.enums[f"{prefix}.{e.name}"] = e
        for m in msgs:
            full = f"{prefix}.{m.name}"
            self.msgs[full] = m
            for x in m.extension:
                self.exts[x.extendee][x.number] = x
            self._walk(full, m.nested_type, m.enum_type)

    def lookup(self, msg, num):
        """-> (FieldDescriptorProto, is_extension) or None."""
        if msg is None:
            return None
        d = self._byfield.get(msg)
        if d is None:
            m = self.msgs.get(msg)
            d = self._byfield[msg] = {f.number: f for f in m.field} if m else {}
        f = d.get(num)
        if f is not None:
            return f, False
        x = self.exts.get(msg, {}).get(num)
        return (x, True) if x is not None else None

    def enum_name(self, type_name, value):
        e = self.enums.get(type_name)
        if e is not None:
            for v in e.value:
                if v.number == value:
                    return v.name
        return None


def want_wt(t):
    return 0 if t in VARINT else 1 if t in FIX64 else 5 if t in FIX32 else 2


def wt_ok(f, wt, v=None):
    if f.type == GROUP:
        return False
    if wt == want_wt(f.type):
        if v is not None and wt == 2:
            if f.type == STRING:
                return valid_text(v)
            if f.type == MESSAGE:
                try:
                    parse_wire(v)
                except ValueError:
                    return False
        return True
    return wt == 2 and f.label == REPEATED and f.type in (VARINT | FIX64 | FIX32)


def scalar(sc, f, v):
    t = f.type
    if t in (INT32, INT64):
        return str(v - (1 << 64) if v >= 1 << 63 else v)
    if t in (UINT32, UINT64):
        return str(v)
    if t == BOOL:
        return "true" if v else "false"
    if t == ENUM:
        sv = v - (1 << 64) if v >= 1 << 63 else v
        return sc.enum_name(f.type_name, sv) or str(sv)
    if t in (SINT32, SINT64):
        return str((v >> 1) ^ -(v & 1))
    fmt = {DOUBLE: "<d", FIXED64: "<Q", SFIXED64: "<q", FLOAT: "<f", FIXED32: "<I", SFIXED32: "<i"}.get(t)
    if fmt:
        return str(struct.unpack(fmt, v)[0])
    if t == STRING:
        s = v.decode("utf-8", "replace")
        return repr(s if len(s) <= 300 else s[:300] + f"...(+{len(s) - 300} chars)")
    return v[:32].hex() + ("..." if len(v) > 32 else "")


def packed(sc, f, v):
    vals, i = [], 0
    if f.type in VARINT:
        while i < len(v):
            x, i = rv(v, i)
            vals.append(scalar(sc, f, x))
    else:
        n = 8 if f.type in FIX64 else 4
        for j in range(0, len(v) - n + 1, n):
            vals.append(scalar(sc, f, v[j:j + n]))
    return "[" + ", ".join(vals) + "]"


def guess(v, wt, depth):
    if wt == 0:
        return str(v)
    if wt in (1, 5):
        return v.hex()
    if v and valid_text(v):
        t = v.decode("utf-8")
        return repr(t if len(t) <= 300 else t[:300] + f"...(+{len(t) - 300} chars)")
    if depth < 6:
        try:
            fields = parse_wire(v)
            if fields:
                return fields
        except ValueError:
            pass
    return "hex:" + v[:32].hex() + ("..." if len(v) > 32 else "")


def generic(fields, lvl, out, depth):
    ind = "  " * lvl
    for num, wt, v in fields:
        g = guess(v, wt, depth)
        if isinstance(g, list):
            out.append(f"{ind}?{num} {{")
            generic(g, lvl + 1, out, depth + 1)
            out.append(f"{ind}}}")
        else:
            out.append(f"{ind}?{num}: {g}")


def decode_msg(sc, msg, buf, lvl, out, depth=0):
    """Print `buf` as message type `msg` (full name or None); return (explained, unexplained)."""
    ind = "  " * lvl
    try:
        fields = parse_wire(buf)
    except ValueError:
        out.append(f"{ind}<malformed: {buf[:24].hex()}>")
        return 0, 1
    ok = bad = 0
    for num, wt, v in fields:
        hit = sc.lookup(msg, num)
        if hit is None or not wt_ok(hit[0], wt, v):
            bad += 1
            g = guess(v, wt, depth)
            if isinstance(g, list):
                out.append(f"{ind}?{num} {{")
                generic(g, lvl + 1, out, depth + 1)
                out.append(f"{ind}}}")
            else:
                out.append(f"{ind}?{num}: {g}")
            continue
        f, is_ext = hit
        ok += 1
        label = ("(ext) " if is_ext else "") + f.name
        if f.type == MESSAGE and wt == 2:
            out.append(f"{ind}{label} [{num}] {{")
            if f.type_name in sc.msgs:
                a, b = decode_msg(sc, f.type_name, v, lvl + 1, out, depth + 1)
                ok += a
                bad += b
            else:  # type isn't embedded in the app: show contents raw
                generic(parse_wire(v), lvl + 1, out, depth + 1)
            out.append(f"{ind}}}")
        elif wt == 2 and f.type in (VARINT | FIX64 | FIX32):
            out.append(f"{ind}{label} [{num}]: {packed(sc, f, v)}")
        else:
            out.append(f"{ind}{label} [{num}]: {scalar(sc, f, v)}")
    return ok, bad


def find_roots(sc, buf, topn=5):
    try:
        top = parse_wire(buf)
    except ValueError:
        return []
    pref = [m for m in sc.msgs if m.startswith((".linqmap.", ".com.waze."))] or list(sc.msgs)
    counts = collections.Counter((n, w) for n, w, _ in top)
    first = []
    for name in pref:
        k = u = 0
        for (n, w), c in counts.items():
            hit = sc.lookup(name, n)
            if hit is not None and wt_ok(hit[0], w):
                k += c
            else:
                u += c
        if k:
            first.append((u, -k, name))
    first.sort()
    refined = []
    for _, _, name in first[:60]:
        out = []
        ok, bad = decode_msg(sc, name, buf, 0, out)
        refined.append((bad, -ok, name, out))
    refined.sort(key=lambda x: x[:3])
    return refined[:topn]


def summarize(sc, root, buf):
    """Inventory of the commands inside a Batch: which Element fields, how many."""
    hit = sc.lookup(root, 1001)
    if hit is None or hit[0].type != MESSAGE:
        return ["(root has no field 1001 to summarize)"]
    elem = hit[0].type_name
    kinds, total = collections.Counter(), 0
    for num, wt, v in parse_wire(buf):
        if num != 1001 or wt != 2:
            continue
        total += 1
        try:
            inner = parse_wire(v)
        except ValueError:
            kinds["<malformed element>"] += 1
            continue
        for n, w, _ in inner:
            h = sc.lookup(elem, n)
            kinds[f"{h[0].name} [{n}]" if h is not None else f"?{n}"] += 1
    lines = [f"{total} element(s) in the batch:"]
    lines += [f"  {c:5d}  {k}" for k, c in kinds.most_common()]
    return lines


# ---------- input ----------

def get_body(a):
    if a.hex:
        data = bytes.fromhex(a.hex.replace(" ", ""))
    elif a.b64:
        data = base64.b64decode(a.b64)
    elif a.file:
        data = pathlib.Path(a.file).read_bytes()
    elif a.flow:
        f = CAP / "flows.jsonl"
        if not f.exists():
            sys.exit(f"{f} not found")
        flows = [json.loads(l) for l in f.read_text().splitlines() if l.strip()]
        flows = [r for r in flows if r.get("ev") == "http" and a.flow in r["url"]]
        if a.index >= len(flows):
            sys.exit(f"only {len(flows)} flow(s) match {a.flow!r}")
        name = flows[a.index].get("req_body" if a.side == "req" else "res_body")
        if not name:
            sys.exit("that flow has no saved body on that side")
        data = (CAP / name).read_bytes()
    else:
        sys.exit(__doc__)
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data


def looks_like_lines(data):
    try:
        t = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if t and all(c.isprintable() or c in "\r\n\t" for c in t) and "," in t.split("\n", 1)[0][:60]:
        return t
    return None


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_argument_group("input")
    src.add_argument("--hex")
    src.add_argument("--b64")
    src.add_argument("--file")
    src.add_argument("--flow", help="URL substring of a captured flow")
    src.add_argument("--index", type=int, default=0, help="which matching flow (0 = first)")
    src.add_argument("--side", choices=["req", "res"], default="req")
    ap.add_argument("--desc", default=str(HOME / "waze_protos" / "descriptors.desc"))
    ap.add_argument("--root", help="full message name (default linqmap.proto.rt.Batch)")
    ap.add_argument("--auto", action="store_true", help="search all message types for the best root")
    ap.add_argument("--summary", action="store_true", help="list which commands a Batch contains")
    ap.add_argument("--max-lines", type=int, default=300)
    a = ap.parse_args()

    data = get_body(a)
    sc = Schema(descriptor_pb2.FileDescriptorSet.FromString(pathlib.Path(a.desc).read_bytes()))
    print(f"(schemas: {len(sc.msgs)} message types, {sum(len(v) for v in sc.exts.values())} extensions)",
          file=sys.stderr)

    def pick_root():
        if a.auto:
            return None
        name = a.root or BATCH
        name = name if name.startswith(".") else "." + name
        if name in sc.msgs:
            return name
        if a.root:
            sys.exit(f"{name} not found in {a.desc}")
        print(f"(note: {BATCH} is not in the schemas; falling back to --auto)", file=sys.stderr)
        return None

    def show(buf, title=""):
        if title:
            print(title)
        root = pick_root()
        if root is not None:
            out = []
            ok, bad = decode_msg(sc, root, buf, 0, out)
            print(f"root: {root[1:]}   explained={ok} unexplained={bad}")
            if a.summary:
                print("\n".join(summarize(sc, root, buf)))
                return
        else:
            best = find_roots(sc, buf)
            if not best:
                print("no schema message explains these bytes; raw view:")
                out = []
                try:
                    generic(parse_wire(buf), 0, out, 0)
                except ValueError:
                    out = ["<not protobuf> " + buf[:48].hex()]
            else:
                for bad, ok, name, _ in best:
                    print(f"candidate: {name[1:]}   explained={-ok} unexplained={bad}")
                out = best[0][3]
                print(f"\nroot: {best[0][2][1:]}")
        for line in out[:a.max_lines]:
            print(line)
        if len(out) > a.max_lines:
            print(f"... {len(out) - a.max_lines} more lines (use --max-lines)")

    text = looks_like_lines(data)
    if text:
        print("legacy text commands:")
        for line in text.splitlines():
            if line.startswith("ProtoBase64,"):
                print("  ProtoBase64,<protobuf>")
                show(base64.b64decode(line.split(",", 1)[1]), "")
            else:
                print("  " + (line if len(line) < 160 else line[:160] + "..."))
        return
    show(data)


if __name__ == "__main__":
    main()
