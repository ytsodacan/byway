#!/usr/bin/env python3
"""Compare the STRUCTURE of the real register / generate_token / login replies (from the capture in
WAZE_CAPTURE_DIR, default ~/waze_capture) with what the private server makes up. Values are masked
(strings -> <string N chars>, numbers over 999 -> <int N digits>, bytes -> <bytes N>), so the output is
safe to paste.

    WAZE_CAPTURE_DIR=~/waze_capture_guest python3 elemshape.py           # real flows, in order
    WAZE_CAPTURE_DIR=~/waze_capture_guest python3 elemshape.py ours      # also what pserver would answer
    python3 elemshape.py names register token login_response             # pick which element names to show

Default names shown: register_successful, client_auth_token, login_response, generate_token (request).
Every rtserver reply is listed with its element order and size, so the envelope is visible too.
"""
import collections, json, pathlib, re, sys
from urllib.parse import urlsplit
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pserver as S
D = S.D
LINE = re.compile(r"^(\s*)(\?\d+|\S.*? \[\d+\]): (.*)$")
DEFAULT = ("register", "register_successful", "register_failed", "generate_token", "client_auth_token",
           "login_response")
MAXL = 60


def mask(v):
    if v in ("true", "false") or re.fullmatch(r"[A-Z][A-Z0-9_]+", v):
        return v
    if v.startswith(("'", '"')):
        return f"<string {max(len(v) - 2, 0)} chars>"
    if re.fullmatch(r"-?\d+", v):
        return v if abs(int(v)) < 1000 else f"<int {len(v.lstrip('-'))} digits>"
    if re.fullmatch(r"-?[\d.]+(e-?\d+)?", v):
        return "<float>"
    return f"<bytes {len(v) // 2}>"


sc = D.Schema(S.descriptor_pb2.FileDescriptorSet.FromString(S.DESC.read_bytes()))
ET = sc.lookup(D.BATCH, 1001)[0].type_name


def name_of(elem):
    h = sc.lookup(ET, S.cmd_of(elem))
    return h[0].name if h else f"?{S.cmd_of(elem)}"


def show(title, elem):
    out = []
    D.decode_msg(sc, ET, elem, 0, out)
    print(f"--- {title} ({len(elem)} bytes)")
    for o in out[:MAXL]:
        m = LINE.match(o)
        print(f"{m.group(1)}{m.group(2)}: {mask(m.group(3))}" if m else re.sub(r"'[^']*'", "<string>", o))
    if len(out) > MAXL:
        print(f"... {len(out) - MAXL} more lines")


def elems(body):
    try:
        if D.looks_like_lines(body):
            return []
        return S.batch_elems(body)
    except ValueError:
        return []


def real(want):
    rows = [json.loads(l) for l in (S.CAP / "flows.jsonl").read_text().splitlines() if l.strip()]
    rows = sorted((r for r in rows if r.get("ev") == "http" and "rtserver/distrib/" in r["url"]), key=lambda r: r["t"])
    t0 = rows[0]["t"] if rows else 0
    print(f"=== REAL rtserver flows in {S.CAP} ({len(rows)})")
    shown = collections.Counter()
    for r in rows:
        kind = urlsplit(r["url"]).path.rstrip("/").rsplit("/", 1)[-1]

        def body(k):
            p = r.get(k) and S.CAP / r[k]
            return S.unz(p.read_bytes()) if p and p.exists() else b""
        rq, rs = elems(body("req_body")), elems(body("res_body"))
        rq_names = [name_of(e) for e in rq if S.cmd_of(e) not in (2001, 2184)]
        rs_names = [name_of(e) for e in rs]
        print(f"+{r['t'] - t0:6.1f}s {kind:8} {r['status']} {r.get('res_size', '?')}b  "
              f"REQ[{','.join(rq_names) or '-'}]  RES[{','.join(rs_names[:10])}{'...' if len(rs_names) > 10 else ''}]")
        for side, es in (("request", rq), ("reply", rs)):
            for e in es:
                n = name_of(e)
                if n in want and shown[(side, n)] < 2:
                    shown[(side, n)] += 1
                    show(f"REAL {kind} {side}: {n}", e)


def ours(want):
    print("\n=== OURS (pserver's made-up replies, dummy values)")
    srv = S.Server()
    now = 1_700_000_000
    import auth, tempfile, pathlib
    auth.DIR = pathlib.Path(tempfile.mkdtemp()); auth.USERS = auth.DIR / "users.json"; auth.SESSIONS = auth.DIR / "sessions.json"
    for e in srv.register_guest([]) or []:
        show("OURS register reply: " + name_of(e), e)
    # answer_for takes the REQUEST command number
    f = srv.codec.field(srv.elem_type, "generate_token")
    if f is not None:
        e, note = srv.answer_for(f.number, now)
        print(f"({note})")
        if e is not None:
            show("OURS generate_token reply", e)
    print("envelope we append to made-up replies:", [name_of(x) for x in srv._envelope()] or "none found")


def main():
    args = sys.argv[1:]
    want = set(DEFAULT)
    if args and args[0] == "names":
        want = set(args[1:])
        args = []
    real(want)
    if "ours" in args:
        ours(want)


main()
