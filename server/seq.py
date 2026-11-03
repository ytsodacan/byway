#!/usr/bin/env python3
"""Print the ORDER of everything the real Waze app did in the capture (~/waze_capture), with command
names, so it can be compared to what the private server saw. Only structure is printed: no query
strings, cookies, bodies or values, so it is safe to paste.

    python3 seq.py            # first 70 requests from the first login on
    python3 seq.py 150        # first 150
"""
import collections, json, pathlib, sys
from urllib.parse import urlsplit
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pserver as S
D = S.D
sc = D.Schema(S.descriptor_pb2.FileDescriptorSet.FromString(S.DESC.read_bytes()))
elem = sc.lookup(D.BATCH, 1001)[0].type_name


def nm(c):
    h = sc.lookup(elem, c)
    return h[0].name if h else str(c)


def cmds(body):
    try:
        lines, protos = S.parse_request(S.unz(body))
        c = collections.Counter(nm(S.cmd_of(e)) for p in protos for e in S.batch_elems(p))
        c.update("legacy:" + l.split(",")[0] for l in lines)
        c.pop("legacy_command", None)
        return ",".join(f"{k}x{v}" if v > 1 else k for k, v in c.most_common(8)) or "-"
    except Exception:
        return "?"


def res_cmds(body):
    try:
        b = S.unz(body)
        if D.looks_like_lines(b):
            return "legacy text"
        c = collections.Counter(nm(S.cmd_of(e)) for e in S.batch_elems(b))
        return ",".join(f"{k}x{v}" if v > 1 else k for k, v in c.most_common(8)) or "-"
    except Exception:
        return "?"


def main():
    args = [a for a in sys.argv[1:] if a != "all"]
    n = int(args[0]) if args else 70
    rows = [json.loads(l) for l in (S.CAP / "flows.jsonl").read_text().splitlines() if l.strip()]
    rows = sorted((r for r in rows if r.get("ev") == "http"), key=lambda r: r["t"])
    start = 0 if "all" in sys.argv else next((i for i, r in enumerate(rows) if "rtserver/distrib/login" in r["url"]), 0)
    rows = rows[start:start + n]
    t0 = rows[0]["t"] if rows else 0
    for r in rows:
        u = urlsplit(r["url"])
        line = f"+{r['t'] - t0:6.1f}s {r.get('method', '?'):4} {u.netloc}{u.path[:70]} {r['status']} {r.get('res_size', '?')}b"
        if "rtserver" in u.path:
            def body(k):
                p = r.get(k) and S.CAP / r[k]
                return p.read_bytes() if p and p.exists() else b""
            line += f"   REQ[{cmds(body('req_body'))}] RES[{res_cmds(body('res_body'))}]"
        print(line)


main()
