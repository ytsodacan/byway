#!/usr/bin/env python3
"""Print the STRUCTURE of the captured login/static request and reply with values masked,
so it is safe to paste. Names, field numbers, enums and booleans stay; strings, big numbers
and bytes become <string 12 chars> etc.

    python3 shape.py login req | login res | command req N | command res N
"""
import json, pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pserver as S
D = S.D
LINE = re.compile(r"^(\s*)(\?\d+|\S.*? \[\d+\]): (.*)$")


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


def main():
    kind, side = sys.argv[1], sys.argv[2]
    idx = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    cap = S.CAP
    recs = [json.loads(l) for l in (cap / "flows.jsonl").read_text().splitlines() if l.strip()]
    recs = [r for r in recs if r.get("ev") == "http" and f"rtserver/distrib/{kind}" in r["url"] and r.get("res_body")]
    if idx >= len(recs):
        sys.exit(f"only {len(recs)} {kind} flow(s) captured")
    body = S.unz((cap / recs[idx]["req_body" if side == "req" else "res_body"]).read_bytes())
    sc = D.Schema(S.descriptor_pb2.FileDescriptorSet.FromString(S.DESC.read_bytes()))
    lines, protos = S.parse_request(body) if side == "req" else ([], [body])
    for l in lines:
        parts = l.split(",")
        print(f"legacy: {parts[0]},{','.join('<%d chars>' % len(p) for p in parts[1:])}")
    for p in protos:
        out = []
        D.decode_msg(sc, D.BATCH, p, 0, out)
        for o in out:
            m = LINE.match(o)
            print(f"{m.group(1)}{m.group(2)}: {mask(m.group(3))}" if m else o)


main()
