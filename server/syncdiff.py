#!/usr/bin/env python3
"""Compare the sync_config_request the app sent to the private server (saved in ~/waze_private/unseen)
with the sync_config_request/_response pairs in the real capture. Structure only, values masked
(strings -> <string N chars>, numbers over 999 -> <int N digits>), so it is safe to paste.

    python3 syncdiff.py
"""
import json, pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pserver as S
D = S.D
LINE = re.compile(r"^(\s*)(\?\d+|\S.*? \[\d+\]): (.*)$")
REQ, RES, MAXL = 2167, 2168, 70


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


def show(title, elem):
    out = []
    D.decode_msg(sc, ET, elem, 0, out)
    print(f"--- {title} ({len(elem)} bytes)")
    for o in out[:MAXL]:
        m = LINE.match(o)
        print(f"{m.group(1)}{m.group(2)}: {mask(m.group(3))}" if m else re.sub(r"'[^']*'", "<string>", o))
    if len(out) > MAXL:
        print(f"... {len(out) - MAXL} more lines")


def elems_of(body, num):
    _, protos = S.parse_request(S.unz(body))
    return [e for p in protos for e in S.batch_elems(p) if S.cmd_of(e) == num]


def main():
    print("=== what the APP sent to the private server (newest 2)")
    for f in [f for f in sorted(S.UNSEEN.glob("*_command.bin"))][-6:]:
        es = elems_of(f.read_bytes(), REQ)
        for e in es[-1:]:
            show("app request " + f.name.split("_")[0], e)
    print("\n=== REAL capture: request/response pairs")
    rows = [json.loads(l) for l in (S.CAP / "flows.jsonl").read_text().splitlines() if l.strip()]
    n = 0
    for r in rows:
        if r.get("ev") != "http" or "rtserver/distrib/command" not in r["url"] or not (r.get("req_body") and r.get("res_body")):
            continue
        rq = elems_of((S.CAP / r["req_body"]).read_bytes(), REQ)
        rs = [e for e in S.batch_elems(S.unz((S.CAP / r["res_body"]).read_bytes())) if S.cmd_of(e) == RES]
        if not (rq or rs):
            continue
        n += 1
        print(f"\n##### captured pair #{n}: request has sync_config={bool(rq)}, reply has sync_config_response={bool(rs)}")
        for e in rq[:1]:
            show("captured sync_config_request", e)
        for e in rs[:1]:
            show("captured sync_config_response", e)
        if n >= 3:
            break
    print("\n=== what the private server REPLIED to the app's lone sync_config_request: the same captured_response above, retimed")


main()
