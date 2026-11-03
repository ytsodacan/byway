#!/usr/bin/env python3
"""Find where marketplace / moods / cars live in the Waze protocol. Safe to paste: schema names only, plus
masked shapes (strings -> <string N chars>, numbers over 999 -> <int N digits>) of matching elements that
appear in your captures (~/waze_capture and ~/waze_capture_guest) and in what the app sent the private server.

    python3 mpfind.py                 # default keywords
    python3 mpfind.py skin avatar     # your own keywords (matched inside field and message names)
"""
import json, pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pserver as S
import fieldmap as F
D = S.D

DEFAULT = ["market", "mood", "vehicle", "car_", "_car", "skin", "avatar", "inventory", "purchas", "store", "item_"]
LINE = re.compile(r"^(\s*)(\?\d+|\S.*? \[\d+\]): (.*)$")


def snake(s):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower()


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
    kws = [k.lower() for k in sys.argv[1:]] or DEFAULT
    hit = lambda *names: any(k in snake(n) for n in names for k in kws)
    fds = S.descriptor_pb2.FileDescriptorSet.FromString(S.DESC.read_bytes())
    rows = list(F.rows(fds))
    sc = D.Schema(fds)
    ET = sc.lookup(D.BATCH, 1001)[0].type_name

    print("=== commands (fields of Element) whose name matches")
    cmds = sorted((r for r in rows if r[2].endswith(ET.lstrip(".").split(".")[-1]) and hit(r[3])), key=lambda r: r[0])
    for num, kind, owner, name, typ, _ in cmds[:80]:
        print(f"  {num:>5} {name}  ({typ})")
    print(f"  ({len(cmds)} found)")

    print("\n=== other messages / fields whose name matches (first 60)")
    seen = 0
    for num, kind, owner, name, typ, _ in sorted(rows, key=lambda r: (r[2], r[0])):
        if (hit(name) or hit(owner.split('.')[-1])) and not owner.endswith("Element") and seen < 60:
            print(f"  {owner.split('.')[-1]}.{name} [{num}]  ({typ})")
            seen += 1

    wanted = {r[0] for r in cmds}
    names = {r[0]: r[3] for r in cmds}
    print("\n=== where those commands appear in captures / app requests")
    caps = [S.HOME / "waze_capture", S.HOME / "waze_capture_guest"]
    shown = set()
    for cap in caps:
        fl = cap / "flows.jsonl"
        if not fl.exists():
            continue
        for line in fl.read_text().splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("ev") != "http" or "rtserver/distrib/" not in r.get("url", ""):
                continue
            for side in ("req_body", "res_body"):
                p = r.get(side) and cap / r[side]
                if not p or not p.exists():
                    continue
                try:
                    body = S.unz(p.read_bytes())
                    es = [] if D.looks_like_lines(body) else S.batch_elems(body)
                except ValueError:
                    continue
                for e in es:
                    c = S.cmd_of(e)
                    if c in wanted and (c, side, cap.name) not in shown:
                        shown.add((c, side, cap.name))
                        out = []
                        D.decode_msg(sc, ET, e, 0, out)
                        print(f"--- {names[c]} [{c}] in {cap.name} ({'request' if side == 'req_body' else 'reply'}, {len(e)} bytes)")
                        for o in out[:40]:
                            m = LINE.match(o)
                            print(f"{m.group(1)}{m.group(2)}: {mask(m.group(3))}" if m else re.sub(r"'[^']*'", "<string>", o))
    for f in sorted(S.UNSEEN.glob("*_command.bin"))[-40:] if S.UNSEEN.exists() else []:
        try:
            lines, protos = S.parse_request(S.unz(f.read_bytes()))
            for p in protos:
                for e in S.batch_elems(p):
                    c = S.cmd_of(e)
                    if c in wanted and ("app", c) not in shown:
                        shown.add(("app", c))
                        print(f"(app sent {names[c]} [{c}] to the private server: {f.name.split('_')[0]})")
        except ValueError:
            pass
    if not shown:
        print("  none of them appear in your captures yet")


main()
