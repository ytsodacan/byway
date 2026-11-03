#!/usr/bin/env python3
"""Which UpdateConfig settings differ between the REAL geo reply (saved in ~/waze_private/unseen) and your
captured replies? Setting names are shown; values are shown only if they are short numbers/booleans/ALL_CAPS
words, otherwise just their length. Safe to paste.

    python3 confdiff.py
"""
import collections, pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pserver as S
D = S.D
SAFE = re.compile(r"-?\d{1,6}|true|false|[A-Z_]{2,20}")
NAME = re.compile(r"[A-Za-z0-9_.:-]{1,60}")


def lines_of(elems):
    for e in elems:
        f = D.parse_wire(e)
        if f and f[0][0] == 2001 and f[0][1] == 2:
            yield from (l for l in f[0][2].decode("utf-8", "replace").splitlines() if l.strip())


def conf(elems):
    out = collections.defaultdict(set)
    for ln in lines_of(elems):
        p = ln.split(",")
        if p[0] == "UpdateConfig" and len(p) >= 4:
            out[(p[1], p[2])].add(",".join(p[3:]))
    return out


def nm(x):
    return x if NAME.fullmatch(x) else f"<{len(x)} chars>"


def val(v):
    return ",".join(x if SAFE.fullmatch(x) else f"<{len(x)}>" for x in v.split(","))


def main():
    files = [f for f in sorted(S.UNSEEN.glob("*_geo_reply.bin")) if f.stat().st_size > 1000]
    if not files:
        sys.exit("no geo reply saved yet")
    geo_elems = S.batch_elems(S.unz(files[-1].read_bytes()))
    geo = conf(geo_elems)
    for ln in lines_of(geo_elems):
        if ln.startswith("GeoServerConfig") and len(ln) < 80:
            print("real geo line:", ln)
    srv = S.Server()
    cap = collections.defaultdict(set)
    for r in srv.recs:
        for k, v in conf(r["elems"]).items():
            cap[k] |= v
    both = [k for k in geo if k in cap]
    diff = [k for k in both if not (geo[k] & cap[k])]
    only_geo = [k for k in geo if k not in cap]
    only_cap = [k for k in cap if k not in geo]
    print(f"UpdateConfig settings: real geo reply {len(geo)}, your capture {len(cap)}, in both {len(both)}")
    print(f"  same value: {len(both) - len(diff)}   DIFFERENT value: {len(diff)}   only in geo: {len(only_geo)}   only in capture: {len(only_cap)}")
    print("\nDIFFERENT value (setting: geo -> capture):")
    for k in sorted(diff)[:40]:
        print(f"  {nm(k[0])} / {nm(k[1])}: {', '.join(val(v) for v in sorted(geo[k]))[:40]} -> {', '.join(val(v) for v in sorted(cap[k]))[:40]}")
    print("\nonly in the real geo reply:")
    for k in sorted(only_geo)[:25]:
        print(f"  {nm(k[0])} / {nm(k[1])}: {', '.join(val(v) for v in sorted(geo[k]))[:40]}")
    print("\nonly in your capture:")
    for k in sorted(only_cap)[:25]:
        print(f"  {nm(k[0])} / {nm(k[1])}")


main()
