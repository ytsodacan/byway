#!/usr/bin/env python3
"""Compare the real geo-server reply (saved by pserver in ~/waze_private/unseen/*_geo_reply.bin) with what
your captured login/command replies contain. Only legacy-command NAMES, counts and waze/google host names are
shown; every other value becomes <N> (its length), so the output is safe to paste.

    python3 geoinfo.py
"""
import collections, pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pserver as S
D = S.D
HOST = S.Server.HOSTISH
NAME = re.compile(r"[A-Za-z0-9_]{1,40}")
INTEREST = re.compile(r"tile|server|url|host|geo|region|map|config|version", re.I)


def legacy(elems):
    for e in elems:
        f = D.parse_wire(e)
        if f and f[0][0] == 2001 and f[0][1] == 2:
            for ln in f[0][2].decode("utf-8", "replace").splitlines():
                if ln.strip():
                    yield ln


def name_of(ln):
    n = ln.split(",", 1)[0]
    return n if NAME.fullmatch(n) else f"<{len(n)} chars>"


def masked(ln):
    n, _, rest = ln.partition(",")
    flds = [f if (HOST.fullmatch(f) or re.fullmatch(r"-?\d{1,6}|true|false|[A-Z_]{2,20}", f)) else f"<{len(f)}>"
            for f in rest.split(",")[:8]]
    return f"{name_of(ln)},{','.join(flds)}"


def main():
    files = [f for f in sorted(S.UNSEEN.glob("*_geo_reply.bin")) if f.stat().st_size > 1000]
    if not files:
        sys.exit(f"no geo reply saved in {S.UNSEEN} yet: run the server, open Waze, sign out once")
    geo = S.batch_elems(S.unz(files[-1].read_bytes()))
    srv = S.Server()
    cap = collections.Counter()
    for r in srv.recs:
        cap.update(name_of(l) for l in legacy(r["elems"]))
    g = collections.Counter(name_of(l) for l in legacy(geo))
    print(f"geo reply: {len(geo)} elements, {sum(g.values())} legacy commands, {len(g)} distinct names")
    print("most common:", ", ".join(f"{k}x{v}" for k, v in g.most_common(12)))
    only_geo = {k: v for k, v in g.items() if k not in cap}
    print(f"\nin the geo reply but NEVER in your captured replies ({len(only_geo)}):")
    for k, v in sorted(only_geo.items(), key=lambda x: -x[1])[:40]:
        ex = next((masked(l) for l in legacy(geo) if name_of(l) == k), "")
        print(f"  {k} x{v}   e.g. {ex[:110]}")
    only_cap = [k for k in cap if k not in g]
    print(f"\nin your captured replies but NOT in the geo reply ({len(only_cap)}): " + ", ".join(sorted(only_cap)[:30]))
    print("\nlines in the geo reply whose name looks like server/tile/url/config (masked):")
    seen = set()
    for l in legacy(geo):
        n = name_of(l)
        if INTEREST.search(n) and n not in seen and len(seen) < 25:
            seen.add(n)
            print("  " + masked(l)[:140])


main()
