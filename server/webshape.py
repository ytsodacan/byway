#!/usr/bin/env python3
"""Print the structure of the marketplace web replies the proxy saved (~/waze_private/unseen/*_web_*.json).
Short plain strings and image URLs (query strings cut) are shown; token-looking strings become <N chars>.
Gallery content is public, but read it before pasting.

    python3 webshape.py            # newest gallery / config replies
    python3 webshape.py gallery    # only files whose name contains this
    python3 webshape.py gallery --depth 7
"""
import json, pathlib, re, sys
UNSEEN = pathlib.Path.home() / "waze_private" / "unseen"
TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.]{24,}")


def val(s):
    if re.match(r"https?://", s) and len(s) <= 140:
        return json.dumps(s.split("?")[0] + ("?…" if "?" in s else ""))
    if len(s) <= 60 and not TOKEN.fullmatch(s):
        return json.dumps(s)
    return f"<string {len(s)} chars>"


def show(x, lvl, depth, out, key=""):
    ind = "  " * lvl
    if isinstance(x, dict):
        out.append(f"{ind}{key}{{ {len(x)} keys")
        if lvl < depth:
            for k, v in list(x.items())[:40]:
                show(v, lvl + 1, depth, out, f"{k}: ")
        out.append(f"{ind}}}")
    elif isinstance(x, list):
        out.append(f"{ind}{key}[ {len(x)} items")
        if lvl < depth and x:
            show(x[0], lvl + 1, depth, out, "[0] ")
            if len(x) > 1:
                show(x[1], lvl + 1, depth, out, "[1] ")
        out.append(f"{ind}]")
    elif isinstance(x, str):
        out.append(f"{ind}{key}{val(x)}")
    else:
        out.append(f"{ind}{key}{json.dumps(x)}")


def main():
    a = sys.argv[1:]
    depth = 6
    if "--depth" in a:
        i = a.index("--depth"); depth = int(a[i + 1]); del a[i:i + 2]
    tag = a[0] if a else ""
    files = [f for f in sorted(UNSEEN.glob("*_web_*.bin")) if tag in f.name]
    latest = {}
    for f in files:
        latest[f.name.split("_web_", 1)[1]] = f
    if not latest:
        sys.exit(f"no saved web replies in {UNSEEN}: run ./start.sh, open the marketplace in Waze, wait 10 seconds")
    for name, f in latest.items():
        raw = f.read_bytes()
        print("=" * 60)
        print(name, f"({len(raw)} bytes)")
        try:
            out = []
            show(json.loads(raw), 0, depth, out)
            print("\n".join(out[:150]))
            if len(out) > 150:
                print(f"... {len(out) - 150} more lines")
        except ValueError:
            print("(not JSON) starts:", repr(raw[:80]))


main()
