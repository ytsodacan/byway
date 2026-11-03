#!/usr/bin/env python3
"""Print the STRUCTURE of requests the private server had no template for
(saved in ~/waze_private/unseen), with every value masked so it is safe to paste.
Strings, numbers over 999 and bytes become <string 12 chars> / <int 13 digits> / <bytes 35>.

    python3 unseen_shape.py            # the 6 newest
    python3 unseen_shape.py 15         # the 15 newest
    python3 unseen_shape.py login 2    # only files whose tag contains "login" (or "command", "static"), newest 2

A Logout line also shows its snake_case word parameters (e.g. a reason like "session_expired"); numbers and tokens stay masked.
"""
import pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pserver as S
D = S.D
LINE = re.compile(r"^(\s*)(\?\d+|\S.*? \[\d+\]): (.*)$")
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_ .-]{0,40}")


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


def show_proto(sc, p):
    out = []
    ok, _ = D.decode_msg(sc, D.BATCH, p, 0, out)
    if ok == 0:
        out = []
        try:
            D.generic(D.parse_wire(p), 0, out, 0)
            print("(not a known Batch; generic field view)")
        except ValueError:
            return print(f"<not protobuf: {len(p)} bytes>")
    for o in out:
        if "<malformed" in o:
            print("<malformed, masked>")
            continue
        m = LINE.match(o)
        print(f"{m.group(1)}{m.group(2)}: {mask(m.group(3))}" if m else re.sub(r"'[^']*'", "<string>", o))


def main():
    a = sys.argv[1:]
    tag = a.pop(0) if a and not a[0].isdigit() else ""
    n = int(a[0]) if a else 6
    files = [f for f in sorted(S.UNSEEN.glob("*.bin")) if tag in f.name][-n:]
    if not files:
        sys.exit(f"nothing in {S.UNSEEN}" + (f" matching {tag!r}" if tag else ""))
    sc = D.Schema(S.descriptor_pb2.FileDescriptorSet.FromString(S.DESC.read_bytes()))
    for f in files:
        body = S.unz(f.read_bytes())
        print("=" * 60)
        print(f.name.split("_", 1)[1], f"({len(body)} bytes)")
        if D.looks_like_lines(body):
            lines, protos = S.parse_request(body)
            for l in lines:
                parts = l.split(",")
                word = lambda x: re.fullmatch(r"[a-z]{2,15}(_[a-z]{2,15}){0,3}", x)
                if parts[0] == "Logout":
                    print("legacy: Logout," + ",".join(x if word(x) else "<%d chars>" % len(x) for x in parts[1:]))
                else:
                    print(f"legacy: {parts[0]},{','.join('<%d chars>' % len(x) for x in parts[1:])}"
                          if NAME.fullmatch(parts[0]) else f"legacy: <non-text line, {len(l)} chars>")
            for p in protos:
                show_proto(sc, p)
        else:
            show_proto(sc, body)


main()
