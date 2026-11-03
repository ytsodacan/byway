#!/usr/bin/env python3
"""Look up protobuf field numbers in the extracted schemas.

The Waze realtime protocol wraps every command in an envelope and identifies
the command by a field number (e.g. 2685). This finds which message / command
owns a given number, including fields added through `extend`.

    python3 fieldmap.py 1001 2184 2685 2761 2709 2150
    python3 fieldmap.py --desc ~/waze_protos/descriptors.desc 2685
    python3 fieldmap.py --name Login        # search names instead of numbers
"""
import argparse
import pathlib
import sys

from google.protobuf import descriptor_pb2

TYPES = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32", 6: "fixed64", 7: "fixed32",
         8: "bool", 9: "string", 10: "group", 11: "message", 12: "bytes", 13: "uint32", 14: "enum",
         15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"}


def rows(fds):
    """Yield (number, kind, owner, name, type, file) for every field and extension."""
    def walk(prefix, msgs, fname):
        for m in msgs:
            full = f"{prefix}.{m.name}" if prefix else m.name
            for f in m.field:
                yield (f.number, "field", full, f.name, TYPES.get(f.type, "?") + (f" {f.type_name}" if f.type_name else ""), fname)
            for x in m.extension:
                yield (x.number, "ext", x.extendee.lstrip("."), x.name, TYPES.get(x.type, "?") + (f" {x.type_name}" if x.type_name else ""), fname)
            yield from walk(full, m.nested_type, fname)

    for fd in fds.file:
        yield from walk(fd.package, fd.message_type, fd.name)
        for x in fd.extension:
            yield (x.number, "ext", x.extendee.lstrip("."), x.name,
                   TYPES.get(x.type, "?") + (f" {x.type_name}" if x.type_name else ""), fd.name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("numbers", nargs="*", type=int)
    ap.add_argument("--desc", default=str(pathlib.Path.home() / "waze_protos" / "descriptors.desc"))
    ap.add_argument("--name", help="substring to search in message/field names")
    a = ap.parse_args()

    fds = descriptor_pb2.FileDescriptorSet.FromString(pathlib.Path(a.desc).read_bytes())
    allrows = list(rows(fds))

    if a.name:
        n = a.name.lower()
        hits = [r for r in allrows if n in r[2].lower() or n in r[3].lower()]
        for num, kind, owner, name, typ, fname in sorted(hits, key=lambda r: (r[2], r[0]))[:200]:
            print(f"{num:>6}  {kind:5} {owner}.{name}  ({typ})")
        print(f"\n{len(hits)} match(es)")
        return

    if not a.numbers:
        sys.exit(__doc__)
    for num in a.numbers:
        hits = [r for r in allrows if r[0] == num]
        print(f"=== {num}: {len(hits)} definition(s)")
        for _, kind, owner, name, typ, fname in hits[:25]:
            word = "extends" if kind == "ext" else "in"
            print(f"  {name}  ({typ})  {word} {owner}   [{fname.split('/')[-1]}]")
        if len(hits) > 25:
            print(f"  ... {len(hits) - 25} more")


if __name__ == "__main__":
    main()
