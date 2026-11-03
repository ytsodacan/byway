#!/usr/bin/env python3
"""Print the definition of protobuf messages from the app's schemas, following nested message types.
Schema names only (no captured data), so it is safe to paste.

    python3 msgdef.py GetSettingsCopilotCarsResponse
    python3 msgdef.py get_settings_copilot_cars_response get_settings_copilot_voices_response   # command names work too
    python3 msgdef.py MoodAsset --depth 5
"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "server"))
import pserver as S
D = S.D

TYPES = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32", 6: "fixed64", 7: "fixed32", 8: "bool",
         9: "string", 12: "bytes", 13: "uint32", 15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"}
MAXL = 200


def main():
    args = sys.argv[1:]
    depth = 4
    if "--depth" in args:
        i = args.index("--depth")
        depth = int(args[i + 1])
        del args[i:i + 2]
    if not args:
        sys.exit(__doc__)
    sc = D.Schema(S.descriptor_pb2.FileDescriptorSet.FromString(S.DESC.read_bytes()))
    ET = sc.lookup(D.BATCH, 1001)[0].type_name
    printed, lines = set(), []

    def fields_of(full):
        m = sc.msgs[full]
        return list(m.field) + [x for x in sc.exts.get(full, {}).values()]

    def show(full, lvl):
        if full in printed or lvl > depth:
            lines.append("  " * lvl + f"... see {full.rsplit('.', 1)[-1]} above" if full in printed else "  " * lvl + "...")
            return
        printed.add(full)
        for f in sorted(fields_of(full), key=lambda f: f.number):
            rep = "repeated " if f.label == D.REPEATED else ""
            if f.type == D.MESSAGE:
                tn = f.type_name.rsplit(".", 1)[-1]
                lines.append("  " * lvl + f"{f.name} [{f.number}]: {rep}{tn}" + ("" if f.type_name in sc.msgs else "  (not in schemas)"))
                if f.type_name in sc.msgs:
                    show(f.type_name, lvl + 1)
            elif f.type == D.ENUM:
                vals = ", ".join(v.name for v in sc.enums[f.type_name].value[:8]) if f.type_name in sc.enums else "?"
                lines.append("  " * lvl + f"{f.name} [{f.number}]: {rep}enum {f.type_name.rsplit('.', 1)[-1]} ({vals})")
            else:
                lines.append("  " * lvl + f"{f.name} [{f.number}]: {rep}{TYPES.get(f.type, '?')}")

    for a in args:
        full = None
        hit = {x.name: x for x in list(sc.msgs[ET].field) + list(sc.exts.get(ET, {}).values())}.get(a)
        if hit is not None and hit.type_name in sc.msgs:
            full = hit.type_name                     # a command name: use its message type
        else:
            full = next((m for m in sc.msgs if m.rsplit(".", 1)[-1] == a), None)
        if full is None:
            lines.append(f"{a}: not found")
            continue
        lines.append(f"=== {a}  ({full[1:]})")
        show(full, 1)
        lines.append("")
    print("\n".join(lines[:MAXL]))
    if len(lines) > MAXL:
        print(f"... {len(lines) - MAXL} more lines (use fewer names or --depth 3)")


main()
