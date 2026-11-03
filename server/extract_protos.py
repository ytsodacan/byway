#!/usr/bin/env python3
"""Find protobuf schemas embedded in an app binary and write them out.

Many apps ship their message definitions as serialized FileDescriptorProtos
(C++ protobuf does this). This scans a binary for them, so we can read message
and service definitions instead of guessing the wire format.

Usage:
    pip3 install protobuf
    python3 extract_protos.py ~/Downloads/waze/Payload/Waze.app/Waze [outdir]

Output (default ./protos_out):
    descriptors.desc   FileDescriptorSet; use with `protoc --decode`
    <path>/<name>.proto  readable .proto source for each schema found
    summary.txt        what was found
"""
import pathlib
import re
import sys

from google.protobuf import descriptor_pb2

FILE_FIELDS = set(range(1, 16))          # field numbers FileDescriptorProto uses
NAMECHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-")

SCALARS = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32", 6: "fixed64",
           7: "fixed32", 8: "bool", 9: "string", 12: "bytes", 13: "uint32",
           15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"}


# ---------- locating descriptors in the binary ----------

def read_varint(buf, i):
    shift = val = 0
    while True:
        if i >= len(buf) or shift > 63:
            return None, i
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def extent(buf, start):
    """Walk protobuf wire format from `start`; return where valid
    FileDescriptorProto fields stop."""
    i = last = start
    n = len(buf)
    while i < n:
        tag, j = read_varint(buf, i)
        if tag is None:
            break
        field, wt = tag >> 3, tag & 7
        if field not in FILE_FIELDS or wt not in (0, 2):
            break
        if wt == 0:
            v, j = read_varint(buf, j)
            if v is None:
                break
        else:
            ln, j = read_varint(buf, j)
            if ln is None or j + ln > n:
                break
            j += ln
        i = last = j
    return last


def candidates(data):
    """Yield offsets where `0x0a <len> <name>.proto` begins (field 1: name)."""
    seen = set()
    pos = 0
    while True:
        idx = data.find(b".proto", pos)
        if idx < 0:
            return
        pos = idx + 1
        end = idx + 6
        s = idx
        while s > 0 and end - s < 128 and chr(data[s - 1]) in NAMECHARS:
            s -= 1
        for start in range(s, idx + 1):
            k = end - start
            if 1 <= k <= 127 and start >= 2 and data[start - 1] == k and data[start - 2] == 0x0A:
                if start - 2 not in seen:
                    seen.add(start - 2)
                    yield start - 2


# ---------- rendering FileDescriptorProto as .proto text ----------

def tname(f):
    return SCALARS.get(f.type) or f.type_name


def render_field(f, maps, syn, in_oneof=False):
    if f.label == 3 and f.type == 11:
        entry = maps.get(f.type_name.rsplit(".", 1)[-1])
        if entry is not None and len(entry.field) == 2:
            return f"map<{tname(entry.field[0])}, {tname(entry.field[1])}> {f.name} = {f.number};"
    label = ""
    if not in_oneof:
        if f.label == 3:
            label = "repeated "
        elif syn == "proto2":
            label = "required " if f.label == 2 else "optional "
        elif f.proto3_optional:
            label = "optional "
    opts = ""
    if syn == "proto2" and f.label == 3 and f.HasField("options") and f.options.packed:
        opts = " [packed = true]"
    return f"{label}{tname(f)} {f.name} = {f.number}{opts};"


def render_extend(exts, lvl, syn):
    """`extend X { ... }` blocks; commands in this protocol are often extensions."""
    ind = "  " * lvl
    by = {}
    for x in exts:
        by.setdefault(x.extendee, []).append(x)
    out = []
    for target, fields in by.items():
        out.append(f"{ind}extend {target} {{")
        out += [f"{ind}  {render_field(f, {}, syn)}" for f in fields]
        out += [f"{ind}}}", ""]
    return out


def render_enum(e, lvl):
    ind = "  " * lvl
    out = [f"{ind}enum {e.name} {{"]
    if e.options.allow_alias:
        out.append(f"{ind}  option allow_alias = true;")
    out += [f"{ind}  {v.name} = {v.number};" for v in e.value]
    return out + [f"{ind}}}", ""]


def render_msg(m, lvl, syn):
    ind = "  " * lvl
    out = [f"{ind}message {m.name} {{"]
    maps = {n.name: n for n in m.nested_type if n.options.map_entry}
    for n in m.nested_type:
        if n.name not in maps:
            out += render_msg(n, lvl + 1, syn)
    for e in m.enum_type:
        out += render_enum(e, lvl + 1)
    groups = {}
    for f in m.field:
        if f.HasField("oneof_index") and not f.proto3_optional:
            groups.setdefault(f.oneof_index, []).append(f)
    done = set()
    for f in m.field:
        if f.HasField("oneof_index") and not f.proto3_optional:
            oi = f.oneof_index
            if oi in done:
                continue
            done.add(oi)
            out.append(f"{ind}  oneof {m.oneof_decl[oi].name} {{")
            out += [f"{ind}    {render_field(g, maps, syn, True)}" for g in groups[oi]]
            out.append(f"{ind}  }}")
        else:
            out.append(f"{ind}  {render_field(f, maps, syn)}")
    for r in m.extension_range:
        hi = "max" if r.end > 536870911 else str(r.end - 1)
        out.append(f"{ind}  extensions {r.start} to {hi};")
    out += render_extend(m.extension, lvl + 1, syn)
    return out + [f"{ind}}}", ""]


def render_service(s):
    out = [f"service {s.name} {{"]
    for m in s.method:
        cs = "stream " if m.client_streaming else ""
        ss = "stream " if m.server_streaming else ""
        out.append(f"  rpc {m.name}({cs}{m.input_type}) returns ({ss}{m.output_type});")
    return out + ["}", ""]


def render(fd):
    syn = fd.syntax if fd.syntax in ("proto2", "proto3") else "proto2"
    out = [f'syntax = "{syn}";']
    if fd.package:
        out.append(f"package {fd.package};")
    out += [f'import "{d}";' for d in fd.dependency]
    out.append("")
    for e in fd.enum_type:
        out += render_enum(e, 0)
    for m in fd.message_type:
        out += render_msg(m, 0, syn)
    out += render_extend(fd.extension, 0, syn)
    for s in fd.service:
        out += render_service(s)
    return "\n".join(out) + "\n"


# ---------- main ----------

def safe_rel(name):
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    return pathlib.PurePosixPath(*parts)


def extract(data):
    found = {}
    for off in candidates(data):
        blob = data[off:extent(data, off)]
        fd = descriptor_pb2.FileDescriptorProto()
        try:
            fd.ParseFromString(blob)
        except Exception:
            continue
        if not fd.name.endswith(".proto"):
            continue
        if not (fd.message_type or fd.enum_type or fd.service or fd.extension):
            continue
        prev = found.get(fd.name)
        if prev is None or len(blob) > len(prev[1]):
            found[fd.name] = (fd, blob)
    return found


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    data = pathlib.Path(sys.argv[1]).read_bytes()
    out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "protos_out")
    out.mkdir(parents=True, exist_ok=True)

    found = extract(data)
    fds = descriptor_pb2.FileDescriptorSet()
    lines = []
    for name in sorted(found):
        fd = found[name][0]
        fds.file.append(fd)
        rel = safe_rel(name)
        if rel is not None:
            p = out / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(render(fd))
        lines.append(f"{name}  package={fd.package or '-'}  messages={len(fd.message_type)}"
                     f"  enums={len(fd.enum_type)}  services={len(fd.service)}")
        for s in fd.service:
            lines.append(f"    service {s.name}: " + ", ".join(m.name for m in s.method))
    (out / "descriptors.desc").write_bytes(fds.SerializeToString())
    summary = f"{len(found)} schema file(s) found in {sys.argv[1]}\n" + "\n".join(lines) + "\n"
    (out / "summary.txt").write_text(summary)
    print(summary)


if __name__ == "__main__":
    main()
