import { batchElems, parseWire, cmdOf } from "./wire.js";

function looksLikeLines(body) {
  // crude mirror of decode.py's looks_like_lines: mostly-printable text in the first bytes
  const sample = body.slice(0, 64);
  if (!sample.length) return false;
  let printable = 0;
  for (const b of sample) if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13) printable++;
  return printable / sample.length > 0.9;
}

/** -> { lines: string[], protos: Uint8Array[] } */
export function parseRequest(body) {
  const lines = [];
  const protos = [];
  if (!looksLikeLines(body)) {
    let elems = [];
    try {
      elems = batchElems(body);
    } catch (_) {
      elems = [];
    }
    if (elems.length) {
      protos.push(body);
      for (const e of elems) {
        const f = parseWire(e);
        if (f.length && f[0][0] === 2001 && f[0][1] === 2) {
          const text = new TextDecoder("utf-8", { fatal: false }).decode(f[0][2]);
          lines.push(...text.trim().split("\n").filter(Boolean));
        }
      }
      return { lines, protos };
    }
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(body);
  for (const ln of text.split("\n")) {
    if (ln.startsWith("ProtoBase64,")) {
      try {
        const b64 = ln.split(",", 2)[1] ?? ln.slice("ProtoBase64,".length);
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        protos.push(bytes);
      } catch (_) {
        /* skip unparsable line */
      }
    } else if (ln.trim()) {
      lines.push(ln);
    }
  }
  return { lines, protos };
}

export function signature(lines, protos) {
  const names = [...new Set(lines.map((l) => l.split(",", 1)[0]))].sort();
  const cmdSet = new Set();
  for (const p of protos) for (const e of batchElems(p)) cmdSet.add(cmdOf(e));
  cmdSet.delete(2001);
  const cmds = [...cmdSet].sort((a, b) => a - b);
  return names.join("+") + " | " + cmds.join(",");
}
