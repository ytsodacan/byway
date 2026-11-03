import { batchElems, parseWire, cmdOf } from "./wire.js";

function looksLikeLines(body) {
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
    try { elems = batchElems(body); } catch (_) { elems = []; }
    if (elems.length) {
      protos.push(body);
      for (const e of elems) {
        try {
          const f = parseWire(e);
          if (f.length && f[0][0] === 2001 && f[0][1] === 2) {
            const text = new TextDecoder("utf-8", { fatal: false }).decode(f[0][2]);
            lines.push(...text.trim().split("\n").filter(Boolean));
          }
        } catch (_) { /* skip */ }
      }
      return { lines, protos };
    }
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(body);
  for (const ln of text.split("\n")) {
    if (ln.startsWith("ProtoBase64,")) {
      try {
        const bin = atob(ln.slice("ProtoBase64,".length).trim());
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        protos.push(bytes);
      } catch (_) { /* skip */ }
    } else if (ln.trim()) {
      lines.push(ln);
    }
  }
  return { lines, protos };
}

export function signature(lines, protos) {
  const names = [...new Set(lines.map((l) => l.split(",", 1)[0]))].sort();
  const cmdSet = new Set();
  for (const p of protos) {
    try { for (const e of batchElems(p)) cmdSet.add(cmdOf(e)); } catch (_) { /* skip */ }
  }
  cmdSet.delete(2001);
  const cmds = [...cmdSet].sort((a, b) => a - b);
  return names.join("+") + " | " + cmds.join(",");
}

/** KV keys are capped at 512 bytes and signatures can get long: key on a SHA-1 of the signature.
 *  (export_templates.py uses hashlib.sha1(sig.encode()).hexdigest() — keep the two in sync.) */
export async function sigKey(sig) {
  const d = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(sig));
  return "cmd:" + [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
