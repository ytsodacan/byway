// Schema-free protobuf wire format: encode/decode by field NUMBER only.
// Varints use plain Numbers on the fast path (<= 2^53) and fall back to BigInt
// only for huge values (e.g. negative int64), because BigInt-everywhere is slow
// enough to blow the Workers CPU budget on big world-data replies.

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

export function vint(n) {
  if (typeof n === "number" && n >= 0 && n <= MAX_SAFE) {
    const out = [];
    while (n >= 128) {
      out.push((n % 128) | 0x80);
      n = Math.floor(n / 128);
    }
    out.push(n);
    return Uint8Array.from(out);
  }
  let b = BigInt.asUintN(64, BigInt(n));
  const out = [];
  for (;;) {
    const lo = Number(b & 0x7fn);
    b >>= 7n;
    if (b) out.push(lo | 0x80);
    else {
      out.push(lo);
      break;
    }
  }
  return Uint8Array.from(out);
}

export function tagBytes(num, wt) {
  return vint(num * 8 + wt);
}

export function concat(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function ld(num, payload) {
  return concat([tagBytes(num, 2), vint(payload.length), payload]);
}

/** -> [[fieldNum, wireType, value], ...]; value is Number|BigInt (wt 0) or Uint8Array.
 *  Throws on truncated/overlong data instead of silently clipping it. */
export function parseWire(buf) {
  const out = [];
  let i = 0;
  const readVarint = () => {
    const start = i;
    let result = 0,
      mul = 1;
    for (let k = 0; k < 7; k++) {
      if (i >= buf.length) throw new Error("truncated varint");
      const b = buf[i++];
      result += (b & 0x7f) * mul;
      if (!(b & 0x80)) return result;
      mul *= 128;
    }
    i = start; // long varint: redo in BigInt
    let r = 0n,
      shift = 0n;
    for (;;) {
      if (i >= buf.length) throw new Error("truncated varint");
      const b = buf[i++];
      r |= BigInt(b & 0x7f) << shift;
      if (!(b & 0x80)) break;
      shift += 7n;
      if (shift > 63n) throw new Error("varint too long");
    }
    return r <= BigInt(MAX_SAFE) ? Number(r) : r;
  };
  while (i < buf.length) {
    const key = readVarint();
    let num, wt;
    if (typeof key === "number") {
      num = Math.floor(key / 8);
      wt = key % 8;
    } else {
      num = Number(key >> 3n);
      wt = Number(key & 7n);
    }
    if (num === 0) throw new Error("field number 0");
    if (wt === 0) {
      out.push([num, 0, readVarint()]);
    } else if (wt === 1 || wt === 5) {
      const n = wt === 1 ? 8 : 4;
      if (i + n > buf.length) throw new Error("truncated fixed field");
      out.push([num, wt, buf.subarray(i, i + n)]);
      i += n;
    } else if (wt === 2) {
      const len = readVarint();
      if (typeof len !== "number" || len > buf.length - i) throw new Error("bad length");
      out.push([num, 2, buf.subarray(i, i + len)]);
      i += len;
    } else {
      throw new Error(`unsupported wire type ${wt}`);
    }
  }
  return out;
}

export function batchElems(buf) {
  return parseWire(buf)
    .filter(([n, w]) => n === 1001 && w === 2)
    .map(([, , v]) => v);
}

export function cmdOf(elem) {
  const f = parseWire(elem);
  return f.length ? f[0][0] : 0;
}

export function makeBatch(elems) {
  return concat(elems.map((e) => ld(1001, e)));
}

export function bytesToB64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
