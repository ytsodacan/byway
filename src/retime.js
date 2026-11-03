// Move timestamp-looking varints (seconds or ms, within ~400 days of now) to now.
// Only rebuilds a message if something inside it actually changed; everything
// else is returned byte-for-byte, so strings that merely *happen* to parse as
// protobuf can never be corrupted by a re-encode.
import { parseWire, tagBytes, vint, ld, concat } from "./wire.js";

const DAY = 86400;

function walk(buf, nowS, nowMs, depth) {
  const fields = parseWire(buf); // may throw -> caller leaves buf untouched
  let changed = false;
  const parts = [];
  for (const [num, wt, v] of fields) {
    if (wt === 0) {
      let n = v;
      if (typeof v === "number") {
        if (Math.abs(v - nowS) < 400 * DAY) {
          if (v !== nowS) { n = nowS; changed = true; }
        } else if (Math.abs(v - nowMs) < 400 * DAY * 1000) {
          if (v !== nowMs) { n = nowMs; changed = true; }
        }
      }
      parts.push(tagBytes(num, 0), vint(n));
    } else if (wt === 2) {
      let nv = v;
      if (depth < 8 && v.length > 1) {
        try {
          const r = walk(v, nowS, nowMs, depth + 1);
          if (r) { nv = r; changed = true; }
        } catch (_) { /* not a nested message */ }
      }
      parts.push(ld(num, nv));
    } else {
      parts.push(tagBytes(num, wt), v);
    }
  }
  return changed ? concat(parts) : null;
}

export function retime(buf, nowSec) {
  const nowS = Math.floor(nowSec);
  try {
    return walk(buf, nowS, nowS * 1000, 0) ?? buf;
  } catch (_) {
    return buf;
  }
}
