// Move any timestamp-looking varint (seconds or ms, within ~400 days of now)
// to now. Port of pserver.py's retime(), minus the schema narrowing (the
// Python version only retimes fields the descriptor says are int-typed;
// this version retimes any varint field that fits the window — slightly
// more aggressive, but matches the same heuristic pserver.py already
// leans on for everything it can't name).
import { parseWire, tagBytes, vint, ld, concat } from "./wire.js";

const DAY = 86400;

export function retime(buf, nowSec, depth = 0) {
  const parts = [];
  for (const [num, wt, v] of parseWire(buf)) {
    if (wt === 0) {
      let n = v; // BigInt
      const asNum = Number(n);
      if (Math.abs(asNum - nowSec) < 400 * DAY) {
        n = BigInt(Math.floor(nowSec));
      } else if (Math.abs(asNum - nowSec * 1000) < 400 * DAY * 1000) {
        n = BigInt(Math.floor(nowSec * 1000));
      }
      parts.push(concat([tagBytes(num, 0), vint(n)]));
    } else if (wt === 2 && depth < 8) {
      let nv = v;
      try {
        nv = retime(v, nowSec, depth + 1);
      } catch (_) {
        /* not a nested message we can parse: leave untouched */
      }
      parts.push(ld(num, nv));
    } else {
      parts.push(concat([tagBytes(num, wt), v]));
    }
  }
  return concat(parts);
}
