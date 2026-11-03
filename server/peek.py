#!/usr/bin/env python3
"""Summarise what capture.py recorded in ~/waze_capture.

    python3 peek.py                      # per-endpoint counts + first login/command flows
    python3 peek.py rtserver/distrib/command -n 5   # first 5 flows whose URL contains the text

Cookies, auth headers and session/token query params are masked. Request and
response BODIES are shown as-is (truncated) and a login body may contain
credentials, so read it before you paste it anywhere.
"""
import argparse
import collections
import gzip
import json
import pathlib
import re
import sys
from urllib.parse import urlsplit

CAP = pathlib.Path.home() / "waze_capture"
SENSITIVE_HEADERS = {"cookie", "set-cookie", "authorization", "x-api-key", "proxy-authorization"}
SENSITIVE_Q = re.compile(r"((?:sessionid|session|cookie|token|pass\w*|secret|key|auth\w*)=)[^&\s]+", re.I)


def mask_url(u):
    return SENSITIVE_Q.sub(r"\1<redacted>", u)


def mask_headers(h):
    return {k: ("<redacted>" if k.lower() in SENSITIVE_HEADERS else v) for k, v in (h or {}).items()}


def body_info(name, limit=500):
    if not name:
        return "(no body)"
    p = CAP / name
    if not p.exists():
        return f"(missing {name})"
    b = p.read_bytes()
    notes = [f"{len(b)} bytes"]
    if b[:2] == b"\x1f\x8b":
        try:
            b = gzip.decompress(b)
            notes.append(f"gzip -> {len(b)} bytes")
        except Exception:
            notes.append("gzip header but bad stream")
    try:
        text = b.decode("utf-8")
        printable = sum(c.isprintable() or c in "\r\n\t" for c in text) / max(len(text), 1)
        if printable > 0.95:
            kind = "json" if text.lstrip()[:1] in "{[" else "text"
            return f"[{kind}, {', '.join(notes)}] " + repr(text[:limit])
    except UnicodeDecodeError:
        pass
    ascii_view = "".join(chr(c) if 32 <= c < 127 else "." for c in b[:96])
    return f"[binary, {', '.join(notes)}] hex={b[:48].hex()}  ascii={ascii_view}"


def load():
    f = CAP / "flows.jsonl"
    if not f.exists():
        sys.exit(f"{f} not found - run capture.py first")
    return [json.loads(l) for l in f.read_text().splitlines() if l.strip()]


def show(r):
    print("=" * 78)
    print(f"{r.get('method')} {mask_url(r.get('url', ''))}  ->  {r.get('status')}")
    print("req headers:", json.dumps(mask_headers(r.get("req_headers")), indent=1))
    print("res headers:", json.dumps(mask_headers(r.get("res_headers")), indent=1))
    print("REQUEST :", body_info(r.get("req_body")))
    print("RESPONSE:", body_info(r.get("res_body")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("match", nargs="?", help="only flows whose URL contains this")
    ap.add_argument("-n", type=int, default=2)
    a = ap.parse_args()

    flows = [r for r in load() if r.get("ev") == "http"]
    if a.match:
        for r in [r for r in flows if a.match in r["url"]][: a.n]:
            show(r)
        return

    counts = collections.Counter()
    for r in flows:
        u = urlsplit(r["url"])
        counts[f"{r['method']} {u.netloc}{u.path}"] += 1
    print(f"{len(flows)} http flows to waze hosts\n")
    for k, v in counts.most_common(25):
        print(f"{v:5d}  {k}")
    print()
    for key, n in (("rtserver/distrib/login", 1), ("rtserver/distrib/command", 2)):
        for r in [r for r in flows if key in r["url"]][:n]:
            show(r)


if __name__ == "__main__":
    main()
