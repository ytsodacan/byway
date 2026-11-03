#!/usr/bin/env python3
"""Export pserver.py's capture templates (login, static/register, command
signatures, geo-server discovery) into a file wrangler can bulk-upload into
the Worker's TEMPLATES KV namespace.

Run this from the same ~/Downloads folder as pserver.py/decode.py/auth.py,
with the same WAZE_CAPTURE_DIR env var (if any) you normally use:

    ~/pserver-venv/bin/python export_templates.py
    wrangler kv bulk put --binding=TEMPLATES templates_bulk.json

Note: pserver.py's own loader only reads login/command flows from
flows.jsonl (not "static"/register), since the Python server normally
synthesizes a fresh guest account per run instead of replaying one. The
Worker can't synthesize one (that needs field names from your protobuf
schema, which isn't ported yet — see the project README), so this script
separately scans flows.jsonl for one real captured register reply and
reuses it every time. Fine for a single personal device; every run of the
Worker will log in as the same guest account.
"""
import base64
import hashlib
import json
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pserver  # noqa: E402


def pack(res_bytes, headers, t):
    return {"resBase64": base64.b64encode(res_bytes).decode(), "headers": headers, "t": t}


def find_static_template(cap):
    flows = cap / "flows.jsonl"
    if not flows.exists():
        return None
    for line in flows.read_text().splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("ev") == "http" and r.get("status") == 200 and r.get("res_body") \
                and "rtserver/distrib/static" in r.get("url", ""):
            res = pserver.unz((cap / r["res_body"]).read_bytes())
            return pack(res, r.get("res_headers", {}), r["t"])
    return None


def main():
    srv = pserver.Server()
    out = {}

    if srv.login:
        out["login"] = pack(srv.login["res"], srv.login["headers"], srv.login["t"])
    else:
        print("WARNING: no login template loaded; /rtserver/login will 204-passthrough", file=sys.stderr)

    static_tpl = find_static_template(pserver.CAP)
    if static_tpl:
        out["static"] = static_tpl
    else:
        print("WARNING: no captured register reply found in flows.jsonl; "
              "/rtserver/static will 204-passthrough (the app won't be able to register a guest)", file=sys.stderr)

    if srv.geo:
        out["geo"] = pack(srv.geo["res"], srv.geo.get("headers", {}), srv.geo["t"])

    for sig, rec in srv.cmd.items():
        out["cmd:" + hashlib.sha1(sig.encode()).hexdigest()] = pack(rec["res"], rec["headers"], rec["t"])

    fallback = min((r for r in srv.recs if r["kind"] == "command"), key=lambda r: len(r["res"]), default=None)
    if fallback:
        out["fallback"] = pack(fallback["res"], fallback["headers"], fallback["t"])

    if len(out) > 10000:
        print("WARNING: wrangler kv bulk put accepts at most 10,000 keys per file; split templates_bulk.json", file=sys.stderr)
    bulk = [{"key": k, "value": json.dumps(v)} for k, v in out.items()]
    outfile = pathlib.Path("templates_bulk.json")
    outfile.write_text(json.dumps(bulk))
    print(f"wrote {outfile} ({len(bulk)} entries, {outfile.stat().st_size} bytes)", file=sys.stderr)
    print("upload with:  wrangler kv bulk put --binding=TEMPLATES templates_bulk.json", file=sys.stderr)


if __name__ == "__main__":
    main()
