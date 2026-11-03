#!/usr/bin/env python3
"""Private Waze realtime server, stage 3: thin local relay.

All the logic (login, command replies, world/wazers, marketplace, the custom
gallery card) now lives in a Cloudflare Worker. This mitmproxy addon only
terminates TLS for *.waze.com (via your trusted proxy cert) and forwards the
relevant requests to the Worker, returning whatever it says. Everything the
Worker doesn't claim passes through to real Waze, same as before.

    export PSERVER_WORKER_URL=https://waze-private-server.<you>.workers.dev
    mitmdump -s ~/Downloads/pserver_relay.py
"""
import asyncio
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

try:
    from mitmproxy import http
except ImportError:  # allows `python3 pserver_relay.py` for a quick syntax/self-check
    http = None

WORKER = os.environ.get("PSERVER_WORKER_URL", "").rstrip("/")
RELAY_KEY = os.environ.get("PSERVER_RELAY_KEY", "")
# never route the Worker call through the system proxy (that may be mitmproxy itself -> loop)
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
DROP_HEADERS = {"content-length", "content-encoding", "transfer-encoding", "connection"}


def log(msg):
    print(f"[relay] {msg}", file=sys.stderr, flush=True)


def call_worker(path, body=b"", headers=None, method="POST", timeout=8):
    """-> (status, body bytes, headers dict with LOWERCASE keys) or None if unreachable."""
    h = {"Content-Type": "application/octet-stream",
         "User-Agent": "pserver-relay/1.0",  # Cloudflare blocks the default Python-urllib UA
         "X-Relay-Key": RELAY_KEY}
    h.update(headers or {})
    req = urllib.request.Request(WORKER + path, data=(body or None) if method == "POST" else None,
                                 method=method, headers=h)
    try:
        with OPENER.open(req, timeout=timeout) as r:
            return r.status, r.read(), {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}
    except Exception as ex:
        log(f"worker call failed: {type(ex).__name__}: {ex}")
        return None


async def acall(*a, **kw):
    """call_worker off the event loop so a slow Worker doesn't stall every other flow."""
    return await asyncio.get_running_loop().run_in_executor(None, lambda: call_worker(*a, **kw))


async def request(flow):
    if http is None or "waze" not in flow.request.pretty_host:
        return
    if not WORKER or not RELAY_KEY:
        log("PSERVER_WORKER_URL / PSERVER_RELAY_KEY not set; everything passes through to real Waze")
        return

    path = flow.request.path.split("?")[0]
    url = flow.request.pretty_url

    # the detail page for a gallery card: let the Worker fully own ids it recognizes as its own
    if path.startswith("/webviews/copilot-marketplace/api/theme-campaign/"):
        cid = path.rstrip("/").rsplit("/", 1)[-1]
        res = await acall(f"/gallery/theme-campaign/{urllib.parse.quote(cid)}", method="GET")
        if res and res[0] == 200:
            flow.response = http.Response.make(200, res[1], {"Content-Type": "application/json"})
            log(f"theme-campaign: Worker answered {cid!r}")
            return
        # not one of ours (404 from the Worker) -> fall through, real Waze answers as usual

    # our own served images for the custom gallery card / custom cars
    if path.startswith("/private/"):
        name = urllib.parse.unquote(os.path.basename(path))
        res = await acall(f"/private/{urllib.parse.quote(name)}", method="GET")
        if res and res[0] == 200:
            ctype = res[2].get("content-type", "application/octet-stream")
            flow.response = http.Response.make(200, res[1], {"Content-Type": ctype, "Cache-Control": "no-cache"})
        else:
            flow.response = http.Response.make(404, b"", {})
            log(f"private file not found via Worker: {name}")
        return

    # the marketplace gallery JSON itself: ask for a full copy (no 304), patch it after the real fetch (see response())
    if flow.request.pretty_host == "www.waze.com" and (
        path.startswith("/webviews/copilot-marketplace/api/") or path.startswith("/api/config/CopilotWeb")
    ):
        for h in ("If-None-Match", "If-Modified-Since"):
            flow.request.headers.pop(h, None)
        flow.metadata["pserver_web"] = True
        return  # let it reach real Waze; response() below patches the result

    kind = (
        "login" if "rtserver/distrib/login" in url else
        "command" if "rtserver/distrib/command" in url else
        "static" if "rtserver/distrib/static" in url else None
    )
    if kind is None:
        return  # everything else (tiles, tts assets, inbox, ads, ...): untouched, real Waze answers

    body = flow.request.content or b""
    res = await acall(f"/rtserver/{kind}", body=body)
    if res is None:
        flow.response = http.Response.make(502, b"worker unreachable", {})
        log(f"{kind}: Worker unreachable, returned 502 to the app")
        return
    status, rbody, rheaders = res
    if rheaders.get("x-pserver-passthrough") == "1":
        log(f"{kind}: Worker says pass through to real Waze (e.g. geo-server discovery)")
        return  # flow.response stays None -> mitmproxy forwards to real Waze
    if status == 403:
        log("Worker returned 403: PSERVER_RELAY_KEY doesn't match the Worker's RELAY_KEY secret")
    if kind == "command":
        log(f"command sig={urllib.parse.unquote(rheaders.get('x-pserver-sig', '?'))} matched={rheaders.get('x-pserver-matched')}")
    hdr = {k: v for k, v in rheaders.items()
           if k not in DROP_HEADERS and not k.startswith("x-pserver-") and not k.startswith("cf-")
           and k not in ("server", "date", "report-to", "nel", "alt-svc")}
    flow.response = http.Response.make(status, rbody, hdr)
    log(f"{kind}: Worker answered, {len(rbody)} bytes")


async def response(flow):
    """Run the real gallery reply through the Worker's patch endpoint before the app sees it."""
    if http is None or not flow.metadata.get("pserver_web") or flow.response is None \
            or flow.response.status_code != 200 or not WORKER:
        return
    path = flow.request.path.split("?")[0]
    if not path.endswith("/webviews/copilot-marketplace/api/gallery"):
        return
    raw = flow.response.content or b""
    if not raw:
        return
    res = await acall("/gallery/patch", body=raw, headers={"Content-Type": "application/json"})
    if res and res[0] == 200 and res[1]:
        flow.response.content = res[1]
        log("gallery: patched via Worker")
    else:
        log("gallery: Worker patch failed or unreachable; left unmodified")


if __name__ == "__main__":
    print(__doc__)
