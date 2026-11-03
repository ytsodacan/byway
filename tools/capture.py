"""mitmproxy addon: record how the Waze app talks to *.waze.com.

Run:   mitmdump -s capture.py
Output: ~/waze_capture/flows.jsonl  (one JSON record per event)
        ~/waze_capture/<timestamp>_<kind>_<hash>.bin  (raw bodies / messages)

Records HTTP request+response, raw TCP messages, WebSocket messages, and TLS
handshake failures (a failure right after the app connects usually means the
app pins certificates).
"""
import hashlib
import json
import os
import pathlib
import time

from mitmproxy import http, tcp, tls

OUT = pathlib.Path(os.environ.get("WAZE_CAPTURE_DIR") or pathlib.Path.home() / "waze_capture")
OUT.mkdir(parents=True, exist_ok=True)
LOG = OUT / "flows.jsonl"
MAX_SAVE = 2 * 1024 * 1024  # don't store bodies bigger than this


def _log(rec):
    rec["t"] = round(time.time(), 3)
    with LOG.open("a") as f:
        f.write(json.dumps(rec) + "\n")


def _save(kind, data):
    if not data or len(data) > MAX_SAVE:
        return None
    name = f"{int(time.time() * 1000)}_{kind}_{hashlib.sha1(data).hexdigest()[:8]}.bin"
    (OUT / name).write_bytes(data)
    return name


def _is_waze(host):
    return bool(host) and "waze" in host


def response(flow: http.HTTPFlow):
    host = flow.request.pretty_host
    if not _is_waze(host):
        return
    ctype = flow.response.headers.get("content-type", "")
    is_image = ctype.startswith("image/")
    _log({
        "ev": "http",
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "status": flow.response.status_code,
        "req_headers": dict(flow.request.headers),
        "res_headers": dict(flow.response.headers),
        "req_body": _save("req", flow.request.raw_content),
        "res_body": None if is_image else _save("res", flow.response.raw_content),
        "res_size": len(flow.response.raw_content or b""),
    })


def tcp_message(flow: tcp.TCPFlow):
    m = flow.messages[-1]
    host = flow.server_conn.sni or (flow.server_conn.address or ("",))[0]
    if not _is_waze(str(host)):
        return
    _log({
        "ev": "tcp",
        "host": host,
        "dir": "c2s" if m.from_client else "s2c",
        "size": len(m.content),
        "body": _save("tcp_" + ("c2s" if m.from_client else "s2c"), m.content),
    })


def websocket_message(flow: http.HTTPFlow):
    if not _is_waze(flow.request.pretty_host):
        return
    m = flow.websocket.messages[-1]
    _log({
        "ev": "ws",
        "url": flow.request.pretty_url,
        "dir": "c2s" if m.from_client else "s2c",
        "is_text": m.is_text,
        "size": len(m.content),
        "body": _save("ws_" + ("c2s" if m.from_client else "s2c"), m.content),
    })


def tls_failed_client(data: tls.TlsData):
    _log({
        "ev": "tls_failed_client",
        "sni": data.conn.sni,
        "error": str(data.conn.error),
    })
