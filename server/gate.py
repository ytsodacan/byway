#!/usr/bin/env python3
"""Edge authentication for the private Waze server (custom auth, no Waze sign-in involved).

Every client of the proxy must present an account from auth.py (HTTP proxy
authentication, "Basic"). Nothing is answered or forwarded until it does, so the
proxy is not an open proxy and the private world is only served to your accounts.

    python3 gate.py selftest

How it works
  * The device's proxy settings carry a username and password.
  * The proxy replies 407 until a connection presents valid credentials, then
    remembers that connection (not the password) until it closes.
  * The Proxy-Authorization header is removed so it is never forwarded or saved.

Limits worth knowing: Basic auth sends the password unencrypted between the device
and the proxy. On 127.0.0.1 that is fine; across your Wi-Fi it can be read by
anyone on that network, so use a throwaway password made just for this.
"""
import base64
import binascii
import sys
import time

import auth

try:
    from mitmproxy import http
except ImportError:                  # selftest works without mitmproxy
    http = None

REALM = 'Basic realm="waze-private"'
MAX_NAME = 64
_authed = {}                         # client connection id -> account name
_warned = set()


def log(msg):
    print(f"[pserver] {msg}", file=sys.stderr, flush=True)
    try:
        auth.DIR.mkdir(parents=True, exist_ok=True)
        with (auth.DIR / "pserver.log").open("a") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except OSError:
        pass


def parse_basic(value):
    """'Basic base64(name:password)' -> (name, password) or None."""
    if not value:
        return None
    scheme, _, rest = value.strip().partition(" ")
    if scheme.lower() != "basic":
        return None
    try:
        raw = base64.b64decode(rest.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    name, sep, pw = raw.partition(":")          # passwords may contain ':'
    if not sep or not name or len(name) > MAX_NAME:
        return None
    return name, pw


def check(flow):
    """True if this flow's client connection is authenticated. Never logs a password."""
    cid = flow.client_conn.id
    hdr = flow.request.headers.get("Proxy-Authorization")
    if hdr is None:
        name = _authed.get(cid)
        if name:
            flow.metadata["waze_user"] = name
        return bool(name)
    flow.request.headers.pop("Proxy-Authorization", None)     # never forward or store it
    creds = parse_basic(hdr)
    user = auth.verify(*creds) if creds else None
    if user is None:
        _authed.pop(cid, None)
        who = repr(creds[0][:MAX_NAME]) if creds else "(unreadable)"
        peer = (flow.client_conn.peername or ("?",))[0]
        log(f"AUTH FAILED for {who} from {peer}")
        if not auth._load(auth.USERS) and "none" not in _warned:
            _warned.add("none")
            log("no accounts exist yet: run  python3 auth.py add NAME")
        return False
    _authed[cid] = user["name"]
    flow.metadata["waze_user"] = user["name"]
    return True


def deny(flow):
    flow.response = http.Response.make(
        407, b"proxy authentication required",
        {"Proxy-Authenticate": REALM, "Content-Type": "text/plain"})


def forget(client):
    _authed.pop(client.id, None)


# ---------- self test (no mitmproxy needed) ----------

def selftest():
    import tempfile
    import pathlib
    from types import SimpleNamespace as NS
    d = pathlib.Path(tempfile.mkdtemp())
    auth.DIR, auth.USERS, auth.SESSIONS = d, d / "users.json", d / "sessions.json"
    auth.add_user("alice", "correct horse")

    def flow(cid, header=None):
        h = {} if header is None else {"Proxy-Authorization": header}
        return NS(client_conn=NS(id=cid, peername=("10.0.0.2", 1)), metadata={},
                  request=NS(headers=dict(h)))

    enc = lambda s: "Basic " + base64.b64encode(s.encode()).decode()
    assert parse_basic(enc("a:b:c")) == ("a", "b:c")
    for bad in (None, "", "Bearer x", "Basic !!!", "Basic " + base64.b64encode(b"nocolon").decode(),
                enc(":pw"), enc("x" * 65 + ":pw")):
        assert parse_basic(bad) is None, bad
    assert not check(flow("c1")), "no credentials must be refused"
    assert not check(flow("c1", enc("alice:wrong")))
    assert not check(flow("c1", enc("nobody:x")))
    f = flow("c1", enc("alice:correct horse"))
    assert check(f) and f.metadata["waze_user"] == "alice"
    assert "Proxy-Authorization" not in f.request.headers, "header must be stripped"
    assert check(flow("c1")), "same connection stays authenticated"
    assert not check(flow("c2")), "other connections are not"
    assert not check(flow("c1", enc("alice:wrong"))) and not check(flow("c1")), "a bad retry revokes the connection"
    class C:
        id = "c1"
    check(flow("c1", enc("alice:correct horse")))
    forget(C)
    assert not check(flow("c1")), "disconnect must forget"
    print("gate selftest OK")


if __name__ == "__main__":
    if sys.argv[1:] == ["selftest"]:
        selftest()
    else:
        print(__doc__)
