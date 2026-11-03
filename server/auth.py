#!/usr/bin/env python3
"""Accounts and sessions for the private Waze server (stage 2: real authentication).

    python3 auth.py add NAME        create an account (asks for a password, twice)
    python3 auth.py list | passwd NAME | remove NAME | selftest

Passwords are never stored or logged: only a per-user random salt and an scrypt
hash. Sessions are random, expire, and compare in constant time. Five wrong
passwords for one name locks it for 10 minutes. Files are chmod 600.
Use a throwaway password here, never your real Waze one.
"""
import argparse
import base64
import collections
import getpass
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import sys
import threading
import time

DIR = pathlib.Path.home() / "waze_private"
USERS, SESSIONS = DIR / "users.json", DIR / "sessions.json"
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MAX_FAILS, WINDOW, TTL = 5, 600, 30 * 86400
FIRST_UID = 1_900_000_000         # 10 digits like real ids (login global_user_id is 19 chars); the 19 prefix keeps them apart from real ones
_lock = threading.Lock()
_fails = collections.defaultdict(list)


def _load(p):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def _save(p, obj):
    DIR.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(p)


def _kdf(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def add_user(name, pw):
    if not NAME_RE.match(name):
        raise ValueError("name must be 3-32 letters, digits, _ . -")
    if len(pw) < 8:
        raise ValueError("password must be at least 8 characters")
    with _lock:
        users = _load(USERS)
        if name.lower() in {k.lower() for k in users}:
            raise ValueError("that name is taken")
        salt = os.urandom(16)
        uid = max([u["uid"] for u in users.values()] + [FIRST_UID - 1]) + 1
        users[name] = {"uid": uid, "salt": salt.hex(), "hash": _kdf(pw, salt).hex(), "created": int(time.time())}
        _save(USERS, users)
    return uid


def get_user(name):
    return _load(USERS).get(name)


def set_field(name, key, val):
    with _lock:
        users = _load(USERS)
        if name in users:
            users[name][key] = val
            _save(USERS, users)


def by_session(session_id):
    """Account that owns this session id (the app sends it in the `uid` header on every command)."""
    s = _load(SESSIONS).get(str(session_id))
    if not s or s["exp"] <= time.time():
        return None
    return {"name": s["name"], "uid": s["uid"]}


def update_user(name, new_name=None, new_pw=None, email=None):
    """Signup from a guest: rename and/or set password/email. Raises ValueError with a readable reason."""
    with _lock:
        users = _load(USERS)
        u = users.get(name)
        if u is None:
            raise ValueError("no such account")
        if new_name and new_name != name:
            if not NAME_RE.match(new_name):
                raise ValueError("name must be 3-32 letters, digits, _ . -")
            if new_name.lower() in {k.lower() for k in users}:
                raise ValueError("that name is taken")
            users[new_name] = users.pop(name)
            sess = _load(SESSIONS)
            for v in sess.values():
                if v["name"] == name:
                    v["name"] = new_name
            _save(SESSIONS, sess)
            u = users[new_name]
        if new_pw:
            if len(new_pw) < 8:
                raise ValueError("password must be at least 8 characters")
            salt = os.urandom(16)
            u.update(salt=salt.hex(), hash=_kdf(new_pw, salt).hex())
        if email:
            u["email"] = email
        _save(USERS, users)


def verify(name, pw, now=None):
    """-> user dict (with 'name') or None. Same work for unknown names, so timing doesn't reveal them."""
    now = now or time.time()
    with _lock:
        _fails[name] = [t for t in _fails[name] if now - t < WINDOW]
        locked = len(_fails[name]) >= MAX_FAILS
        u = _load(USERS).get(name)
    salt = bytes.fromhex(u["salt"]) if u else b"\0" * 16
    got = _kdf(pw, salt)
    ok = bool(u) and hmac.compare_digest(got, bytes.fromhex(u["hash"])) and not locked
    if not ok:
        with _lock:
            _fails[name].append(now)
        return None
    with _lock:
        _fails.pop(name, None)
    return {"name": name, "uid": u["uid"]}


def new_session(user, now=None):
    """-> {'session_id': int, 'cookie': str, 'uid': int}. Old sessions for this user are dropped."""
    now = now or time.time()
    with _lock:
        s = {k: v for k, v in _load(SESSIONS).items() if v["exp"] > now and v["name"] != user["name"]}
        sid = secrets.randbelow(900_000_000) + 100_000_000
        cookie = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode()
        s[str(sid)] = {"name": user["name"], "uid": user["uid"], "cookie": cookie, "exp": now + TTL}
        _save(SESSIONS, s)
    return {"session_id": sid, "cookie": cookie, "uid": user["uid"]}


def check_session(session_id, cookie, now=None):
    now = now or time.time()
    s = _load(SESSIONS).get(str(session_id))
    if not s or s["exp"] <= now or not hmac.compare_digest(s["cookie"].encode(), str(cookie).encode()):
        return None
    return {"name": s["name"], "uid": s["uid"]}


def waze_user_id(uid):
    return f"1|global|{uid}"          # the shape the real login_response used


def selftest():
    global DIR, USERS, SESSIONS
    import tempfile
    DIR = pathlib.Path(tempfile.mkdtemp())
    USERS, SESSIONS = DIR / "users.json", DIR / "sessions.json"
    assert add_user("alice", "correct horse") == FIRST_UID
    for bad in (("al", "correct horse"), ("bob", "short"), ("ALICE", "correct horse")):
        try:
            add_user(*bad)
            raise SystemExit(f"accepted {bad}")
        except ValueError:
            pass
    assert "correct horse" not in USERS.read_text()
    assert verify("alice", "correct horse")["uid"] == FIRST_UID
    assert verify("alice", "wrong") is None and verify("nobody", "x") is None
    for _ in range(5):
        verify("alice", "wrong")
    assert verify("alice", "correct horse") is None, "should be locked out"
    assert verify("alice", "correct horse", now=time.time() + WINDOW + 1) is not None, "lockout should expire"
    u = {"name": "alice", "uid": FIRST_UID}
    s = new_session(u)
    assert check_session(s["session_id"], s["cookie"]) == u
    assert check_session(s["session_id"], "x") is None
    assert check_session(s["session_id"], s["cookie"], now=time.time() + TTL + 1) is None
    s2 = new_session(u)
    assert check_session(s["session_id"], s["cookie"]) is None, "old session should be revoked"
    assert oct(os.stat(USERS).st_mode)[-3:] == "600"
    print("auth selftest OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["add", "list", "passwd", "remove", "selftest"])
    ap.add_argument("name", nargs="?")
    a = ap.parse_args()
    if a.cmd == "selftest":
        return selftest()
    if a.cmd == "list":
        for n, u in _load(USERS).items():
            print(f"{n}  uid={u['uid']}  created={time.strftime('%Y-%m-%d', time.localtime(u['created']))}")
        return
    if not a.name:
        sys.exit("give a name")
    if a.cmd == "remove":
        with _lock:
            users = _load(USERS)
            if users.pop(a.name, None) is None:
                sys.exit("no such user")
            _save(USERS, users)
        return print("removed")
    pw = getpass.getpass("password: ")
    if pw != getpass.getpass("again: "):
        sys.exit("passwords differ")
    if a.cmd == "passwd":
        with _lock:
            users = _load(USERS)
            if a.name not in users:
                sys.exit("no such user")
            salt = os.urandom(16)
            users[a.name].update(salt=salt.hex(), hash=_kdf(pw, salt).hex())
            _save(USERS, users)
        return print("password changed")
    try:
        print(f"created {a.name} uid={add_user(a.name, pw)}")
    except ValueError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
