#!/usr/bin/env python3
"""Byway admin dashboard: a small password-protected web UI + JSON API that runs inside the server process.

    BYWAY_DASH_PASSWORD   password (default: random, written to <private>/dashboard_password and logged once)
    BYWAY_DASH_HOST       bind address (default 127.0.0.1; the Docker image sets 0.0.0.0)
    BYWAY_DASH_PORT       port (default 8081)
"""
import hmac
import json
import mimetypes
import os
import pathlib
import random
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import auth
import pserver as P

HERE = pathlib.Path(__file__).resolve().parent
COOKIE = "byway_dash"
_tokens = {}                                   # token -> expiry
_fails = {}                                    # ip -> [timestamps]

# what the report form / generator can create: label -> (detail field, enum value)
REPORT_KINDS = {
    "Police": ("police", "POLICE_DEFAULT"), "Police (hidden)": ("police", "POLICE_HIDDEN"),
    "Speed camera": ("camera", "CAMERA_DEFAULT"),
    "Traffic: light": ("traffic", "TRAFFIC_LIGHT"), "Traffic: moderate": ("traffic", "TRAFFIC_MODERATE"),
    "Traffic: heavy": ("traffic", "TRAFFIC_HEAVY"), "Traffic: standstill": ("traffic", "TRAFFIC_STANDSTILL"),
    "Crash: minor": ("crash", "CRASH_MINOR"), "Crash: major": ("crash", "CRASH_MAJOR"),
    "Hazard: object": ("hazard_on_road", "HAZARD_OBJECT_ON_ROAD"), "Hazard: pothole": ("hazard_on_road", "HAZARD_POTHOLE"),
    "Hazard: stopped vehicle": ("hazard_on_road", "HAZARD_VEHICLE_STOPPED"), "Hazard: construction": ("hazard_on_road", "HAZARD_CONSTRUCTION"),
    "Hazard: oil": ("hazard_on_road", "HAZARD_OIL"), "Hazard: broken light": ("hazard_on_road", "HAZARD_BROKEN_TRAFFIC_LIGHT"),
    "Weather: flood": ("weather", "WEATHER_FLOOD"), "Weather: fog": ("weather", "WEATHER_FOG"), "Weather: icy": ("weather", "WEATHER_ICY_ROAD"),
    "Lane blocked: left": ("blocked_lane", "BLOCKED_LANE_LEFT"), "Lane blocked: right": ("blocked_lane", "BLOCKED_LANE_RIGHT"),
    "Road closed": ("closure", "CLOSURE_HAZARD"), "Animal on road": ("animal", "ANIMAL_ON_ROAD"),
}


def password():
    env = os.environ.get("BYWAY_DASH_PASSWORD")
    if env:
        return env
    f = P.PRIV / "dashboard_password"
    try:
        return f.read_text().strip()
    except OSError:
        pw = secrets.token_urlsafe(12)
        P.PRIV.mkdir(parents=True, exist_ok=True)
        f.write_text(pw)
        os.chmod(f, 0o600)
        P.log(f"dashboard password generated: {pw}  (saved to {f})")
        return pw


def start(get_srv):
    host = os.environ.get("BYWAY_DASH_HOST", "127.0.0.1")
    port = int(os.environ.get("BYWAY_DASH_PORT", "8081"))
    pw = password()
    ui = (HERE / "dashboard.html").read_bytes()

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        # ----- plumbing -----
        def send(self, code, body, ctype="application/json", extra=None):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def authed(self):
            c = self.headers.get("Cookie", "")
            m = re.search(COOKIE + r"=([\w-]+)", c)
            return bool(m) and _tokens.get(m.group(1), 0) > time.time()

        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return {}

        def handle_any(self, method):
            u = urlparse(self.path)
            path, q = u.path, {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                if path == "/" and method == "GET":
                    return self.send(200, ui, "text/html; charset=utf-8")
                if path == "/api/login" and method == "POST":
                    ip = self.client_address[0]
                    _fails[ip] = [t for t in _fails.get(ip, []) if time.time() - t < 60]
                    if len(_fails[ip]) >= 5:
                        return self.send(429, {"error": "too many attempts, wait a minute"})
                    given = str(self.body().get("password", ""))
                    if not hmac.compare_digest(given.encode(), pw.encode()):
                        _fails[ip].append(time.time())
                        return self.send(401, {"error": "wrong password"})
                    tok = secrets.token_urlsafe(24)
                    _tokens[tok] = time.time() + 12 * 3600
                    return self.send(200, {"ok": True}, extra={"Set-Cookie": f"{COOKIE}={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200"})
                if not path.startswith("/api/"):
                    return self.send(404, b"not found", "text/plain")
                if not self.authed():
                    return self.send(401, {"error": "login required"})
                if method != "GET" and self.headers.get("Origin") and urlparse(self.headers["Origin"]).netloc != self.headers.get("Host"):
                    return self.send(403, {"error": "cross-origin request refused"})
                srv = get_srv()
                data = api(srv, method, path, q, self.body() if method in ("POST", "PUT", "DELETE") else {})
                return self.send(200, data)
            except ValueError as ex:
                return self.send(400, {"error": str(ex)})
            except KeyError as ex:
                return self.send(404, {"error": f"not found: {ex}"})
            except Exception as ex:                                         # never take the server down
                P.log(f"dashboard error {type(ex).__name__}: {ex}")
                return self.send(500, {"error": f"{type(ex).__name__}: {ex}"})

        do_GET = lambda self: self.handle_any("GET")
        do_POST = lambda self: self.handle_any("POST")
        do_DELETE = lambda self: self.handle_any("DELETE")

    httpd = ThreadingHTTPServer((host, port), H)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, name="byway-dashboard", daemon=True).start()
    P.log(f"dashboard on http://{host}:{port}  (password in {P.PRIV / 'dashboard_password'} unless BYWAY_DASH_PASSWORD is set)")


# ---------------------------------------------------------------- API

def _user_row(name, u, srv):
    seen = P.STATS.last_seen.get(name)
    on = getattr(srv, "online", {}).get(u["uid"])
    return {"name": name, "uid": u["uid"], "created": u.get("created"), "points": u.get("points", 500000),
            "mood": u.get("mood", 1), "email": u.get("email", ""), "banned": bool(u.get("banned")),
            "exclusive_moods": u.get("exclusive_moods", "GOLD"), "last_seen": seen,
            "online": bool(on and time.time() - on["t"] < srv.ONLINE_TTL),
            "lon": on["lon"] if on else None, "lat": on["lat"] if on else None}


def make_report(srv, lon, lat, kind, by="Dashboard", created=None):
    detail, ev = REPORT_KINDS[kind]
    rs = srv.reports()
    rid = max([r["alert"]["realtime_alert"]["id"] for r in rs] + [2_000_000]) + 1
    rep = dict(lon=int(lon * 1e6), lat=int(lat * 1e6), az=random.choice([0, 90, 180, 270]), nodes=(0, 0), direction="BOTH",
               detail=detail, enum=(None, ev))
    now = created or time.time()
    uuid = "00000000-0000-4000-9000-%012d" % rid
    rs.append({"alert": srv.report_to_alert(rep, rid, uuid, by, now), "created": now, "reporter": by})
    srv._save_reports(rs)
    return rid


def generate_world(srv, lon, lat, wazers, alerts, radius_km):
    """Replace world.json with synthetic traffic around a point; every alert goes through the same validated encoder."""
    dx = radius_km / (111.32 * max(0.2, abs(__import__("math").cos(__import__("math").radians(lat)))))
    dy = radius_km / 110.57
    pos = lambda: (lon + random.uniform(-dx, dx), lat + random.uniform(-dy, dy))
    ws = []
    for i in range(wazers):
        x, y = pos()
        ws.append({"mode": "DELETE_IF_NOT_UPDATE", "id": {"session_id": 900000 + i},
                   "gps_sample": {"position": {"lon_times_1000000": int(x * 1e6), "lat_times_1000000": int(y * 1e6)},
                                  "azymuth": random.choice([0, 45, 90, 135, 180, 225, 270, 315]),
                                  "speed_millis_per_second": random.choice([0, 4000, 8000, 15000])},
                   "mood": random.randint(0, 11), "addon": "NONE", "rank": random.randint(0, 5),
                   "points": random.randint(100, 20000), "join_date_sec": 1700000000, "capabilities": 7,
                   "can_ping": False, "can_private_message": False})
    kinds = list(REPORT_KINDS)
    weights = [3, 1, 2, 3, 3, 2, 1, 2, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    al = []
    for i in range(alerts):
        x, y = pos()
        detail, ev = REPORT_KINDS[random.choices(kinds, weights[:len(kinds)] + [1] * (len(kinds) - len(weights)))[0]]
        rep = dict(lon=int(x * 1e6), lat=int(y * 1e6), az=random.choice([0, 90, 180, 270]), nodes=(0, 0), direction="BOTH",
                   detail=detail, enum=(None, ev))
        a = srv.report_to_alert(rep, 990001 + i, "00000000-0000-4000-8000-%012d" % (i + 1), f"Wazer_{random.randint(1, 500)}", 0)
        a["_age_sec"] = random.randint(60, 10800)
        a["realtime_alert"]["alert_reporting_info"]["thumbs_up_count"] = random.randint(0, 40)
        al.append(a)
    P.WORLD.parent.mkdir(parents=True, exist_ok=True)
    P.WORLD.write_text(json.dumps({"wazers": ws, "alerts": al}))
    srv._w = None
    return {"wazers": len(ws), "alerts": len(al)}


def api(srv, method, path, q, b):
    parts = path.strip("/").split("/")[1:]
    now = time.time()
    key = (method, parts[0] if len(parts) == 1 else "/".join(parts[:1] + ["*"]) if parts else "")   # collection vs item routes

    if key == ("GET", "overview"):
        w = srv.world()
        users = auth.list_users()
        cur = int(now // 60)
        series = [P.STATS.per_min.get(m, 0) for m in range(cur - 59, cur + 1)]
        online = [n for n, u in users.items() if (o := getattr(srv, "online", {}).get(u["uid"])) and now - o["t"] < srv.ONLINE_TTL]
        return {"uptime": now - P.STATS.start, "requests": P.STATS.total, "errors": P.STATS.errors, "series": series,
                "accounts": len(users), "online": online, "reports": len(srv.reports()),
                "world": {"wazers": len(w.get("wazers", [])), "alerts": len(w.get("alerts", []))},
                "top_commands": P.STATS.cmds.most_common(12), "templates": len(srv.cmd),
                "caps": {"wazers": srv.MAX_WAZERS, "alerts": srv.MAX_ALERTS, "report_ttl": srv.REPORT_TTL}}
    if key == ("GET", "requests"):
        since = float(q.get("since", 0))
        return {"events": [e for e in P.STATS.events if e["t"] > since][-int(q.get("limit", 200)):]}
    if key == ("GET", "logs"):
        return {"lines": list(P.STATS.logs)[-int(q.get("limit", 300)):]}
    if key == ("GET", "kinds"):
        return {"kinds": list(REPORT_KINDS)}

    if key == ("GET", "users"):
        return {"users": [_user_row(n, u, srv) for n, u in auth.list_users().items()]}
    if key == ("POST", "users"):
        uid = auth.add_user(str(b.get("name", "")), str(b.get("password", "")))
        return {"uid": uid}
    if parts[:1] == ["users"] and len(parts) == 2:
        name = parts[1]
        if method == "DELETE":
            auth.remove_user(name)
            return {"ok": True}
        if method == "POST":
            kw = {}
            if "points" in b: kw["points"] = int(b["points"])
            if "mood" in b: kw["mood"] = int(b["mood"])
            if "banned" in b: kw["banned"] = bool(b["banned"])
            if "email" in b: kw["email"] = str(b["email"])
            if b.get("exclusive_moods") in ("NONE", "BRONZE", "SILVER", "GOLD"): kw["exclusive_moods"] = b["exclusive_moods"]
            if kw:
                auth.set_fields(name, **kw)
            if b.get("password"):
                auth.update_user(name, new_pw=str(b["password"]))
            return {"ok": True}

    if key == ("GET", "reports"):
        out = []
        for r in srv.reports():
            ra = r["alert"]["realtime_alert"]; ai = ra["alert_info"]
            out.append({"id": ra["id"], "type": ai["type"], "sub_type": ai["sub_type"], "lon": ai["position"]["lon_times_1000000"] / 1e6,
                        "lat": ai["position"]["lat_times_1000000"] / 1e6, "by": r["reporter"], "created": r["created"],
                        "thumbs": ra["alert_reporting_info"]["thumbs_up_count"], "expires": r["created"] + srv.REPORT_TTL})
        return {"reports": out}
    if key == ("POST", "reports"):
        if b.get("kind") not in REPORT_KINDS:
            raise ValueError("unknown report kind")
        return {"id": make_report(srv, float(b["lon"]), float(b["lat"]), b["kind"])}
    if parts[:1] == ["reports"] and len(parts) == 2 and method == "DELETE":
        if parts[1] == "all":
            srv._save_reports([])
        else:
            srv._save_reports([r for r in srv.reports() if r["alert"]["realtime_alert"]["id"] != int(parts[1])])
        return {"ok": True}

    if key == ("GET", "map"):
        w = srv.world()
        pick = lambda xs, n: random.sample(xs, n) if len(xs) > n else xs
        wz = [(z["gps_sample"]["position"]["lon_times_1000000"] / 1e6, z["gps_sample"]["position"]["lat_times_1000000"] / 1e6)
              for z in pick(w.get("wazers", []), 600)]
        al = [(a["realtime_alert"]["alert_info"]["position"]["lon_times_1000000"] / 1e6,
               a["realtime_alert"]["alert_info"]["position"]["lat_times_1000000"] / 1e6,
               a["realtime_alert"]["alert_info"]["sub_type"]) for a in pick(w.get("alerts", []), 600)]
        pl = [{"name": o["name"], "lon": o["lon"], "lat": o["lat"], "age": now - o["t"]} for o in getattr(srv, "online", {}).values()
              if now - o["t"] < srv.ONLINE_TTL]
        return {"wazers": wz, "alerts": al, "players": pl, "reports": api(srv, "GET", "/api/reports", {}, {})["reports"]}

    if key == ("POST", "world"):
        if parts[1:] == ["clear"]:
            P.WORLD.write_text(json.dumps({"wazers": [], "alerts": []}))
            srv._w = None
            return {"ok": True}
        n = lambda k, d, hi: max(0, min(int(b.get(k, d)), hi))
        return generate_world(srv, float(b["lon"]), float(b["lat"]), n("wazers", 200, 5000), n("alerts", 300, 20000), min(float(b.get("radius", 8)), 100))

    if key == ("POST", "config"):
        if "wazers" in b: srv.MAX_WAZERS = max(0, min(int(b["wazers"]), 2000))
        if "alerts" in b: srv.MAX_ALERTS = max(0, min(int(b["alerts"]), 5000))
        if "report_ttl" in b: srv.REPORT_TTL = max(60, min(int(b["report_ttl"]), 7 * 86400))
        return {"ok": True}

    if key == ("GET", "unseen"):
        out = []
        for f in sorted(P.UNSEEN.glob("*.bin"), reverse=True)[:60] if P.UNSEEN.exists() else []:
            raw = f.read_bytes()
            try:
                shape = srv._describe(P.unz(raw))[:160]
            except Exception:
                shape = f"{len(raw)} bytes"
            out.append({"file": f.name, "size": len(raw), "shape": shape})
        return {"unseen": out}
    raise KeyError(path)
