# Byway

A private, multiplayer Waze realtime server for experimenting with the app's protocol. One Python
process (a mitmproxy addon) terminates TLS for `*.waze.com`, answers the realtime endpoints
(`rtserver/distrib/login|command|static`) itself, and serves an admin dashboard.

## Features
- **Networked**: every signed-in player appears live on every other player's map (name, mood,
  position), and everyone sees each other's reports. Presence expires 90 s after the last update.
- **Accounts**: "Get started" guest accounts, named logins (scrypt-hashed, lock-out after 5 bad
  tries), sign-up / rename / password change from inside the app, bans, per-account points/mood.
- **Reporting**: police, traffic, crashes, hazards, weather, closures, cameras, animals... stored
  for 3 h, shown on the map, thumbs-up counted, points awarded.
- **Synthetic world**: generate wazers and alerts around any coordinate, capped per reply so the app
  loads quickly.
- **Robust**: every command in the schema gets a valid reply (fuzz-tested), malformed or unknown
  requests get an empty valid batch, never an error. Unknown requests are saved for analysis.
- **Dashboard** (`:8081`): live stats and traffic, map with click-to-report, accounts, reports,
  world generator, logs.

## Run on your Mac
```
cd server
~/pserver-venv/bin/pip install -r requirements.txt   # once
./start.sh                                           # sets the Mac's web proxy, resets it on Ctrl-C
```
Dashboard: http://127.0.0.1:8081 (password in `~/waze_private/dashboard_password`).

## Host it (Docker)
```
cd server
mkdir -p data/capture data/protos data/private       # then copy your capture and schema in (Data, below)
BYWAY_PROXYAUTH=me:long-random-secret BYWAY_DASH_PASSWORD=another-secret docker compose up -d
```
On each phone: Wi-Fi proxy -> `host:8080` (with that user/password), open `http://mitm.it` through
it, install and trust the certificate. The proxy is real: never expose 8080 without
`BYWAY_PROXYAUTH`, and put the dashboard behind your own firewall or reverse proxy with TLS.

## Data (not in the repo)
- `capture/flows.jsonl` and body files: your own mitmproxy capture of the app (`tools/capture.py`,
  `tools/startcap.sh`). Replies are templated from it, and it holds your account data: keep it private.
- `protos/descriptors.desc`: protobuf schema extracted from the app (`tools/extract_protos.py`).
- `private/`: created on first run (users, sessions, reports, world, log).
- Everything lives under `BYWAY_HOME` (default `~/waze_capture`, `~/waze_protos`, `~/waze_private`).

## Layout
`server/` the server and dashboard · `tools/` capture, schema extraction and a schema browser
(`msgdef.py`) · README.

## Limits
Map tiles, routing and search come from Waze's own servers and are passed through. Anything the
capture has never seen gets an empty or default reply: look at the dashboard's Logs tab.
