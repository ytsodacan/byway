# Byway

A private Waze realtime server for experimenting with the app's protocol. One Python process (a
mitmproxy addon, `server/pserver.py`) terminates TLS for `*.waze.com`, answers the realtime
endpoints (`rtserver/distrib/login|command|static`) itself, and passes everything else through.

## What it does
- **Accounts**: guest "Get started" accounts, named logins (scrypt-hashed), sign-up/rename/password
  change from inside the app, per-user session ids and mood.
- **Reporting**: police, traffic, crashes, hazards, weather, closures, cameras, etc. are stored
  (`reports.json`, 3 h lifetime), shown to everyone on the map, thumbs-up counted, points awarded.
- **World**: synthetic wazers/alerts from `world.json`, filtered to the visible map, nearest first
  and capped (`PSERVER_MAX_WAZERS`, `PSERVER_MAX_ALERTS`) so replies stay small.
- **Robustness**: every command number in the schema gets a valid reply (fuzz-tested), malformed
  or unknown requests get an empty valid batch instead of an error, unknown `rtserver` paths are
  answered locally. Set `PSERVER_PASSTHROUGH=1` to forward unknown ones to real Waze instead.
- Exclusive/editor mood level and custom cars/moods: see `server/pserver.py --add-mood`.

## Run on your Mac
```
cd server && ./start.sh          # sets the Mac's web proxy, turns it off again on Ctrl-C
```

## Host it (Docker)
```
cd server
mkdir -p data/capture data/protos data/private
# copy your own capture and schema in (see Data), then:
BYWAY_PROXYAUTH=me:a-long-random-secret docker compose up -d
```
On the phone: set the Wi-Fi HTTP proxy to `host:8080` (with that user/password), open
`http://mitm.it` through it and install + trust the mitmproxy certificate. Don't expose the port
without `BYWAY_PROXYAUTH`: it is a real proxy.

## Data (not in this repo)
- `capture/flows.jsonl` + body files: your own mitmproxy capture of the app (`capture.py`,
  `startcap.sh`). Replies are templated from it. It contains your account data: keep it private.
- `protos/descriptors.desc`: protobuf schema extracted from the app (`extract_protos.py`).
- `private/`: created on first run (users, sessions, reports, world, logs).

## Limits
Map tiles, routing and search come from Waze's own CDN/servers and are passed through. Real
accounts, push notifications and anything the capture has never seen are answered with empty or
default replies. Check `private/pserver.log` and `private/unseen/` to see what the app asked for.
