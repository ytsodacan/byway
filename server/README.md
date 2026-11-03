# Waze private server — Cloudflare Worker edition

Architecture: your Mac still runs mitmproxy (`pserver_relay.py`) to terminate
TLS for `*.waze.com` using your trusted proxy cert — that part can't move to
the cloud, since Cloudflare can't issue certs for a domain it doesn't own.
Everything else (login/command replies, world data, the custom gallery card)
now lives in the Worker.

## 1. Deploy the Worker

```
npm install -g wrangler        # if you don't have it
cd waze-worker
wrangler login
wrangler kv namespace create CONFIG
wrangler kv namespace create TEMPLATES
```

Paste the two ids those commands print into `wrangler.toml` (replacing
`REPLACE_ME` twice), then:

```
wrangler deploy
```

Note the `https://waze-private-server.<you>.workers.dev` URL it prints.

## 2. Export your capture into the Worker's templates

From the same folder as your existing `pserver.py`/`decode.py`/`auth.py`:

```
cp /path/to/waze-worker/export_templates.py .
~/pserver-venv/bin/python export_templates.py
wrangler kv bulk put --binding=TEMPLATES templates_bulk.json
```

## 3. Upload the custom-card image

```
wrangler kv key put --binding=CONFIG "file:red.png" --path=/Users/sebass/waze_private/files/red.png
wrangler kv key put --binding=CONFIG "file-type:red.png" "image/png"
```

## 4. Point the relay at the Worker

```
export PSERVER_WORKER_URL=https://waze-private-server.<you>.workers.dev
mitmdump -s ~/Downloads/pserver_relay.py
```

Same `./start.sh` flow as before, just with `pserver_relay.py` instead of
`pserver.py` and that env var set first.

## What's simplified in this v1 (and why)

pserver.py builds a few replies by encoding protobuf fields **by name**
(`register_successful`, synthetic `add_wazer` entries) using your local
`descriptors.desc` schema. That schema isn't in this project, and guessing
field numbers would silently produce a corrupted wire format rather than
fail loudly — not worth the risk. So, for now:

- **Everything else replays real captured bytes**, byte-for-byte, with only
  timestamps patched — the same trick pserver.py already uses for every
  signature it has a template for. This needs no schema at all.
- **Guest accounts aren't freshly minted.** The Worker replays one real
  captured `static` (register) reply every time, so every run logs in as
  the same guest. Fine for a single device; just means no fresh account
  per session like the Python version does.
- **No live wazer/alert position filtering.** The command templates carry
  whatever `add_wazer`/`add_alert_action` entries were in the original
  capture, unfiltered by the app's current map area.
- **Login doesn't check credentials.** `login_creds()`'s field numbers
  (2744 → 1 → {1, 2}) are literal constants already in pserver.py, so this
  one *could* be ported now — it just isn't yet in this pass.

## To fully close the gap

Export a field-number map from your already-working local Schema object —
e.g. a tiny script that calls `srv.codec.field(srv.elem_type, name).number`
for the handful of names pserver.py uses (`register_successful`,
`client_auth_token`, `username`, `password`, `token`, `user_id`,
`add_wazer`, `gps_sample`, `position`, `lon_times_1000000`,
`lat_times_1000000`, `login_error`, `error_type`) and paste me the JSON. I
can then port `Codec.encode`-equivalent named encoding into `wire.js` and
wire up fresh guest registration + live wazer filtering in the Worker, to
reach full parity with pserver.py.
