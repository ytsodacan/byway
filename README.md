# Waze private server — Cloudflare Worker edition

Your Mac still runs mitmproxy (`pserver_relay.py`) to terminate TLS for `*.waze.com`
with your trusted proxy cert (Cloudflare can't issue certs for a domain it doesn't own).
Everything else (login/command replies, world data, the custom gallery card) lives in the Worker.

## 1. Deploy the Worker
```
npm install -g wrangler
cd waze-worker
wrangler login
wrangler kv namespace create CONFIG
wrangler kv namespace create TEMPLATES     # paste both ids into wrangler.toml
openssl rand -hex 32                        # your relay key; keep it
wrangler secret put RELAY_KEY               # paste the key
wrangler deploy
```
The Worker refuses every request (403) unless `X-Relay-Key` matches `RELAY_KEY`, and refuses
all traffic (503) if the secret isn't set. It holds a captured login/session, so it must not
be publicly readable.

## 2. Export your capture
```
cp /path/to/waze-worker/export_templates.py .      # next to pserver.py / decode.py / auth.py
~/pserver-venv/bin/python export_templates.py
wrangler kv bulk put --binding=TEMPLATES templates_bulk.json
```
Command keys are now `cmd:<sha1 of signature>` (KV keys max 512 bytes). Re-run the export
after updating the Worker — old `cmd:<raw signature>` entries are not read any more.

## 3. Upload the card image
```
wrangler kv key put --binding=CONFIG "file:red.png" --path=/Users/sebass/waze_private/files/red.png
wrangler kv key put --binding=CONFIG "file-type:red.png" "image/png"
```

## 4. Run the relay
```
export PSERVER_WORKER_URL=https://waze-private-server.<you>.workers.dev
export PSERVER_RELAY_KEY=<same key as above>
mitmdump -s ~/Downloads/pserver_relay.py
```
For `command` calls the relay log now shows the signature and whether a template matched
(`matched=0` means the fallback reply was used — those are the signatures worth capturing).

## What changed in this pass
- **Worker auth** (`RELAY_KEY`), previously anyone with the URL could download your captured login.
- **Header bug**: captured `content-type` plus the default `Content-Type` were both emitted,
  producing a combined/invalid value. Now a single case-insensitive `Headers` object.
- **Relay header case bug**: it looked up `X-Pserver-Passthrough` case-sensitively, so geo
  discovery passthrough could silently fail. Keys are lowercased now.
- **Relay**: sends a real User-Agent (Cloudflare blocks `Python-urllib`), bypasses system
  proxy env (no loop through mitmproxy itself), and Worker calls are async so a slow Worker
  doesn't stall other flows.
- **`parseWire`** threw nothing on truncated fields and silently clipped them, so `retime()`
  could re-encode random strings as shortened "messages". It now throws, and `retime()` only
  rebuilds a message when a timestamp inside actually changed (everything else is byte-identical).
- Varints use Numbers instead of BigInt on the fast path (BigInt only for >2^53, e.g. negatives).

## Known limits
- **CPU budget**: retiming a very large world reply is CPU-heavy (~160 ms for 80k varints in
  my test). The free Workers plan allows ~10 ms CPU per request; if big `command` replies fail
  with error 1102, use the Workers Paid plan or precompute timestamp offsets at export time.
- Guests aren't minted fresh (one captured register reply is replayed); no live wazer filtering;
  login credentials aren't checked. Closing these needs the field-number map from your
  `descriptors.desc` (see the list of names in the previous README: `register_successful`,
  `client_auth_token`, `username`, `password`, `token`, `user_id`, `add_wazer`, `gps_sample`,
  `position`, `lon_times_1000000`, `lat_times_1000000`, `login_error`, `error_type`).
