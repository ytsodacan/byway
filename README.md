# Byway - Waze Private Server

A private server for waze.

## Deploy the Worker
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
all traffic (503) if the secret isn't set.

## Features
- Private server
- Custom Moods
- Custom Cars
