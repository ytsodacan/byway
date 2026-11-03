#!/bin/sh
# Env: BYWAY_PROXYAUTH=user:pass (set this on any public host), BYWAY_DASH_PASSWORD, BYWAY_PORT (8080), BYWAY_DASH_PORT (8081)
set -e
AUTH=""
[ -n "$BYWAY_PROXYAUTH" ] && AUTH="--proxyauth $BYWAY_PROXYAUTH"
[ -f "$BYWAY_HOME/capture/flows.jsonl" ] || { echo "missing $BYWAY_HOME/capture/flows.jsonl (see README: Data)"; exit 1; }
[ -f "$BYWAY_HOME/protos/descriptors.desc" ] || { echo "missing $BYWAY_HOME/protos/descriptors.desc (see README: Data)"; exit 1; }
exec mitmdump -s /app/pserver.py --listen-host 0.0.0.0 --listen-port "${BYWAY_PORT:-8080}" --allow-hosts 'waze\.com' $AUTH
