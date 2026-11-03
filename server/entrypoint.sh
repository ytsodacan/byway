#!/bin/sh
# Starts the Byway server. Env: BYWAY_PROXYAUTH=user:pass (strongly recommended on a public host),
# BYWAY_PORT (8080), BYWAY_MAX_WAZERS / BYWAY_MAX_ALERTS via PSERVER_* vars.
set -e
AUTH=""
[ -n "$BYWAY_PROXYAUTH" ] && AUTH="--proxyauth $BYWAY_PROXYAUTH"
[ -f "$BYWAY_HOME/capture/flows.jsonl" ] || { echo "missing $BYWAY_HOME/capture/flows.jsonl (see README: Data)"; exit 1; }
[ -f "$BYWAY_HOME/protos/descriptors.desc" ] || { echo "missing $BYWAY_HOME/protos/descriptors.desc (see README: Data)"; exit 1; }
exec mitmdump -s /app/pserver.py --listen-host 0.0.0.0 --listen-port "${BYWAY_PORT:-8080}" \
  --allow-hosts 'waze\.com' $AUTH
