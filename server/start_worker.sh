#!/bin/bash
# Worker-backed version of start.sh:  ./start_worker.sh        (or ./start_worker.sh "Ethernet")
set -u
cd "$(dirname "$0")"
SERVICE="${1:-Wi-Fi}"
BIN="${PSERVER_VENV:-$HOME/pserver-venv}/bin"

export PSERVER_WORKER_URL=https://waze-private-server.ytsodacan.workers.dev
export PSERVER_RELAY_KEY=63b4ae67fb10a54efb91595a5d35e792ace88d257c9eeba48f7ceeb021c5e0f3

[ -f pserver_relay.py ] || { echo "pserver_relay.py is not in $(pwd)"; exit 1; }
[ "$PSERVER_RELAY_KEY" != "PASTE_YOUR_KEY_HERE" ] || { echo "edit start_worker.sh and set PSERVER_RELAY_KEY"; exit 1; }
[ -x "$BIN/mitmdump" ] || { echo "no mitmdump at $BIN (set PSERVER_VENV to your venv folder)"; exit 1; }
networksetup -listallnetworkservices | grep -qxF "$SERVICE" || {
  echo "no network service called '$SERVICE'. Yours are:"; networksetup -listallnetworkservices; exit 1; }

cleanup() {
  networksetup -setwebproxystate "$SERVICE" off
  networksetup -setsecurewebproxystate "$SERVICE" off
  echo "proxy is off again"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

networksetup -setwebproxy "$SERVICE" 127.0.0.1 8080
networksetup -setsecurewebproxy "$SERVICE" 127.0.0.1 8080
echo "proxy on for '$SERVICE' (Worker mode). Open Waze now. Press Ctrl-C here when done."
"$BIN/mitmdump" -s pserver_relay.py --listen-host 127.0.0.1 --allow-hosts 'waze\.com'
