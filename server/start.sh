#!/bin/bash
# One command for the private Waze server:  ./start.sh        (or ./start.sh "Ethernet")
# Starts the server, points this Mac's web proxy at it, and ALWAYS turns the proxy off again
# when you press Ctrl-C (or if the server fails to start). Only *.waze.com traffic is decrypted;
# everything else just passes through untouched.
set -u
cd "$(dirname "$0")"
SERVICE="${1:-Wi-Fi}"
BIN="${PSERVER_VENV:-$HOME/pserver-venv}/bin"

[ -f pserver.py ] || { echo "pserver.py is not in $(pwd)"; exit 1; }
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
echo "proxy on for '$SERVICE'. Open Waze now. Dashboard: http://127.0.0.1:${BYWAY_DASH_PORT:-8081}  Press Ctrl-C here when done."
"$BIN/mitmdump" -s pserver.py --listen-host 127.0.0.1 --allow-hosts 'waze\.com'
