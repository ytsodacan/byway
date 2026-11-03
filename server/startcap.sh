#!/bin/bash
# Record what the REAL Waze servers do, with NO private server:   ./startcap.sh     (or ./startcap.sh "Ethernet")
# Saves to ~/waze_capture_guest (kept apart from your first capture). Turns the proxy off again on Ctrl-C.
# The saved files contain the guest account's password and tokens: keep them private, don't share the folder.
set -u
umask 077
cd "$(dirname "$0")"
SERVICE="${1:-Wi-Fi}"
BIN="${PSERVER_VENV:-$HOME/pserver-venv}/bin"
export WAZE_CAPTURE_DIR="${WAZE_CAPTURE_DIR:-$HOME/waze_capture_guest}"

[ -f capture.py ] || { echo "capture.py is not in $(pwd)"; exit 1; }
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
echo "RECORDING real Waze to $WAZE_CAPTURE_DIR. Open Waze now. Press Ctrl-C here when done."
"$BIN/mitmdump" -s capture.py --listen-host 127.0.0.1 --allow-hosts 'waze\.com'
