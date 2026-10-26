#!/bin/bash
# Install the root LaunchDaemon that serves the readable local address
# http://localhost/zerocreds in front of the ZeroCreds local server.
#
# Port 80 is privileged, so this script must run as root:
#
#   sudo ./scripts/install-local-proxy.sh
#
# It is idempotent: the daemon is replaced and reloaded.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer requires macOS." >&2
  exit 1
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "This installer needs root (port 80 is privileged). Run: sudo $0" >&2
  exit 1
fi

SOURCE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# The proxy script must live in a stable location too: it is a root LaunchDaemon
# and a pruned worktree would take it down with the rest of the runtime.
RUNTIME_ROOT="${ZEROCREDS_INSTALL_ROOT:-$HOME/.zerocreds/runtime}"
mkdir -p "$RUNTIME_ROOT/scripts"
if [[ -f "$SOURCE_ROOT/scripts/local-proxy.js" ]]; then
  cp -p "$SOURCE_ROOT/scripts/local-proxy.js" "$RUNTIME_ROOT/scripts/local-proxy.js"
fi
ROOT="$RUNTIME_ROOT"
LABEL="com.zerocreds.local-proxy"
PLIST_DST="/Library/LaunchDaemons/$LABEL.plist"
PORT="${ZEROCREDS_PROXY_PORT:-80}"
TARGET="${ZEROCREDS_PROXY_TARGET:-http://127.0.0.1:3456}"
NODE_BIN="$(command -v node || true)"
if [[ -z "$NODE_BIN" ]]; then
  echo "node not found in PATH; install Node.js first." >&2
  exit 1
fi

TMP_PLIST="$(mktemp -t zerocreds-proxy)"
trap 'rm -f "$TMP_PLIST"' EXIT
sed -e "s|__NODE__|$NODE_BIN|g" \
    -e "s|__ROOT__|$ROOT|g" \
    -e "s|__PORT__|$PORT|g" \
    -e "s|__TARGET__|$TARGET|g" \
    "$SOURCE_ROOT/scripts/local-proxy.plist" > "$TMP_PLIST"

install -o root -g wheel -m 644 "$TMP_PLIST" "$PLIST_DST"
launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST_DST"

sleep 1
if ! curl -fsS --max-time 5 -o /dev/null "http://localhost:$( [[ "$PORT" == "80" ]] && echo "" || echo ":$PORT" )/about"; then
  echo "The proxy did not answer yet. Check /var/log/zerocreds-proxy-error.log" >&2
fi

echo "ZeroCreds local proxy installed: system/$LABEL"
echo "Readable address: http://localhost/zerocreds (proxy on port $PORT -> $TARGET)"
echo "Run scripts/setup-local-mac.sh again to point the server and the MCP at it."
