#!/bin/bash
# Install the LaunchAgent/LaunchDaemon that serves the readable local address
# http://localhost/zerocreds in front of the ZeroCreds local server.
#
# Port 80 is privileged, so this script must run as root:
#
#   sudo ./scripts/install-local-proxy.sh
#
# Port 8080 (the default) is not privileged, so it can be installed by the
# user without sudo. Override ZEROCREDS_PROXY_PORT=80 to use the bare port.
#
# It is idempotent: the daemon is replaced and reloaded.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer requires macOS." >&2
  exit 1
fi

PORT="${ZEROCREDS_PROXY_PORT:-8080}"
if [[ "$PORT" == "80" && "$(id -u)" != "0" ]]; then
  echo "This installer needs root (port 80 is privileged). Run: sudo $0" >&2
  exit 1
fi

SOURCE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# The proxy script must live in a stable location too: it is a root LaunchDaemon
# and a pruned worktree would take it down with the rest of the runtime.
RUNTIME_ROOT="${ZEROCREDS_INSTALL_ROOT:-$HOME/.zerocreds/runtime}"
mkdir -p "$RUNTIME_ROOT/scripts"
if [[ -f "$SOURCE_ROOT/scripts/local-proxy.js" ]]; then
  # Skip the copy when the installer is already running from the runtime (the
  # source and destination are the same file); BSD cp exits 1 on that no-op.
  if [[ "$SOURCE_ROOT/scripts/local-proxy.js" -ef "$RUNTIME_ROOT/scripts/local-proxy.js" ]]; then
    :
  else
    cp -p "$SOURCE_ROOT/scripts/local-proxy.js" "$RUNTIME_ROOT/scripts/local-proxy.js"
  fi
fi
ROOT="$RUNTIME_ROOT"
LABEL="com.zerocreds.local-proxy"
NODE_BIN="$(command -v node || true)"
if [[ -z "$NODE_BIN" ]]; then
  echo "node not found in PATH; install Node.js first." >&2
  exit 1
fi

# Port 80 requires root and a system LaunchDaemon; port 8080 works as a user
# LaunchAgent in ~/Library/LaunchAgents.
if [[ "$PORT" == "80" ]]; then
  PLIST_DST="/Library/LaunchDaemons/$LABEL.plist"
  LAUNCHCTL="launchctl"
  SCOPE="system"
  LOG_DIR="/var/log"
else
  PLIST_DST="$HOME/Library/LaunchAgents/$LABEL.plist"
  LAUNCHCTL="launchctl"
  SCOPE="gui/$(id -u)"
  LOG_DIR="/tmp"
fi

TMP_PLIST="$(mktemp -t zerocreds-proxy)"
trap 'rm -f "$TMP_PLIST"' EXIT
sed -e "s|__NODE__|$NODE_BIN|g" \
    -e "s|__ROOT__|$ROOT|g" \
    -e "s|__PORT__|$PORT|g" \
    -e "s|__TARGET__|http://127.0.0.1:3456|g" \
    -e "s|__LOG_DIR__|$LOG_DIR|g" \
    "$SOURCE_ROOT/scripts/local-proxy.plist" > "$TMP_PLIST"

install -o "$(id -u)" -g "$(id -g)" -m 644 "$TMP_PLIST" "$PLIST_DST"
launchctl bootout "$SCOPE/$LABEL" >/dev/null 2>&1 || true
launchctl bootstrap "$SCOPE" "$PLIST_DST"

sleep 1
if ! curl -fsS --max-time 5 -o /dev/null "http://localhost:$( [[ "$PORT" == "80" ]] && echo "" || echo ":$PORT" )/about"; then
  echo "The proxy did not answer yet. Check the logs." >&2
fi

echo "ZeroCreds local proxy installed: $SCOPE/$LABEL"
echo "Readable address: http://localhost:${PORT}/zerocreds (proxy on port $PORT -> http://127.0.0.1:3456)"
echo "Run scripts/setup-local-mac.sh again to point the server and the MCP at it."
