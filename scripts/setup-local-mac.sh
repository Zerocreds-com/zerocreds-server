#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer requires macOS." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Preserve the original checkout path: the root proxy daemon is installed once
# and is infrastructure, not per-worktree runtime.
SOURCE_ROOT="$ROOT"

# The runtime must live in a stable location, independent of where this checkout
# happens to be. Git worktrees get pruned and multiple checkouts drift, so we
# never point launchd or the agent config at the source checkout itself.
RUNTIME_ROOT="${ZEROCREDS_INSTALL_ROOT:-$HOME/.zerocreds/runtime}"
mkdir -p "$RUNTIME_ROOT"

# Copy the runtime into the stable location and install deps there, so the
# running service is self-contained and reproducible regardless of which
# checkout the operator ran this installer from. Directory structure is
# preserved so server/src/server.js and mcp/index.js keep their paths.
copy_runtime() {
  local -a dirs=(server/src server/scripts server mcp opencode-plugin scripts)
  local d
  for d in "${dirs[@]}"; do
    if [[ -d "$ROOT/$d" ]]; then
      # Ensure the target parent directory exists
      local target_dir="${RUNTIME_ROOT}/$(dirname "$d")"
      mkdir -p "$target_dir"
      rm -rf "$RUNTIME_ROOT/$d"
      cp -R "$ROOT/$d" "$RUNTIME_ROOT/$d"
    fi
  done
  local -a files=(server/package.json server/package-lock.json mcp/package.json mcp/package-lock.json scripts/git-credential-zerocreds.sh)
  local f
  for f in "${files[@]}"; do
    if [[ -f "$ROOT/$f" ]]; then
      # Ensure the target parent directory exists
      local target_dir="${RUNTIME_ROOT}/$(dirname "$f")"
      mkdir -p "$target_dir"
      cp -p "$ROOT/$f" "$RUNTIME_ROOT/$f"
    fi
  done
  if [[ ! -d "$RUNTIME_ROOT/server/node_modules" ]]; then
    (cd "$RUNTIME_ROOT/server" && npm ci --no-audit --no-fund)
  fi
  if [[ ! -d "$RUNTIME_ROOT/mcp/node_modules" ]]; then
    (cd "$RUNTIME_ROOT/mcp" && npm ci --no-audit --no-fund)
  fi
}

copy_runtime

# From here on, ROOT points at the stable runtime directory. launchd and the
# agent configs reference this path, never the source checkout.
ROOT="$RUNTIME_ROOT"

CONFIG="$HOME/.config/zerocreds/local"
DATA="$HOME/Library/Application Support/ZeroCreds"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"
LABEL="com.zerocreds.local-server"
UID_NUM="$(id -u)"

# The readable address for the local service. A loopback-only reverse proxy
# (scripts/local-proxy.js) serves http://localhost/zerocreds in front of the
# server. Port 80 is privileged, so by default we use 8080 which needs no
# root; set ZEROCREDS_PROXY_PORT=80 to use the bare port instead.
PROXY_LABEL="com.zerocreds.local-proxy"
PROXY_MODE="${ZEROCREDS_PROXY_MODE:-auto}"
PROXY_PORT="${ZEROCREDS_PROXY_PORT:-8080}"
if [[ "$PROXY_PORT" == "80" ]]; then
  PROXY_PLIST_DST="/Library/LaunchDaemons/$PROXY_LABEL.plist"
  PROXY_SCOPE="system"
else
  PROXY_PLIST_DST="$HOME/Library/LaunchAgents/$PROXY_LABEL.plist"
  PROXY_SCOPE="gui/$(id -u)"
fi
DIRECT_URL="http://localhost:3456"
if [[ "$PROXY_PORT" == "80" ]]; then
  PRETTY_URL="http://localhost/zerocreds"
else
  PRETTY_URL="http://localhost:${PROXY_PORT}/zerocreds"
fi
export ZEROCREDS_PROXY_PORT="$PROXY_PORT" ZEROCREDS_PROXY_TARGET="$DIRECT_URL"

mkdir -p "$CONFIG" "$DATA/pending" "$DATA/tokens" "$LAUNCH_AGENTS"
chmod 700 "$CONFIG" "$DATA" "$DATA/pending" "$DATA/tokens"

HELPER="$CONFIG/zerocreds-keychain"
HELPER_FINGERPRINT="$CONFIG/zerocreds-keychain.sha256"
SOURCE_HASH="$(shasum -a 256 "$ROOT/server/scripts/macos-keychain.swift" | awk '{print $1}')"
INSTALLED_SOURCE_HASH=""
INSTALLED_BINARY_HASH=""
if [[ -f "$HELPER_FINGERPRINT" ]]; then
  read -r INSTALLED_SOURCE_HASH INSTALLED_BINARY_HASH < "$HELPER_FINGERPRINT" || true
fi
CURRENT_BINARY_HASH=""
if [[ -x "$HELPER" ]]; then
  CURRENT_BINARY_HASH="$(shasum -a 256 "$HELPER" | awk '{print $1}')"
fi
if [[ "$SOURCE_HASH" != "$INSTALLED_SOURCE_HASH" || "$CURRENT_BINARY_HASH" != "$INSTALLED_BINARY_HASH" ]]; then
  swiftc -O "$ROOT/server/scripts/macos-keychain.swift" -o "$HELPER.tmp"
  chmod 700 "$HELPER.tmp"
  mv "$HELPER.tmp" "$HELPER"
  CURRENT_BINARY_HASH="$(shasum -a 256 "$HELPER" | awk '{print $1}')"
  printf '%s %s\n' "$SOURCE_HASH" "$CURRENT_BINARY_HASH" > "$HELPER_FINGERPRINT.tmp"
  chmod 600 "$HELPER_FINGERPRINT.tmp"
  mv "$HELPER_FINGERPRINT.tmp" "$HELPER_FINGERPRINT"
fi

if [[ ! -f "$CONFIG/admin-token" ]]; then
  umask 077
  openssl rand -hex 32 > "$CONFIG/admin-token"
fi
chmod 600 "$CONFIG/admin-token"

if [[ ! -f "$CONFIG/destinations.json" ]]; then
  umask 077
  cat > "$CONFIG/destinations.json" <<'JSON'
{
  "mac-keychain": {
    "type": "macos_keychain",
    "service": "zerocreds",
    "account": "{{service}}-{{uid}}"
  }
}
JSON
  chmod 600 "$CONFIG/destinations.json"
fi

if [[ ! -f "$CONFIG/provider-policies.json" ]]; then
  umask 077
  printf '{}\n' > "$CONFIG/provider-policies.json"
  chmod 600 "$CONFIG/provider-policies.json"
fi

# Dependencies are installed by copy_runtime(); these guards are kept only as a
# fallback if the runtime copy was skipped or partially failed.
if [[ ! -d "$ROOT/server/node_modules" ]]; then (cd "$ROOT/server" && npm ci --no-audit --no-fund); fi
if [[ ! -d "$ROOT/mcp/node_modules" ]]; then (cd "$ROOT/mcp" && npm ci --no-audit --no-fund); fi

# The reverse proxy serves the readable address. Port 8080 (the default) needs
# no root; port 80 is privileged and requires sudo. Install the proxy when
# possible, otherwise print the command to run by hand so the readable address
# can be enabled later.
proxy_running() {
  [[ -f "$PROXY_PLIST_DST" ]] && launchctl print "$PROXY_SCOPE/$PROXY_LABEL" >/dev/null 2>&1
}

# Check if the proxy is running on the correct port; reinstall if not.
proxy_port_matches() {
  local current_port
  current_port=$(plutil -extract EnvironmentVariables.ZEROCREDS_PROXY_PORT raw "$PROXY_PLIST_DST" 2>/dev/null || echo "")
  [[ "$current_port" == "$PROXY_PORT" ]]
}

PROXY_OK=0
if [[ "$PROXY_MODE" != "off" ]]; then
  if proxy_running && proxy_port_matches; then
    PROXY_OK=1
  elif sudo -n true 2>/dev/null && [[ "$PROXY_PORT" == "80" ]]; then
    sudo "$ROOT/scripts/install-local-proxy.sh"
    PROXY_OK=1
  elif [[ "$PROXY_PORT" != "80" ]]; then
    # Port 8080 is not privileged; install it directly without sudo.
    "$ROOT/scripts/install-local-proxy.sh"
    PROXY_OK=1
  else
    cat >&2 <<EOF

The readable address $PRETTY_URL needs a reverse proxy on port 80, which requires
root. Run this command and then re-run this installer to switch over:

  sudo "$ROOT/scripts/install-local-proxy.sh"

Until then the service stays on $DIRECT_URL.

EOF
  fi
fi
BASE_URL="$DIRECT_URL"
if [[ "$PROXY_OK" == "1" ]]; then BASE_URL="$PRETTY_URL"; fi
export ZC_BASE_URL="$BASE_URL"

mkdir -p "$HOME/Library/Application Support/ZeroCreds"
PLIST="$LAUNCH_AGENTS/$LABEL.plist"
export ZC_ROOT="$ROOT" ZC_CONFIG="$CONFIG" ZC_DATA="$DATA" ZC_PLIST="$PLIST"
if [[ -f "$HOME/.codex/config.toml" && ! -f "$CONFIG/codex-config.toml.before-zerocreds" ]]; then cp -p "$HOME/.codex/config.toml" "$CONFIG/codex-config.toml.before-zerocreds"; fi
if [[ -f "$HOME/.config/opencode/opencode.json" && ! -f "$CONFIG/opencode-config.json.before-zerocreds" ]]; then cp -p "$HOME/.config/opencode/opencode.json" "$CONFIG/opencode-config.json.before-zerocreds"; fi
node <<'NODE'
const fs = require('fs');
const e = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
const env = {
  PATH: '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
  ZEROCREDS_LOCAL_MODE: '1',
  ZEROCREDS_DEFAULT_DESTINATION: 'mac-keychain',
  ZEROCREDS_KEYCHAIN_HELPER: `${process.env.ZC_CONFIG}/zerocreds-keychain`,
  ZEROCREDS_ADMIN_TOKEN_FILE: `${process.env.ZC_CONFIG}/admin-token`,
  ZEROCREDS_DESTINATIONS_FILE: `${process.env.ZC_CONFIG}/destinations.json`,
  ZEROCREDS_SIGNING_KEY_FILE: `${process.env.ZC_CONFIG}/signing-key.pem`,
  ZEROCREDS_PENDING_DIR: `${process.env.ZC_DATA}/pending`,
  ZEROCREDS_TOKENS_DIR: `${process.env.ZC_DATA}/tokens`,
  ZEROCREDS_LOCAL_CATALOG_FILE: `${process.env.ZC_CONFIG}/connections.json`,
  ZEROCREDS_SHARE_RELAY_URL: process.env.ZEROCREDS_SHARE_RELAY_URL || 'https://zerocreds.ru',
  ZEROCREDS_SHARE_DIRECT_URL: process.env.ZEROCREDS_SHARE_DIRECT_URL || '',
  ZEROCREDS_SHARE_DIRECT_CERT_FILE: process.env.ZEROCREDS_SHARE_DIRECT_CERT_FILE || '',
  ZEROCREDS_SHARE_DIRECT_KEY_FILE: process.env.ZEROCREDS_SHARE_DIRECT_KEY_FILE || '',
  ZEROCREDS_LOCAL_PROVIDER_POLICIES_FILE: `${process.env.ZC_CONFIG}/provider-policies.json`,
  ZEROCREDS_BASE_URL: process.env.ZC_BASE_URL,
  PORT: '3456',
};
const envXml = Object.entries(env).map(([k, v]) => `<key>${e(k)}</key><string>${e(v)}</string>`).join('');
const root = process.env.ZC_ROOT;
const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.zerocreds.local-server</string>
<key>ProgramArguments</key><array><string>${e(process.execPath)}</string><string>${e(`${root}/server/src/server.js`)}</string></array>
<key>WorkingDirectory</key><string>${e(root)}</string>
<key>EnvironmentVariables</key><dict>${envXml}</dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>${e(`${process.env.ZC_DATA}/server.log`)}</string>
<key>StandardErrorPath</key><string>${e(`${process.env.ZC_DATA}/server-error.log`)}</string>
</dict></plist>`;
fs.writeFileSync(process.env.ZC_PLIST, plist, { mode: 0o600 });
NODE

codex mcp remove zerocreds >/dev/null 2>&1 || true
codex mcp add zerocreds \
  --env ZEROCREDS_LOCAL_MODE=1 \
  --env ZEROCREDS_URL="$BASE_URL" \
  --env ZEROCREDS_ADMIN_TOKEN_FILE="$CONFIG/admin-token" \
  --env ZEROCREDS_DEFAULT_DESTINATION=mac-keychain \
  --env ZEROCREDS_LOCAL_CATALOG_FILE="$CONFIG/connections.json" \
  -- "$(command -v node)" "$ROOT/mcp/index.js"
node "$SOURCE_ROOT/scripts/install-codex-guidance.js"

if command -v claude >/dev/null 2>&1; then
  claude mcp remove zerocreds --scope user >/dev/null 2>&1 || true
  claude mcp add --scope user \
    --env ZEROCREDS_LOCAL_MODE=1 \
    --env ZEROCREDS_URL="$BASE_URL" \
    --env ZEROCREDS_ADMIN_TOKEN_FILE="$CONFIG/admin-token" \
    --env ZEROCREDS_DEFAULT_DESTINATION=mac-keychain \
    --env ZEROCREDS_LOCAL_CATALOG_FILE="$CONFIG/connections.json" \
    --transport stdio zerocreds -- "$(command -v node)" "$ROOT/mcp/index.js"
fi

export ZC_NODE="$(command -v node)" ZC_MCP="$ROOT/mcp/index.js"
node <<'NODE'
const fs = require('fs');
const path = require('path');
const home = process.env.HOME;
const configPath = path.join(home, '.config/opencode/opencode.json');
fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
let config = {};
try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
// Hosts on the V2 config schema read MCP servers from `mcp.servers`. Mixing
// legacy flat entries with a `servers` key inside one `mcp` object makes the
// whole block unreadable, so migrate flat entries first and write V2 only.
const existingMcp = config.mcp && typeof config.mcp === 'object' ? config.mcp : {};
const servers = { ...(existingMcp.servers && typeof existingMcp.servers === 'object' ? existingMcp.servers : {}) };
for (const [name, value] of Object.entries(existingMcp)) {
  if (name === 'servers') continue;
  if (value && typeof value === 'object' && typeof value.type === 'string') servers[name] = value;
}
config.mcp = { servers };
config.mcp.servers.zerocreds = {
  type: 'local',
  command: [process.env.ZC_NODE, process.env.ZC_MCP],
  environment: {
    ZEROCREDS_LOCAL_MODE: '1',
    ZEROCREDS_URL: process.env.ZC_BASE_URL,
    ZEROCREDS_ADMIN_TOKEN_FILE: `${home}/.config/zerocreds/local/admin-token`,
    ZEROCREDS_DEFAULT_DESTINATION: 'mac-keychain',
    ZEROCREDS_LOCAL_CATALOG_FILE: `${home}/.config/zerocreds/local/connections.json`,
  },
};
const pluginPath = path.join(process.env.ZC_ROOT, 'opencode-plugin/zerocreds-events.js');
const pluginOptions = { baseUrl: process.env.ZC_BASE_URL, adminTokenFile: `${home}/.config/zerocreds/local/admin-token` };
config.plugin = Array.isArray(config.plugin) ? config.plugin : [];
const existingPlugin = config.plugin.findIndex((entry) =>
  (typeof entry === 'string' && entry === pluginPath) ||
  (Array.isArray(entry) && entry[0] === pluginPath));
const pluginEntry = [pluginPath, pluginOptions];
if (existingPlugin >= 0) config.plugin[existingPlugin] = pluginEntry;
else config.plugin.push(pluginEntry);
const tmp = `${configPath}.zerocreds.tmp`;
fs.writeFileSync(tmp, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
fs.renameSync(tmp, configPath);
NODE

launchctl bootout "gui/$UID_NUM" "$PLIST" >/dev/null 2>&1 || true
sleep 1
launchctl bootstrap "gui/$UID_NUM" "$PLIST"
launchctl kickstart -k "gui/$UID_NUM/$LABEL"

echo "ZeroCreds local Mac service installed."
echo "Server: $BASE_URL (loopback only)"
if [[ "$PROXY_OK" == "1" ]]; then
  echo "Readable address: $PRETTY_URL (reverse proxy on port $PROXY_PORT, $PROXY_SCOPE/$PROXY_LABEL)"
fi
echo "Keychain destination: zerocreds/<provider>-<account-alias>"
if [[ -n "${ZEROCREDS_SHARE_DIRECT_URL:-}" ]]; then
  echo "Direct sharing: $ZEROCREDS_SHARE_DIRECT_URL (ensure the public port reaches this Mac)"
else
  echo "Sharing: outbound HTTPS relay (set ZEROCREDS_SHARE_DIRECT_URL for a public-IP endpoint)"
fi
echo "Restart Codex, OpenCode and Claude Code (if installed) to load the MCP tools."
