#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer requires macOS." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$HOME/.config/zerocreds/local"
DATA="$HOME/Library/Application Support/ZeroCreds"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"
LABEL="com.zerocreds.local-server"
UID_NUM="$(id -u)"

# The readable address for the local service. Port 80 is privileged, so it needs a
# root LaunchDaemon (scripts/local-proxy.js) in front of the server; without it the
# service is still reachable on the direct loopback port.
PROXY_LABEL="com.zerocreds.local-proxy"
PROXY_PLIST_SRC="$ROOT/scripts/local-proxy.plist"
PROXY_PLIST_DST="/Library/LaunchDaemons/$PROXY_LABEL.plist"
PROXY_MODE="${ZEROCREDS_PROXY_MODE:-auto}"
PROXY_PORT="${ZEROCREDS_PROXY_PORT:-80}"
DIRECT_URL="http://localhost:3456"
PRETTY_URL="http://localhost/zerocreds"

mkdir -p "$CONFIG" "$DATA/pending" "$DATA/tokens" "$LAUNCH_AGENTS"
chmod 700 "$CONFIG" "$DATA" "$DATA/pending" "$DATA/tokens"

swiftc -O "$ROOT/server/scripts/macos-keychain.swift" -o "$CONFIG/zerocreds-keychain.tmp"
chmod 700 "$CONFIG/zerocreds-keychain.tmp"
mv "$CONFIG/zerocreds-keychain.tmp" "$CONFIG/zerocreds-keychain"

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

if [[ ! -d "$ROOT/server/node_modules" ]]; then (cd "$ROOT/server" && npm ci); fi
if [[ ! -d "$ROOT/mcp/node_modules" ]]; then (cd "$ROOT/mcp" && npm ci); fi

# The reverse proxy runs as root because port 80 is privileged. Stage a concrete
# plist first, then either install it (when sudo is available) or print the exact
# commands, so the readable address can also be enabled by hand later.
STAGED_PROXY_PLIST="$CONFIG/local-proxy.plist"
export ZC_PROXY_TPL="$PROXY_PLIST_SRC" ZC_PROXY_OUT="$STAGED_PROXY_PLIST"
export ZC_NODE="$(command -v node)" ZC_ROOT="$ROOT" ZC_PROXY_PORT="$PROXY_PORT" ZC_PROXY_TARGET="$DIRECT_URL"
node <<'NODE'
const fs = require('fs');
const out = fs.readFileSync(process.env.ZC_PROXY_TPL, 'utf8')
  .replaceAll('__NODE__', process.env.ZC_NODE)
  .replaceAll('__ROOT__', process.env.ZC_ROOT)
  .replaceAll('__PORT__', process.env.ZC_PROXY_PORT)
  .replaceAll('__TARGET__', process.env.ZC_PROXY_TARGET);
fs.writeFileSync(process.env.ZC_PROXY_OUT, out, { mode: 0o644 });
NODE

proxy_running() {
  [[ -f "$PROXY_PLIST_DST" ]] && launchctl print "system/$PROXY_LABEL" >/dev/null 2>&1
}

PROXY_OK=0
if [[ "$PROXY_MODE" != "off" ]]; then
  if proxy_running; then
    PROXY_OK=1
  elif sudo -n true 2>/dev/null; then
    sudo cp "$STAGED_PROXY_PLIST" "$PROXY_PLIST_DST"
    sudo chown root:wheel "$PROXY_PLIST_DST"
    sudo chmod 644 "$PROXY_PLIST_DST"
    sudo launchctl bootout "system/$PROXY_LABEL" >/dev/null 2>&1 || true
    sudo launchctl bootstrap system "$PROXY_PLIST_DST"
    PROXY_OK=1
  else
    cat >&2 <<EOF

The readable address $PRETTY_URL needs a reverse proxy on port 80, which requires
root. Run these three commands and re-run this installer to switch over:

  sudo cp "$STAGED_PROXY_PLIST" "$PROXY_PLIST_DST"
  sudo chown root:wheel "$PROXY_PLIST_DST"
  sudo launchctl bootstrap system "$PROXY_PLIST_DST"

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
  echo "Readable address: $PRETTY_URL (port 80 reverse proxy, system/$PROXY_LABEL)"
fi
echo "Keychain destination: zerocreds/<provider>-<account-alias>"
echo "Restart Codex and OpenCode to load the MCP tools."
