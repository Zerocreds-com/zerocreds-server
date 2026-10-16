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
  ZEROCREDS_ADMIN_TOKEN_FILE: `${process.env.ZC_CONFIG}/admin-token`,
  ZEROCREDS_DESTINATIONS_FILE: `${process.env.ZC_CONFIG}/destinations.json`,
  ZEROCREDS_SIGNING_KEY_FILE: `${process.env.ZC_CONFIG}/signing-key.pem`,
  ZEROCREDS_PENDING_DIR: `${process.env.ZC_DATA}/pending`,
  ZEROCREDS_TOKENS_DIR: `${process.env.ZC_DATA}/tokens`,
  ZEROCREDS_LOCAL_CATALOG_FILE: `${process.env.ZC_CONFIG}/connections.json`,
  ZEROCREDS_LOCAL_PROVIDER_POLICIES_FILE: `${process.env.ZC_CONFIG}/provider-policies.json`,
  ZEROCREDS_BASE_URL: 'http://127.0.0.1:3456',
  ZEROCREDS_KEYCHAIN_HELPER: `${process.env.ZC_CONFIG}/zerocreds-keychain`,
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
  --env ZEROCREDS_URL=http://127.0.0.1:3456 \
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
config.mcp = config.mcp || {};
config.mcp.zerocreds = {
  type: 'local',
  command: [process.env.ZC_NODE, process.env.ZC_MCP],
  enabled: true,
  environment: {
    ZEROCREDS_LOCAL_MODE: '1',
    ZEROCREDS_URL: 'http://127.0.0.1:3456',
    ZEROCREDS_ADMIN_TOKEN_FILE: `${home}/.config/zerocreds/local/admin-token`,
    ZEROCREDS_DEFAULT_DESTINATION: 'mac-keychain',
    ZEROCREDS_LOCAL_CATALOG_FILE: `${home}/.config/zerocreds/local/connections.json`,
  },
};
const pluginPath = path.join(process.env.ZC_ROOT, 'opencode-plugin/zerocreds-events.js');
const pluginOptions = { baseUrl: 'http://127.0.0.1:3456', adminTokenFile: `${home}/.config/zerocreds/local/admin-token` };
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
echo "Server: http://127.0.0.1:3456 (loopback only)"
echo "Keychain destination: zerocreds/<provider>-<account-alias>"
echo "Restart Codex and OpenCode to load the MCP tools."
