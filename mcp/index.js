'use strict';

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');
const { createWalletProvider, bindingForOperation, API_OPERATIONS } = require('./provider');

const BASE_URL = (process.env.ZEROCREDS_URL || 'https://zerocreds.ru').replace(/\/$/, '');
const fs = require('fs');
const ADMIN_TOKEN_FILE = process.env.ZEROCREDS_ADMIN_TOKEN_FILE || '';
let ADMIN_TOKEN = process.env.ZEROCREDS_ADMIN_TOKEN || '';
if (!ADMIN_TOKEN && ADMIN_TOKEN_FILE) {
  let fd;
  try {
    fd = fs.openSync(ADMIN_TOKEN_FILE, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid()) || stat.size > 256) {
      throw new Error('ZeroCreds admin token file must be a private regular file owned by the current user');
    }
    ADMIN_TOKEN = fs.readFileSync(fd, 'utf8').trim();
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  if (ADMIN_TOKEN.length < 32 || /\s/.test(ADMIN_TOKEN)) throw new Error('ZeroCreds admin token file is invalid');
}
const WALLET_API_TOKEN = process.env.ZEROCREDS_WALLET_API_TOKEN || '';
const LOCAL_MODE = process.env.ZEROCREDS_LOCAL_MODE === '1';
const DEFAULT_DESTINATION = process.env.ZEROCREDS_DEFAULT_DESTINATION || '';
if (LOCAL_MODE) {
  let endpoint;
  try { endpoint = new URL(BASE_URL); } catch {}
  if (!endpoint || endpoint.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname)
      || endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash
      || !DEFAULT_DESTINATION) {
    throw new Error('Local ZeroCreds requires a loopback URL and a configured local Keychain destination');
  }
}

async function apiCall(method, path, body) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${ADMIN_TOKEN}`,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
}

const walletProvider = createWalletProvider({ baseUrl: BASE_URL });
const walletHandlers = new Map(walletProvider.tools.map(tool => [tool.name, tool.handler]));
const legacyWalletContext = (toolName) => ({ bindings: {
  [bindingForOperation(API_OPERATIONS[toolName])]: WALLET_API_TOKEN,
} });

const server = new McpServer({
  name: 'zerocreds',
  version: '0.1.0',
});

server.tool(
  'zerocreds_create_session',
  'Create a ZeroCreds credential-collection session. Returns a one-time URL to send to the user. The user fills in credentials directly — the agent never sees them.',
  {
    title: z.string().describe('Heading shown on the form (e.g. "Connect GitHub")'),
    description: z.string().optional().describe('Subtext explaining what credentials are needed and why'),
    fields: z.array(z.object({
      name: z.string().describe('Key in the saved credentials JSON (alphanumeric + underscore)'),
      label: z.string().describe('Label shown on the form'),
      type: z.enum(['text', 'password', 'email', 'tel', 'number', 'textarea', 'url']).optional().describe('Input type (default: text)'),
      placeholder: z.string().optional(),
      required: z.boolean().optional(),
      level: z.enum(['secret', 'pii', 'attribute', 'credential']).optional().describe('Sensitivity badge shown on the form. "secret" = passwords/tokens (never logged, badge: SECRET); "pii" = personal data like username/email/domain (anonymised in logs, badge: PII DATA); "attribute" = open config the AI can see freely (badge: CONFIG); "credential" = session-scoped tokens, used once (never logged, badge: SESSION). Omit to fall back to "default" grouping.'),
    })).describe('List of fields to collect. level is optional — fields without it fall back to "default" grouping in destinations_by_level.'),
    destination: z.union([
      z.string().describe('Named destination configured by the server admin (the default and, on production servers, the only option)'),
      z.object({
        type: z.enum(['local_file', 'gcp_secret_manager', 'aws_secrets_manager', 'vault']),
        uid: z.string().optional(),
        filename: z.string().optional(),
      }).passthrough().describe('Inline destination config — only accepted when the server sets ZEROCREDS_ALLOW_INLINE_DESTINATIONS=1'),
    ]).optional().describe('Where to save credentials. Local mode always uses the locally configured Keychain destination.'),
    uid: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/).optional().describe('Stable local account alias, for example github-work or github-personal. Used to keep multiple accounts separate.'),
    service: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/).optional().describe('Provider slug used in the local credential catalog, for example github.'),
    credential_expires_at: z.string().datetime({ offset: true }).optional().describe('Known credential expiry as an ISO timestamp. Omit when unknown; this is different from the form link expiry.'),
    ttl_minutes: z.number().int().min(1).max(1440).optional().describe('Link expiry in minutes (default: 30)'),
    notify: z.object({
      tg_bot_token: z.string(),
      tg_chat_id: z.string(),
    }).optional().describe('Send the form link via Telegram automatically'),
  },
  async ({ title, description, fields, destination, uid, service, credential_expires_at, ttl_minutes, notify }) => {
    const selectedDestination = LOCAL_MODE ? DEFAULT_DESTINATION : destination;
    if (!selectedDestination) throw new Error('ZeroCreds destination is not configured');
    if (LOCAL_MODE && (!uid || !service)) throw new Error('Local credential setup requires a provider slug and a distinct account alias');
    if (LOCAL_MODE && destination && destination !== DEFAULT_DESTINATION) {
      throw new Error('Local ZeroCreds always uses the configured macOS Keychain destination');
    }
    const data = await apiCall('POST', '/api/session/create', {
      title,
      description,
      fields,
      destination: selectedDestination,
      uid,
      service,
      credential_expires_at,
      ttl_minutes,
      notify,
    });
    if (data.error) throw new Error(data.error);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          token: data.token,
          url: data.url,
          expires_at: data.expires_at,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  'zerocreds_connections_list',
  'List local ZeroCreds credential connections without returning credential values. Shows provider, account alias, expiry and verification status.',
  {
    provider: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/).optional(),
  },
  async ({ provider }) => {
    const query = provider ? `?provider=${encodeURIComponent(provider)}` : '';
    const data = await apiCall('GET', `/api/local/connections${query}`);
    if (data.error) throw new Error(data.error);
    return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
  },
);

server.tool(
  'zerocreds_connection_resolve',
  'Resolve an existing local connection for a provider. Pass an account alias when more than one account exists. Never returns the credential value.',
  {
    provider: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
    account_alias: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/).optional(),
  },
  async ({ provider, account_alias }) => {
    const query = new URLSearchParams({ provider, resolve: '1' });
    if (account_alias) query.set('account_alias', account_alias);
    const data = await apiCall('GET', `/api/local/connections?${query}`);
    if (data.error) throw new Error(data.error);
    return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
  },
);

if (LOCAL_MODE) server.tool(
  'zerocreds_connection_verify',
  'Verify a saved GitHub or Cloudflare credential against that provider from the trusted local ZeroCreds server. Returns identity, observed permissions and expiry only; never returns credential values.',
  {
    provider: z.enum(['github', 'cloudflare']),
    account_alias: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
  },
  async ({ provider, account_alias }) => {
    const data = await apiCall('POST', '/api/local/connections/verify', { provider, account_alias });
    if (data.error) throw new Error(data.error);
    return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
  },
);

if (LOCAL_MODE) {
  server.tool('zerocreds_discovery_sources',
    'First step when the user asks what access exists: detect supported credential sources and report availability. Read-only; does not catalog anything and never reads secret values. Then call zerocreds_discovery_preview to show candidate metadata. Browser password stores may be detected but are not read.',
    {},
    async () => {
      const data = await apiCall('GET', '/api/local/discovery/sources');
      if (data.error) throw new Error(data.error);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    });

  server.tool('zerocreds_discovery_preview',
    'Scan available local sources and show credential metadata candidates without saving them. Call when the user asks about available access. Present provider, account, source and scopes clearly; do not catalog yet. Ask which candidates the user wants added, then call zerocreds_discovery_catalog only for those refs after the user confirms.',
    { source_ids: z.array(z.enum(['github_cli', 'cloudflare_cli', 'gcloud_cli', 'macos_keychain', 'chrome'])).optional() },
    async ({ source_ids }) => {
      const data = await apiCall('POST', '/api/local/discovery/preview', { source_ids });
      if (data.error) throw new Error(data.error);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    });

  server.tool('zerocreds_discovery_catalog',
    'Add only explicitly selected metadata candidates from a recent discovery preview. This writes a searchable local metadata catalog, never copies secrets. Call only after the user has reviewed the preview and chosen these refs.',
    { preview_id: z.string().regex(/^[a-f0-9]{36}$/), refs: z.array(z.string().regex(/^disc_[a-f0-9]{24}$/)).min(1).max(200) },
    async ({ preview_id, refs }) => {
      const data = await apiCall('POST', '/api/local/discovery/catalog', { preview_id, refs });
      if (data.error) throw new Error(data.error);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    });

  server.tool('zerocreds_credentials_search',
    'Search the approved local credential metadata catalog by provider, account, source, label or scope. Search results describe where access may exist; they do not prove a credential is usable. Use discovery preview when the user asks for a fresh inventory. Optionally search an active preview before the user chooses what to catalog.',
    { q: z.string().min(1).max(256), preview_id: z.string().regex(/^[a-f0-9]{36}$/).optional(), limit: z.number().int().min(1).max(100).optional() },
    async ({ q, preview_id, limit }) => {
      const query = new URLSearchParams({ q });
      if (preview_id) query.set('preview_id', preview_id);
      if (limit) query.set('limit', String(limit));
      const data = await apiCall('GET', `/api/local/discovery/search?${query}`);
      if (data.error) throw new Error(data.error);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    });
}

server.tool(
  'zerocreds_check_status',
  'Check whether the user has submitted the ZeroCreds form. Poll every 5–10 seconds until status is "done" or "expired".',
  {
    token: z.string().describe('Session token returned by zerocreds_create_session'),
  },
  async ({ token }) => {
    const data = await apiCall('GET', `/api/session/${token}/status`);
    if (data.error) throw new Error(data.error);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(data, null, 2),
      }],
    };
  }
);

if (!LOCAL_MODE || WALLET_API_TOKEN) {
server.tool(
  'zerocreds_wallet_form_create',
  'Request a credential form in the current user profile. Returns a one-time URL and connection_id. The agent never sees credential values or chooses the storage destination.',
  {
    provider: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/).describe('Service slug, for example github or tilda'),
    kind: z.enum(['token', 'ssh', 'login']).default('token'),
    title: z.string().max(200).optional(),
    description: z.string().max(2000).optional(),
    fields: z.array(z.object({
      name: z.string(), label: z.string(),
      type: z.enum(['text', 'password', 'email', 'tel', 'number', 'textarea', 'url']).optional(),
      required: z.boolean().optional(),
    })).min(1).optional(),
    ttl_minutes: z.number().int().min(1).max(1440).optional(),
    idempotency_key: z.string().regex(/^[a-zA-Z0-9_-]{16,128}$/).optional(),
  },
  async (input) => ({ content: [{ type: 'text', text: JSON.stringify(
    await walletHandlers.get('zerocreds_wallet_form_create')(input, legacyWalletContext('zerocreds_wallet_form_create')), null, 2) }] }),
);

server.tool(
  'zerocreds_wallet_form_status',
  'Check whether a wallet form was completed. Returns only status, connection_id and version metadata; never credential values.',
  { form_id: z.string().regex(/^[a-f0-9]{32}$/) },
  async ({ form_id }) => ({ content: [{ type: 'text', text: JSON.stringify(
    await walletHandlers.get('zerocreds_wallet_form_status')({ form_id }, legacyWalletContext('zerocreds_wallet_form_status')), null, 2) }] }),
);

server.tool(
  'zerocreds_wallet_connection_status',
  'Check a saved connection by ID after the form link has expired. Returns metadata only, never credential values.',
  { connection_id: z.string().regex(/^[a-zA-Z0-9_-]{1,100}$/) },
  async ({ connection_id }) => ({ content: [{ type: 'text', text: JSON.stringify(
    await walletHandlers.get('zerocreds_wallet_connection_status')({ connection_id }, legacyWalletContext('zerocreds_wallet_connection_status')), null, 2) }] }),
);

server.tool(
  'zerocreds_wallet_connection_revoke',
  'Mark a saved connection revoked when the user explicitly requests it. Trusted brokers must deny future use; this does not return or erase credential values.',
  { connection_id: z.string().regex(/^[a-zA-Z0-9_-]{1,100}$/) },
  async ({ connection_id }) => ({ content: [{ type: 'text', text: JSON.stringify(
    await walletHandlers.get('zerocreds_wallet_connection_revoke')({ connection_id }, legacyWalletContext('zerocreds_wallet_connection_revoke')), null, 2) }] }),
);
}

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(err => {
  console.error('ZeroCreds MCP error:', err);
  process.exit(1);
});
