'use strict';

const PROVIDER_ID = 'zerocreds-wallet';
const PROVIDER_VERSION = '1.0.0';
const BINDING = 'zerocreds.wallet-api';
function bindingForOperation(operation) { return `${BINDING}:${operation}`; }
const API_OPERATIONS = Object.freeze({
  wallet_form_create: 'wallet.forms.create',
  wallet_form_status: 'wallet.forms.status',
  wallet_connection_status: 'wallet.connections.status',
  wallet_connection_revoke: 'wallet.connections.revoke',
});

// These are conservative collection shapes, not claims about service-specific
// scopes. Prefer each provider's own token UI when it offers OAuth or scoped PATs.
const SERVICE_CATALOG = Object.freeze([
  ['github', 'GitHub', 'token', 'GitHub token / fine-grained personal access token'],
  ['gitlab', 'GitLab', 'token', 'GitLab personal or project access token'],
  ['cloudflare', 'Cloudflare', 'token', 'Cloudflare API token'],
  ['google_cloud', 'Google Cloud', 'token', 'Google Cloud service account key or API token'],
  ['aws', 'Amazon Web Services', 'login', 'Access key ID and secret access key'],
  ['openai', 'OpenAI', 'token', 'OpenAI API key'],
  ['anthropic', 'Anthropic', 'token', 'Anthropic API key'],
  ['slack', 'Slack', 'token', 'Slack app or bot token'],
  ['notion', 'Notion', 'token', 'Notion integration token'],
  ['npm', 'npm', 'token', 'npm access token'],
  ['vercel', 'Vercel', 'token', 'Vercel access token'],
  ['sentry', 'Sentry', 'token', 'Sentry auth token'],
  ['stripe', 'Stripe', 'token', 'Stripe restricted or secret key'],
  ['linear', 'Linear', 'token', 'Linear API key'],
].map(([id, name, kind, credentialHint]) => Object.freeze({ id, name, kind, credentialHint })));
const SERVICE_ALIASES = Object.freeze({
  gh: 'github', 'github.com': 'github', gitlabcom: 'gitlab', 'gitlab.com': 'gitlab', cf: 'cloudflare', 'cloudflare.com': 'cloudflare',
  gcp: 'google_cloud', 'google cloud': 'google_cloud', aws: 'aws', 'amazon aws': 'aws',
  'open ai': 'openai', 'api.openai.com': 'openai', 'console.anthropic.com': 'anthropic',
});
function normalizeService(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
  const alias = SERVICE_ALIASES[normalized];
  if (alias) return alias;
  return SERVICE_CATALOG.some(service => service.id === normalized) ? normalized : null;
}
function getServiceTemplate(value) {
  const id = normalizeService(value);
  return SERVICE_CATALOG.find(service => service.id === id) || null;
}

const tools = [
  {
    name: 'service_catalog',
    description: 'List supported credential collection templates. For a known service, create a form using its canonical slug; the server chooses the credential fields. Never ask for a secret in chat. For an unknown service, ask only the missing non-secret connection details, then draft a minimal form spec and create it with explicit fields.',
    inputSchema: { type: 'object', additionalProperties: false, properties: {} },
    operation: API_OPERATIONS.wallet_form_create,
    local: true,
    handler: async () => ({ services: SERVICE_CATALOG.map(({ id, name, kind, credentialHint }) => ({ id, name, kind, credential_hint: credentialHint })), unknown_service_flow: 'draft_minimal_spec_then_create_with_explicit_fields' }),
  },
  {
    name: 'wallet_form_create',
    description: 'Create a ZeroCreds credential form for the current owner and profile. For a known service in service_catalog, pass its canonical provider slug only; omit kind and fields so the server chooses the safe default. Unknown services require a minimal explicit non-secret form spec. Ask the user only for required non-secret context (for example which GitHub account or what access is needed); never ask for or accept credential values in chat. Do not use service configuration APIs to satisfy a connection request. Returns one-time form URL and value-free metadata.',
    inputSchema: {
      type: 'object', additionalProperties: false,
      properties: {
        provider: { type: 'string', pattern: '^[a-z0-9][a-z0-9_-]{0,63}$', description: 'Use a canonical slug from service_catalog for known services. For an unknown service, use a normalized service slug only after preparing a minimal field spec and confirming its service label with the user.' },
        kind: { type: 'string', enum: ['token', 'ssh', 'login'], default: 'token' },
        title: { type: 'string', maxLength: 200 },
        description: { type: 'string', maxLength: 2000 },
        fields: { type: 'array', minItems: 1, items: { type: 'object', additionalProperties: false, required: ['name', 'label'], properties: {
          name: { type: 'string' }, label: { type: 'string' },
          type: { type: 'string', enum: ['text', 'password', 'email', 'tel', 'number', 'textarea', 'url'] },
          required: { type: 'boolean' },
        } } },
        ttl_minutes: { type: 'integer', minimum: 1, maximum: 1440 },
        idempotency_key: { type: 'string', pattern: '^[a-zA-Z0-9_-]{16,128}$' },
      }, required: ['provider'],
    },
    operation: API_OPERATIONS.wallet_form_create,
    method: 'POST', path: '/api/wallet/forms',
  },
  {
    name: 'wallet_form_status',
    description: 'Check whether a wallet form was completed. Returns status and non-secret metadata only.',
    inputSchema: { type: 'object', additionalProperties: false, properties: { form_id: { type: 'string', pattern: '^[a-f0-9]{32}$' } }, required: ['form_id'] },
    operation: API_OPERATIONS.wallet_form_status,
    method: 'GET', path: (args) => `/api/wallet/forms/${encodeURIComponent(args.form_id)}/status`,
  },
  {
    name: 'wallet_connection_status',
    description: 'Check a saved connection by ID after the form expires. Returns safe metadata only.',
    inputSchema: { type: 'object', additionalProperties: false, properties: { connection_id: { type: 'string', pattern: '^[a-zA-Z0-9_-]{1,100}$' } }, required: ['connection_id'] },
    operation: API_OPERATIONS.wallet_connection_status,
    method: 'GET', path: (args) => `/api/wallet/connections/${encodeURIComponent(args.connection_id)}`,
  },
  {
    name: 'wallet_connection_revoke',
    description: 'Revoke a saved connection when the user explicitly requests it. This does not return or erase credential values.',
    inputSchema: { type: 'object', additionalProperties: false, properties: { connection_id: { type: 'string', pattern: '^[a-zA-Z0-9_-]{1,100}$' } }, required: ['connection_id'] },
    operation: API_OPERATIONS.wallet_connection_revoke,
    method: 'POST', path: (args) => `/api/wallet/connections/${encodeURIComponent(args.connection_id)}/revoke`,
  },
];

function projectResponse(name, data, endpoint) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('ZeroCreds returned an invalid response');
  if (name === 'wallet_form_create') {
    if (!/^[a-f0-9]{32}$/.test(data.form_id || '') || !/^[a-zA-Z0-9_-]{1,100}$/.test(data.connection_id || '')
      || typeof data.url !== 'string' || typeof data.expires_at !== 'string'
      || !Number.isFinite(Date.parse(data.expires_at)) || Date.parse(data.expires_at) <= Date.now()
      || data.state !== undefined && data.state !== 'pending') throw new Error('ZeroCreds returned an invalid form response');
    let formUrl;
    try {
      const candidate = new URL(data.url);
      if (candidate.origin === new URL(endpoint).origin && candidate.pathname === `/f/${data.form_id}`
        && !candidate.username && !candidate.password && !candidate.search && !candidate.hash) formUrl = candidate.toString();
    } catch {}
    if (!formUrl) throw new Error('ZeroCreds returned an invalid form URL');
    let statusUrl;
    if (typeof data.status_url === 'string') {
      try {
        const candidate = new URL(data.status_url, endpoint);
        if (candidate.origin === new URL(endpoint).origin
          && candidate.pathname === `/api/wallet/forms/${data.form_id}/status`
          && !candidate.username && !candidate.password && !candidate.hash) statusUrl = candidate.toString();
      } catch {}
    }
    return { form_id: data.form_id, connection_id: data.connection_id, url: formUrl, expires_at: data.expires_at,
      ...(statusUrl ? { status_url: statusUrl } : {}),
      ...(typeof data.state === 'string' ? { state: data.state } : {}) };
  }
  if (name === 'wallet_form_status') {
    if (!/^[a-f0-9]{32}$/.test(data.form_id || '') || !/^[a-zA-Z0-9_-]{1,100}$/.test(data.connection_id || '')
      || !['pending', 'done', 'expired', 'revoked'].includes(data.status)) throw new Error('ZeroCreds returned an invalid form status');
    return { form_id: data.form_id, connection_id: data.connection_id, status: data.status,
      ...(Number.isSafeInteger(data.kv_version) ? { kv_version: data.kv_version } : {}),
      ...(typeof data.receipt_ref === 'string' ? { receipt_ref: data.receipt_ref } : {}) };
  }
  if (!/^[a-zA-Z0-9_-]{1,100}$/.test(data.connection_id || '') || !['allocated', 'active', 'revoked'].includes(data.state)) {
    throw new Error('ZeroCreds returned an invalid connection response');
  }
  if (name === 'wallet_connection_status') return {
    connection_id: data.connection_id,
    ...(typeof data.provider === 'string' ? { provider: data.provider } : {}),
    state: data.state,
    ...(Number.isSafeInteger(data.kv_version) ? { kv_version: data.kv_version } : {}),
    ...(Number.isSafeInteger(data.updated_at) ? { updated_at: data.updated_at } : {}),
  };
  return { connection_id: data.connection_id, state: data.state };
}

function createWalletProvider({ baseUrl, fetchImpl = globalThis.fetch, timeoutMs = 10_000 } = {}) {
  const endpoint = String(baseUrl || '').replace(/\/+$/, '');
  return {
    id: PROVIDER_ID,
    version: PROVIDER_VERSION,
    tools: tools.map((definition) => ({
      name: definition.name,
      description: definition.description,
      inputSchema: definition.inputSchema,
      requiredBindings: definition.local ? [] : [bindingForOperation(definition.operation)],
      providerId: PROVIDER_ID,
      handler: async (args, context = {}) => {
        if (definition.local) return definition.handler(args, context);
        let endpointUrl;
        try { endpointUrl = new URL(endpoint); } catch {}
        const localHttp = endpointUrl?.protocol === 'http:'
          && ['localhost', '127.0.0.1', '[::1]'].includes(endpointUrl.hostname);
        if (!endpointUrl || (endpointUrl.protocol !== 'https:' && !localHttp)
          || endpointUrl.username || endpointUrl.password || endpointUrl.search || endpointUrl.hash) {
          throw new Error('ZeroCreds wallet provider is not configured');
        }
        const assertion = context.bindings?.[bindingForOperation(definition.operation)];
        if (typeof assertion !== 'string' || !assertion) throw new Error('ZeroCreds wallet authorization is unavailable');
        if (typeof fetchImpl !== 'function') throw new Error('ZeroCreds wallet provider is not configured');
        const path = typeof definition.path === 'function' ? definition.path(args || {}) : definition.path;
        const signal = context.signal && typeof AbortSignal.any === 'function'
          ? AbortSignal.any([context.signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
        let response;
        try {
          response = await fetchImpl(`${endpointUrl.origin}${endpointUrl.pathname.replace(/\/$/, '')}${path}`, {
            method: definition.method,
            headers: { authorization: `Bearer ${assertion}`, ...(definition.method === 'POST' ? { 'content-type': 'application/json' } : {}) },
            ...(definition.method === 'POST' ? { body: JSON.stringify(definition.name === 'wallet_form_create' ? args : {}) } : {}),
            signal,
            redirect: 'error',
          });
        } catch {
          throw new Error('ZeroCreds wallet request failed');
        }
        let data;
        try { data = await response.json(); } catch { throw new Error('ZeroCreds returned an invalid response'); }
        if (!response.ok) throw new Error(response.status === 401 || response.status === 403
          ? 'ZeroCreds wallet authorization failed' : response.status === 404
            ? 'ZeroCreds wallet item is unavailable' : 'ZeroCreds wallet request failed');
        return projectResponse(definition.name, data, endpointUrl.toString());
      },
    })),
  };
}

module.exports = { createWalletProvider, PROVIDER_ID, PROVIDER_VERSION, BINDING, API_OPERATIONS, bindingForOperation, projectResponse, SERVICE_CATALOG, normalizeService, getServiceTemplate };
