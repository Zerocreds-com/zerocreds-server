'use strict';

const PROVIDER_ID = 'zerocreds-wallet';
const PROVIDER_VERSION = '1.0.0';
const BINDING = 'zerocreds.wallet-api';
function bindingForOperation(operation) { return `${BINDING}:${operation}`; }
const API_OPERATIONS = Object.freeze({
  zerocreds_wallet_form_create: 'wallet.forms.create',
  zerocreds_wallet_form_status: 'wallet.forms.status',
  zerocreds_wallet_connection_status: 'wallet.connections.status',
  zerocreds_wallet_connection_revoke: 'wallet.connections.revoke',
});

const tools = [
  {
    name: 'zerocreds_wallet_form_create',
    description: 'Request a credential form for the current owner and profile. Returns a one-time form URL and value-free connection metadata. The caller cannot select an owner, profile, or storage destination.',
    inputSchema: {
      type: 'object', additionalProperties: false,
      properties: {
        provider: { type: 'string', pattern: '^[a-z0-9][a-z0-9_-]{0,63}$', description: 'Service slug, for example github or tilda.' },
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
    operation: API_OPERATIONS.zerocreds_wallet_form_create,
    method: 'POST', path: '/api/wallet/forms',
  },
  {
    name: 'zerocreds_wallet_form_status',
    description: 'Check whether a wallet form was completed. Returns status and non-secret metadata only.',
    inputSchema: { type: 'object', additionalProperties: false, properties: { form_id: { type: 'string', pattern: '^[a-f0-9]{32}$' } }, required: ['form_id'] },
    operation: API_OPERATIONS.zerocreds_wallet_form_status,
    method: 'GET', path: (args) => `/api/wallet/forms/${encodeURIComponent(args.form_id)}/status`,
  },
  {
    name: 'zerocreds_wallet_connection_status',
    description: 'Check a saved connection by ID after the form expires. Returns safe metadata only.',
    inputSchema: { type: 'object', additionalProperties: false, properties: { connection_id: { type: 'string', pattern: '^[a-zA-Z0-9_-]{1,100}$' } }, required: ['connection_id'] },
    operation: API_OPERATIONS.zerocreds_wallet_connection_status,
    method: 'GET', path: (args) => `/api/wallet/connections/${encodeURIComponent(args.connection_id)}`,
  },
  {
    name: 'zerocreds_wallet_connection_revoke',
    description: 'Revoke a saved connection when the user explicitly requests it. This does not return or erase credential values.',
    inputSchema: { type: 'object', additionalProperties: false, properties: { connection_id: { type: 'string', pattern: '^[a-zA-Z0-9_-]{1,100}$' } }, required: ['connection_id'] },
    operation: API_OPERATIONS.zerocreds_wallet_connection_revoke,
    method: 'POST', path: (args) => `/api/wallet/connections/${encodeURIComponent(args.connection_id)}/revoke`,
  },
];

function projectResponse(name, data, endpoint) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('ZeroCreds returned an invalid response');
  if (name === 'zerocreds_wallet_form_create') {
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
  if (name === 'zerocreds_wallet_form_status') {
    if (!/^[a-f0-9]{32}$/.test(data.form_id || '') || !/^[a-zA-Z0-9_-]{1,100}$/.test(data.connection_id || '')
      || !['pending', 'done', 'expired', 'revoked'].includes(data.status)) throw new Error('ZeroCreds returned an invalid form status');
    return { form_id: data.form_id, connection_id: data.connection_id, status: data.status,
      ...(Number.isSafeInteger(data.kv_version) ? { kv_version: data.kv_version } : {}),
      ...(typeof data.receipt_ref === 'string' ? { receipt_ref: data.receipt_ref } : {}) };
  }
  if (!/^[a-zA-Z0-9_-]{1,100}$/.test(data.connection_id || '') || !['allocated', 'active', 'revoked'].includes(data.state)) {
    throw new Error('ZeroCreds returned an invalid connection response');
  }
  if (name === 'zerocreds_wallet_connection_status') return {
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
      requiredBindings: [bindingForOperation(definition.operation)],
      providerId: PROVIDER_ID,
      handler: async (args, context = {}) => {
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
            ...(definition.method === 'POST' ? { body: JSON.stringify(definition.name === 'zerocreds_wallet_form_create' ? args : {}) } : {}),
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

module.exports = { createWalletProvider, PROVIDER_ID, PROVIDER_VERSION, BINDING, API_OPERATIONS, bindingForOperation, projectResponse };
