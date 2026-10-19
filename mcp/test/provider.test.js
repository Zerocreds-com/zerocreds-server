'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createWalletProvider, API_OPERATIONS, bindingForOperation, PROVIDER_ID, PROVIDER_VERSION, SERVICE_CATALOG, normalizeService, getServiceTemplate } = require('@zerocreds/mcp/provider');

const FORM_ID = 'a'.repeat(32);
const CONNECTION_ID = 'connection_123';
const assertion = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJ6ZXJvY3JlZHMtd2FsbGV0In0.signature';

test('Worker provider exports the four pinned tools and reuses the scoped API contract', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    const data = calls.length === 1
      ? { form_id: FORM_ID, connection_id: CONNECTION_ID, url: `https://wallet.example/f/${FORM_ID}`, expires_at: '2030-01-01T00:00:00.000Z', status_url: `/api/wallet/forms/${FORM_ID}/status`, owner_id: 'must-drop', token: 'must-drop' }
      : calls.length === 2
        ? { form_id: FORM_ID, connection_id: CONNECTION_ID, status: 'pending', owner_id: 'must-drop', value: 'must-drop' }
        : calls.length === 3
          ? { connection_id: CONNECTION_ID, provider: 'github', state: 'active', kv_version: 3, updated_at: 123, credential: 'must-drop' }
          : { connection_id: CONNECTION_ID, state: 'revoked', openbao_token: 'must-drop' };
    return new Response(JSON.stringify(data), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const provider = createWalletProvider({ baseUrl: 'https://wallet.example', fetchImpl });
  assert.equal(provider.id, PROVIDER_ID);
  assert.equal(provider.version, PROVIDER_VERSION);
  const byName = new Map(provider.tools.map(tool => [tool.name, tool]));
  assert.deepEqual([...byName.keys()], [
    'service_catalog',
    'wallet_form_create', 'wallet_form_status',
    'wallet_connection_status', 'wallet_connection_revoke',
  ]);
  assert.deepEqual(byName.get('service_catalog').requiredBindings, []);
  assert.ok(provider.tools.filter(tool => tool.name !== 'service_catalog').every(tool => tool.requiredBindings.length === 1
    && tool.requiredBindings[0].startsWith('zerocreds.wallet-api:')));
  const serviceCatalog = await byName.get('service_catalog').handler({});
  assert.equal(serviceCatalog.services.length, SERVICE_CATALOG.length);
  assert.equal(serviceCatalog.services.some(service => service.id === 'github'), true);
  assert.deepEqual(['github', 'gitlab', 'cloudflare'].map(getServiceTemplate), [
    { id: 'github', name: 'GitHub', kind: 'token', credentialHint: 'GitHub token / fine-grained personal access token' },
    { id: 'gitlab', name: 'GitLab', kind: 'token', credentialHint: 'GitLab personal or project access token' },
    { id: 'cloudflare', name: 'Cloudflare', kind: 'token', credentialHint: 'Cloudflare API token' },
  ]);
  assert.equal(normalizeService('https://github.com'), 'github');
  assert.equal(normalizeService('arbitrary.example'), null);
  const contextFor = name => ({ bindings: { [bindingForOperation(API_OPERATIONS[name])]: assertion }, signal: new AbortController().signal });
  const created = await byName.get('wallet_form_create').handler({ provider: 'github', kind: 'token' }, contextFor('wallet_form_create'));
  assert.deepEqual(created, { form_id: FORM_ID, connection_id: CONNECTION_ID,
    url: `https://wallet.example/f/${FORM_ID}`, expires_at: '2030-01-01T00:00:00.000Z',
    status_url: `https://wallet.example/api/wallet/forms/${FORM_ID}/status` });
  assert.deepEqual(await byName.get('wallet_form_status').handler({ form_id: FORM_ID }, contextFor('wallet_form_status')),
    { form_id: FORM_ID, connection_id: CONNECTION_ID, status: 'pending' });
  assert.deepEqual(await byName.get('wallet_connection_status').handler({ connection_id: CONNECTION_ID }, contextFor('wallet_connection_status')),
    { connection_id: CONNECTION_ID, provider: 'github', state: 'active', kv_version: 3, updated_at: 123 });
  assert.deepEqual(await byName.get('wallet_connection_revoke').handler({ connection_id: CONNECTION_ID }, contextFor('wallet_connection_revoke')),
    { connection_id: CONNECTION_ID, state: 'revoked' });
  assert.deepEqual(calls.map(call => [call.init.method, new URL(call.url).pathname]), [
    ['POST', '/api/wallet/forms'], ['GET', `/api/wallet/forms/${FORM_ID}/status`],
    ['GET', `/api/wallet/connections/${CONNECTION_ID}`], ['POST', `/api/wallet/connections/${CONNECTION_ID}/revoke`],
  ]);
  assert.ok(calls.every(call => call.init.headers.authorization === `Bearer ${assertion}`));
  assert.equal(JSON.stringify([created]).includes('must-drop'), false);
});

test('provider fails closed without a trusted binding and sanitizes upstream errors', async () => {
  let calls = 0;
  const tool = createWalletProvider({ baseUrl: 'https://wallet.example', fetchImpl: async () => {
    calls++;
    return new Response(JSON.stringify({ error: 'bearer=secret upstream detail' }), { status: 500 });
  } }).tools.find(item => item.name === 'wallet_form_create');
  const required = tool.requiredBindings[0];
  await assert.rejects(tool.handler({ provider: 'github' }, { bindings: {} }), /authorization is unavailable/);
  await assert.rejects(tool.handler({ provider: 'github' }, { bindings: { [required]: assertion } }), /request failed/);
  assert.equal(calls, 1);
});

test('service discovery is value-free and remains available without a wallet API binding', async () => {
  const provider = createWalletProvider({ baseUrl: '' });
  const tool = provider.tools.find(item => item.name === 'service_catalog');
  const result = await tool.handler({});
  assert.equal(result.services.some(service => service.id === 'github'), true);
  assert.equal(JSON.stringify(result).includes('token_value'), false);
  assert.equal(tool.requiredBindings.length, 0);
});

test('provider rejects unsafe endpoint configurations', async () => {
  const tool = createWalletProvider({ baseUrl: 'http://wallet.example' }).tools.find(item => item.name === 'wallet_form_create');
  await assert.rejects(tool.handler({}, { bindings: { [tool.requiredBindings[0]]: assertion } }), /not configured/);
});
