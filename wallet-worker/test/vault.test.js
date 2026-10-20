import { env } from 'cloudflare:test';
import { test, expect } from 'vitest';
import worker from '../src/index.js';

const serviceToken = 'test-service-token-with-at-least-thirty-two-characters';
const owner = () => `owner_${crypto.randomUUID().replaceAll('-', '')}`;
const ciphertext = 'Zm9vYmFyYmF6cXV4';
const iv = 'aXZpdml2MTIzNDU2Nzg5';
const tag = 'dGFnMTIzNDU2Nzg5YWJjZGVm';

async function call(path, body, options = {}) {
  const method = options.method || 'POST';
  const headers = { authorization: `Bearer ${options.token ?? serviceToken}`,
    ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...options.headers };
  const response = await worker.fetch(new Request(`https://wallet.test${path}`, {
    method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }), { ...env, WALLET_SERVICE_TOKEN: serviceToken });
  return { status: response.status, body: await response.json() };
}

async function allocate(ownerId, profileId = 'profile_a') {
  const response = await call('/internal/connections/allocate', { owner_id: ownerId, profile_id: profileId,
    provider: 'github', idempotency_key: `request_${crypto.randomUUID().replaceAll('-', '')}` });
  return response.body;
}

function valueBody(ownerId, profileId = 'profile_a') {
  return { owner_id: ownerId, profile_id: profileId, provider: 'github',
    ciphertext, iv, tag, alg: 'A256GCM', key_ref: 'k1' };
}

test('a stored value is versioned, scoped and never handed back', async () => {
  const ownerId = owner();
  const connection = await allocate(ownerId);
  const first = await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId), { method: 'PUT' });
  expect(first.status).toBe(200);
  expect(first.body.version).toBe(1);
  expect(first.body.key_ref).toBe('k1');
  expect(JSON.stringify(first.body)).not.toContain(ciphertext);

  const second = await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId), { method: 'PUT' });
  expect(second.body.version).toBe(2);

  const row = await env.VAULT_DB.prepare('SELECT * FROM credential_values WHERE connection_id = ? ORDER BY version')
    .bind(connection.connection_id).all();
  expect(row.results).toHaveLength(2);
  expect(row.results[0].ciphertext).toBe(ciphertext);
  expect(row.results[0].revoked_at).toBeNull();

  const status = await call(`/internal/vault/values/${connection.connection_id}`, undefined,
    { method: 'GET', headers: { 'x-wallet-owner': ownerId, 'x-wallet-profile': 'profile_a' } });
  expect(status.status).toBe(200);
  expect(status.body.state).toBe('active');
  expect(status.body.version).toBe(2);
  expect(JSON.stringify(status.body)).not.toContain(ciphertext);
  expect(Object.keys(status.body).sort()).toEqual(['connection_id', 'state', 'updated_at', 'version']);
  expect(JSON.stringify(status.body)).not.toContain(iv);
  expect(JSON.stringify(status.body)).not.toContain(tag);
});

test('a value cannot be read or written outside its owner and profile', async () => {
  const ownerId = owner();
  const connection = await allocate(ownerId);
  await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId), { method: 'PUT' });

  const foreign = await call(`/internal/vault/values/${connection.connection_id}`, undefined,
    { method: 'GET', headers: { 'x-wallet-owner': owner(), 'x-wallet-profile': 'profile_a' } });
  expect(foreign.body.state).toBe('missing');

  const wrongProfile = await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId, 'profile_b'), { method: 'PUT' });
  expect(wrongProfile.status).toBe(404);

  const noScope = await call(`/internal/vault/values/${connection.connection_id}`, undefined, { method: 'GET' });
  expect(noScope.status).toBe(400);
});

test('a revoked connection refuses new values and the value is destroyed', async () => {
  const ownerId = owner();
  const connection = await allocate(ownerId);
  await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId), { method: 'PUT' });

  const revoked = await call(`/internal/connections/${connection.connection_id}/revoke`,
    { owner_id: ownerId, profile_id: 'profile_a' });
  expect(revoked.status).toBe(200);

  const refused = await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId), { method: 'PUT' });
  expect(refused.status).toBe(409);

  const destroyed = await call(`/internal/vault/values/${connection.connection_id}/revoke`,
    { owner_id: ownerId, profile_id: 'profile_a' });
  expect(destroyed.status).toBe(200);
  expect(destroyed.body.versions_revoked).toBe(1);
  const rows = await env.VAULT_DB.prepare('SELECT COUNT(*) AS n FROM credential_values WHERE connection_id = ?')
    .bind(connection.connection_id).first();
  expect(rows.n).toBe(0);
  const events = await env.VAULT_DB.prepare('SELECT action FROM credential_events WHERE connection_id = ?')
    .bind(connection.connection_id).all();
  expect(events.results.map((row) => row.action)).toEqual(['created', 'revoked']);
});

test('custody routes need the service token and reject malformed values', async () => {
  const ownerId = owner();
  const connection = await allocate(ownerId);
  expect((await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId), { method: 'PUT', token: 'wrong' })).status).toBe(401);
  expect((await call(`/internal/vault/values/${connection.connection_id}`,
    { ...valueBody(ownerId), alg: 'plain' }, { method: 'PUT' })).status).toBe(400);
  expect((await call(`/internal/vault/values/${connection.connection_id}`,
    { ...valueBody(ownerId), ciphertext: 'not base64!!' }, { method: 'PUT' })).status).toBe(400);
  expect((await call(`/internal/vault/values/does-not-exist`, valueBody(ownerId), { method: 'PUT' })).status).toBe(404);
});
