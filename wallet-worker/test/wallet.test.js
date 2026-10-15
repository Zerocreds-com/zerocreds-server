import { env } from 'cloudflare:test';
import { test, expect } from 'vitest';
import worker from '../src/index.js';

const serviceToken = 'test-service-token-with-at-least-thirty-two-characters';
const owner = () => `owner_${crypto.randomUUID().replaceAll('-', '')}`;
const sha = 'a'.repeat(64);
const formId = () => crypto.randomUUID().replaceAll('-', '');
async function call(path, body, options = {}) {
  const method = options.method || 'POST';
  const headers = { authorization: `Bearer ${options.token ?? serviceToken}`,
    ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...options.headers };
  const response = await worker.fetch(new Request(`https://wallet.test${path}`, {
    method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }), { ...env, WALLET_SERVICE_TOKEN: serviceToken });
  return { status: response.status, body: await response.json() };
}
async function allocate(ownerId, profileId = 'profile_a', key = `request_${crypto.randomUUID().replaceAll('-', '')}`) {
  return call('/internal/connections/allocate', { owner_id: ownerId, profile_id: profileId,
    provider: 'github', idempotency_key: key });
}

test('service authentication is mandatory and no shared token means fail closed', async () => {
  const denied = await call('/internal/connections/allocate', {}, { token: 'wrong' });
  expect(denied.status).toBe(401);
  const response = await worker.fetch(new Request('https://wallet.test/internal/connections/allocate', {
    method: 'POST', headers: { authorization: `Bearer ${serviceToken}` }, body: '{}',
  }), { ...env, WALLET_SERVICE_TOKEN: '' });
  expect(response.status).toBe(503);
  expect((await call('/internal/connections/allocate', { owner_id: 123, profile_id: 'profile_a',
    provider: 'github', idempotency_key: 'long_enough_request_key_123' })).status).toBe(400);
  const oversize = await worker.fetch(new Request('https://wallet.test/internal/connections/allocate', {
    method: 'POST', headers: { authorization: `Bearer ${serviceToken}` },
    body: JSON.stringify({ owner_id: 'x'.repeat(5000) }),
  }), { ...env, WALLET_SERVICE_TOKEN: serviceToken });
  expect(oversize.status).toBe(400);
});

test('allocation is idempotent and derives an owner-scoped OpenBao path', async () => {
  const ownerId = owner();
  const key = `request_${crypto.randomUUID().replaceAll('-', '')}`;
  const first = await allocate(ownerId, 'profile_a', key);
  expect(first.status).toBe(200);
  expect(first.body.openbao_path).toBe(`${env.OPENBAO_MOUNT}/data/owners/${ownerId}/connections/${first.body.connection_id}`);
  expect((await allocate(ownerId, 'profile_a', key)).body.connection_id).toBe(first.body.connection_id);
  expect((await allocate(ownerId, 'profile_b', key)).status).toBe(409);
  expect((await call('/internal/connections/allocate', { owner_id: ownerId, profile_id: 'profile_a',
    provider: 'github', idempotency_key: `request_${crypto.randomUUID().replaceAll('-', '')}`,
    openbao_path: 'evil/data/owners/other/connections/x' })).status).toBe(400);
  const raw = await env.DB.prepare('SELECT * FROM wallet_connections WHERE connection_id = ?')
    .bind(first.body.connection_id).first();
  expect(Object.keys(raw)).not.toContain('secret_value');
  expect(raw.request_key_hash).not.toBe(key);
});

test('form completion is owner/profile-bound, one-time, value-free and revocable', async () => {
  const ownerId = owner();
  const allocated = await allocate(ownerId);
  const conn = allocated.body.connection_id;
  const id = formId();
  const registration = { form_id: id, connection_id: conn, owner_id: ownerId,
    profile_id: 'profile_a', manifest_id: sha, expires_at: Date.now() + 60_000 };
  expect((await call('/internal/forms', registration)).status).toBe(200);
  expect((await call('/internal/forms', registration)).status).toBe(200);
  expect((await call('/internal/forms', { ...registration, manifest_id: 'b'.repeat(64) })).status).toBe(409);
  const wrongOwner = await call(`/internal/forms/${id}/complete`, {
    owner_id: owner(), profile_id: 'profile_a', manifest_id: sha, kv_version: 1, receipt_ref: 'c'.repeat(64),
  });
  expect(wrongOwner.status).toBe(404);
  const completion = { owner_id: ownerId, profile_id: 'profile_a', manifest_id: sha,
    kv_version: 1, receipt_ref: 'c'.repeat(64) };
  const done = await call(`/internal/forms/${id}/complete`, completion);
  expect(done.status).toBe(200);
  expect((await call(`/internal/forms/${id}/complete`, completion)).status).toBe(200);
  expect((await call(`/internal/forms/${id}/complete`, { ...completion, kv_version: 2 })).status).toBe(409);
  const laterForm = formId();
  expect((await call('/internal/forms', { ...registration, form_id: laterForm })).status).toBe(200);
  expect((await call(`/internal/forms/${laterForm}/complete`, completion)).status).toBe(409);
  const unchanged = await env.DB.prepare('SELECT state FROM wallet_forms WHERE form_id = ?').bind(laterForm).first();
  expect(unchanged.state).toBe('pending');
  const status = await call(`/internal/connections/${conn}`, undefined, { method: 'GET',
    headers: { 'x-wallet-owner': ownerId, 'x-wallet-profile': 'profile_a' } });
  expect(status.body.state).toBe('active');
  expect(status.body.kv_version).toBe(1);
  expect((await call(`/internal/connections/${conn}`, undefined, { method: 'GET',
    headers: { 'x-wallet-owner': ownerId, 'x-wallet-profile': 'profile_b' } })).status).toBe(404);
  expect((await call(`/internal/connections/${conn}/revoke`, { owner_id: ownerId, profile_id: 'profile_a' })).status).toBe(200);
  expect((await call(`/internal/connections/${conn}`, undefined, { method: 'GET',
    headers: { 'x-wallet-owner': ownerId, 'x-wallet-profile': 'profile_a' } })).body.state).toBe('revoked');
  const rows = await env.DB.prepare('SELECT * FROM wallet_forms WHERE form_id = ?').bind(id).all();
  expect(rows.results[0].receipt_ref).toBe(completion.receipt_ref);
  expect(JSON.stringify(rows.results)).not.toContain('real-secret');
});

test('revocation before completion blocks an already issued form', async () => {
  const ownerId = owner();
  const conn = (await allocate(ownerId)).body.connection_id;
  const id = formId();
  expect((await call('/internal/forms', { form_id: id, connection_id: conn, owner_id: ownerId,
    profile_id: 'profile_a', manifest_id: sha, expires_at: Date.now() + 60_000 })).status).toBe(200);
  expect((await call(`/internal/connections/${conn}/revoke`, { owner_id: ownerId, profile_id: 'profile_a' })).status).toBe(200);
  expect((await call(`/internal/forms/${id}/complete`, { owner_id: ownerId, profile_id: 'profile_a',
    manifest_id: sha, kv_version: 1, receipt_ref: 'c'.repeat(64) })).status).toBe(409);
});
