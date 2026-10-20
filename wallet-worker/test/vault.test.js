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

test('a stored value is versioned, scoped and the metadata read never hands it back', async () => {
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

test('a run-scoped read hands the ciphertext back and records the run', async () => {
  const ownerId = owner();
  const connection = await allocate(ownerId);
  await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId), { method: 'PUT' });

  const runRef = 'run_2b1c0f6d9a4e_9f4e2a1b';
  const read = await call(`/internal/vault/values/${connection.connection_id}/read`,
    { owner_id: ownerId, profile_id: 'profile_a', run_id: runRef });
  expect(read.status).toBe(200);
  expect(read.body.ciphertext).toBe(ciphertext);
  expect(read.body.iv).toBe(iv);
  expect(read.body.tag).toBe(tag);
  expect(read.body.alg).toBe('A256GCM');
  expect(read.body.version).toBe(1);

  const events = await env.VAULT_DB.prepare('SELECT action, actor FROM credential_events WHERE connection_id = ? ORDER BY event_id')
    .bind(connection.connection_id).all();
  expect(events.results.map((row) => [row.action, row.actor]))
    .toEqual([['created', 'wallet'], ['granted', runRef]]);

  // A read has to name the run it is for, and a foreign scope learns nothing.
  expect((await call(`/internal/vault/values/${connection.connection_id}/read`,
    { owner_id: ownerId, profile_id: 'profile_a' })).status).toBe(400);
  expect((await call(`/internal/vault/values/${connection.connection_id}/read`,
    { owner_id: owner(), profile_id: 'profile_a', run_id: runRef })).status).toBe(404);

  // A revoked value is gone: the read fails closed.
  await call(`/internal/vault/values/${connection.connection_id}/revoke`, { owner_id: ownerId, profile_id: 'profile_a' });
  expect((await call(`/internal/vault/values/${connection.connection_id}/read`,
    { owner_id: ownerId, profile_id: 'profile_a', run_id: runRef })).status).toBe(404);
});

test("a run's grant is recorded once, however many times the run asks", async () => {
  const ownerId = owner();
  const connection = await allocate(ownerId);
  await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId), { method: 'PUT' });

  const runRef = 'run_5c3e1a77b0d4_1a2b3c4d';
  const read = (run) => call(`/internal/vault/values/${connection.connection_id}/read`,
    { owner_id: ownerId, profile_id: 'profile_a', run_id: run });
  const granted = async () => {
    const events = await env.VAULT_DB.prepare(`SELECT actor, version FROM credential_events
      WHERE connection_id = ? AND action = 'granted' ORDER BY event_id`).bind(connection.connection_id).all();
    return events.results;
  };

  const first = await read(runRef);
  expect(first.status).toBe(200);
  expect(first.body.replay).toBe(false);
  expect(first.body.ciphertext).toBe(ciphertext);

  // The same run asking again is the same grant — a retry, a cut-over to
  // another worker, a replacement host after the previous one died. The value
  // is still answered, because the run needs it to work, but the journal does
  // not grow and the host is told it is a replay.
  const again = await read(runRef);
  expect(again.status).toBe(200);
  expect(again.body.ciphertext).toBe(ciphertext);
  expect(again.body.version).toBe(1);
  expect(again.body.replay).toBe(true);
  expect(await granted()).toHaveLength(1);

  // Another run is another grant.
  const other = await read('run_6d4f2b88c1e5_2b3c4d5e');
  expect(other.status).toBe(200);
  expect(other.body.replay).toBe(false);
  expect(await granted()).toHaveLength(2);

  // A rotated value is a genuinely different grant: the run consumes a
  // different value, and the journal has to say so.
  await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId), { method: 'PUT' });
  const rotated = await read(runRef);
  expect(rotated.status).toBe(200);
  expect(rotated.body.version).toBe(2);
  expect(rotated.body.replay).toBe(false);
  const events = await granted();
  expect(events).toHaveLength(3);
  expect(events.map((row) => row.version)).toEqual([1, 1, 2]);
});

test('a value without a lease keeps working, and a lease is recorded on the value and in the journal', async () => {
  const ownerId = owner();
  const connection = await allocate(ownerId);
  const noLease = await call(`/internal/vault/values/${connection.connection_id}`, valueBody(ownerId), { method: 'PUT' });
  expect(noLease.status).toBe(200);
  expect(noLease.body.lease_expires_at).toBeNull();

  const runRef = 'run_7a1b2c3d4e5f_6a7b8c9d';
  const read = await call(`/internal/vault/values/${connection.connection_id}/read`,
    { owner_id: ownerId, profile_id: 'profile_a', run_id: runRef });
  expect(read.status).toBe(200);
  expect(read.body.lease_expires_at).toBeNull();

  // A value with a lease records the lease on the value itself, so the grant
  // path can refuse it later without asking anybody.
  const leaseStart = Date.now();
  const leaseEnd = leaseStart + 3_600_000;
  const leased = await call(`/internal/vault/values/${connection.connection_id}`,
    { ...valueBody(ownerId), lease_started_at: leaseStart, lease_expires_at: leaseEnd }, { method: 'PUT' });
  expect(leased.status).toBe(200);
  expect(leased.body.lease_expires_at).toBe(leaseEnd);
  const row = await env.VAULT_DB.prepare('SELECT lease_started_at, lease_expires_at FROM credential_values WHERE connection_id = ? AND version = ?')
    .bind(connection.connection_id, leased.body.version).first();
  expect(row.lease_started_at).toBe(leaseStart);
  expect(row.lease_expires_at).toBe(leaseEnd);

  // The journal keeps the lease with the grant, so "the value was handed out
  // under a lease that ended" stays answerable after the fact. The journal is
  // keyed by version as well: the first grant answered the unleased version,
  // the second answered the leased one, and each says which it was.
  const grant = await call(`/internal/vault/values/${connection.connection_id}/read`,
    { owner_id: ownerId, profile_id: 'profile_a', run_id: runRef });
  expect(grant.status).toBe(200);
  expect(grant.body.lease_expires_at).toBe(leaseEnd);
  const events = await env.VAULT_DB.prepare(`SELECT version, lease_expires_at FROM credential_events
    WHERE connection_id = ? AND action = 'granted' AND actor = ? ORDER BY version`).bind(connection.connection_id, runRef).all();
  expect(events.results).toHaveLength(2);
  expect(events.results[0].version).toBe(1);
  expect(events.results[0].lease_expires_at).toBeNull();
  expect(events.results[1].version).toBe(2);
  expect(events.results[1].lease_expires_at).toBe(leaseEnd);
});

test('an expired lease refuses the grant and says so without the value', async () => {
  const ownerId = owner();
  const connection = await allocate(ownerId);
  const now = Date.now();
  await call(`/internal/vault/values/${connection.connection_id}`,
    { ...valueBody(ownerId), lease_started_at: now - 7_200_000, lease_expires_at: now - 3_600_000 }, { method: 'PUT' });

  const read = await call(`/internal/vault/values/${connection.connection_id}/read`,
    { owner_id: ownerId, profile_id: 'profile_a', run_id: 'run_8b2c3d4e5f6a_7b8c9d0e' });
  expect(read.status).toBe(409);
  expect(read.body.error).toBe('lease_expired');
  expect(typeof read.body.lease_expires_at).toBe('string');
  // The refusal names the lease and never the value.
  expect(JSON.stringify(read.body)).not.toContain(ciphertext);
  expect(JSON.stringify(read.body)).not.toContain(iv);
  expect(JSON.stringify(read.body)).not.toContain(tag);

  // A refused grant is not a grant: the journal must not record one.
  const events = await env.VAULT_DB.prepare(`SELECT action FROM credential_events
    WHERE connection_id = ? AND action = 'granted'`).bind(connection.connection_id).all();
  expect(events.results).toHaveLength(0);
});

test('the lease boundary is exact: valid before the end, refused at and after it', async () => {
  const ownerId = owner();
  const connection = await allocate(ownerId);
  const end = Date.now() + 60_000;
  await call(`/internal/vault/values/${connection.connection_id}`,
    { ...valueBody(ownerId), lease_started_at: Date.now(), lease_expires_at: end }, { method: 'PUT' });
  const read = (run) => call(`/internal/vault/values/${connection.connection_id}/read`,
    { owner_id: ownerId, profile_id: 'profile_a', run_id: run });

  // Before the end the value is still handed out.
  const before = await read('run_9c3d4e5f6a7b_8c9d0e1f');
  expect(before.status).toBe(200);
  expect(before.body.ciphertext).toBe(ciphertext);

  // At the end the lease is over: the end instant itself is expired.
  const atEnd = await env.VAULT_DB.prepare(`SELECT version FROM credential_values WHERE connection_id = ? AND version = 1`)
    .bind(connection.connection_id).first();
  expect(atEnd.version).toBe(1);
  await env.VAULT_DB.prepare('UPDATE credential_values SET lease_expires_at = ? WHERE connection_id = ? AND version = 1')
    .bind(Date.now(), connection.connection_id).run();
  const expired = await read('run_0d4e5f6a7b8c_9d0e1f2a');
  expect(expired.status).toBe(409);
  expect(expired.body.error).toBe('lease_expired');

  // A lease that ends before it starts is refused at write time, not stored.
  const bad = await call(`/internal/vault/values/${connection.connection_id}`,
    { ...valueBody(ownerId), lease_started_at: Date.now(), lease_expires_at: Date.now() - 1 }, { method: 'PUT' });
  expect(bad.status).toBe(400);
  expect(bad.body.error).toBe('invalid_lease');
  const unreadable = await call(`/internal/vault/values/${connection.connection_id}`,
    { ...valueBody(ownerId), lease_expires_at: 'not-a-time' }, { method: 'PUT' });
  expect(unreadable.status).toBe(400);
  expect(unreadable.body.error).toBe('invalid_lease');
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
