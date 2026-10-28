'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const { createApp } = require('../src/server');

async function freePort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

function call(port, method, route, body, token) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? '' : JSON.stringify(body);
    const req = http.request({ hostname: '127.0.0.1', port, path: route, method, headers: {
      ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    } }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(raw) }));
    });
    req.once('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function seedCatalog(file, overrides = {}) {
  fs.writeFileSync(file, JSON.stringify([{
    connection_id: 'connection-1', provider: 'github', account_alias: 'work',
    storage: 'keychain:github-work', state: 'active', credential_expires_at: null,
    verification_status: 'unknown', created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    ...overrides,
  }]));
}

async function withLocalServer(run, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-auth-check-'));
  const port = await freePort();
  const token = 'local-test-token-' + 'x'.repeat(40);
  const catalogFile = path.join(root, 'connections.json');
  seedCatalog(catalogFile, options.entry);
  const app = createApp({
    adminToken: token,
    localMode: true,
    baseUrl: `http://127.0.0.1:${port}`,
    localCatalogFile: catalogFile,
    localDiscoveryCatalogFile: path.join(root, 'discovery-catalog.json'),
    localCredentialDiscovery: async () => ({ sources: [], candidates: [] }),
    localCredentialReader: options.reader || (async () => ({ token: 'must-never-escape-test-secret' })),
    localCredentialVerifier: options.verifier || (async () => ({ status: 'valid', identity: { id: '123', login: 'octocat' },
      permissions: ['repo'], permission_evidence: 'provider_verified' })),
    pendingDir: path.join(root, 'pending'),
    tokensDir: path.join(root, 'tokens'),
    destinationsFile: path.join(root, 'destinations.json'),
    integratorsFile: path.join(root, 'integrators.json'),
    signingKeyFile: path.join(root, 'signing-key.pem'),
  });
  await new Promise((resolve, reject) => { app.once('error', reject); app.listen(port, '127.0.0.1', resolve); });
  try { await run({ port, token, catalogFile }); }
  finally {
    await new Promise((resolve) => app.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('auth_check requires admin auth', async () => {
  await withLocalServer(async ({ port }) => {
    const denied = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' });
    assert.equal(denied.status, 401);
  });
});

test('auth_check validates provider and account_alias', async () => {
  await withLocalServer(async ({ port, token }) => {
    const bad = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'GitHub!', account_alias: 'work' }, token);
    assert.equal(bad.status, 400);
    const missing = await call(port, 'POST', '/api/local/auth/check', {}, token);
    assert.equal(missing.status, 400);
  });
});

test('auth_check returns live identity and permissions without writing the catalog', async () => {
  await withLocalServer(async ({ port, token, catalogFile }) => {
    const before = fs.readFileSync(catalogFile, 'utf8');
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(result.status, 200);
    assert.equal(result.body.connection_id, 'connection-1');
    assert.equal(result.body.live.status, 'valid');
    assert.deepEqual(result.body.live.identity, { id: '123', login: 'octocat' });
    assert.deepEqual(result.body.live.permissions, ['repo']);
    assert.deepEqual(result.body.conflicts, []);
    assert.equal(result.body.catalog_written, false);
    assert.equal(result.body.credential_values_read, true);
    assert.ok(result.body.checked_at);
    // Read-only: the catalog on disk is byte-identical afterwards.
    assert.equal(fs.readFileSync(catalogFile, 'utf8'), before);
    const text = JSON.stringify(result.body);
    assert.ok(!text.includes('must-never-escape-test-secret'));
  });
});

test('auth_check reports identity mismatch when the token resolves elsewhere', async () => {
  await withLocalServer(async ({ port, token }) => {
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(result.status, 200);
    assert.equal(result.body.live.status, 'valid');
    const kinds = result.body.conflicts.map((c) => c.kind);
    assert.ok(kinds.includes('identity_mismatch'), `expected identity_mismatch, got ${kinds.join(',')}`);
    assert.deepEqual(result.body.conflicts.find((c) => c.kind === 'identity_mismatch').live_identity,
      { id: '123', login: 'octocat' });
  }, {
    entry: { verification_status: 'valid', verified_identity: { id: '999', login: 'someone-else' },
      verified_permissions: ['repo'], permission_evidence: 'provider_verified' },
  });
});

test('auth_check reports permissions drift only with provider evidence on both sides', async () => {
  await withLocalServer(async ({ port, token }) => {
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(result.status, 200);
    const drift = result.body.conflicts.find((c) => c.kind === 'permissions_changed');
    assert.ok(drift, 'permissions_changed conflict expected');
    assert.deepEqual(drift.recorded_permissions, ['admin']);
    assert.deepEqual(drift.live_permissions, ['repo']);
  }, {
    entry: { verification_status: 'valid', verified_identity: { id: '123', login: 'octocat' },
      verified_permissions: ['admin'], permission_evidence: 'provider_verified' },
  });
});

test('auth_check does not claim permission drift without provider evidence', async () => {
  await withLocalServer(async ({ port, token }) => {
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.conflicts, []);
  }, {
    entry: { verification_status: 'unknown', verified_permissions: ['admin'], permission_evidence: 'unknown' },
  });
});

test('auth_check reports status drift when the catalog and the provider disagree', async () => {
  await withLocalServer(async ({ port, token }) => {
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(result.status, 200);
    const drift = result.body.conflicts.find((c) => c.kind === 'status_drift');
    assert.ok(drift, 'status_drift conflict expected');
    assert.match(drift.detail, /verification_status=invalid but the provider now answers valid/);
  }, {
    entry: { verification_status: 'invalid', verified_identity: { id: '123', login: 'octocat' } },
  });
});

test('auth_check reports a locally revoked connection without consulting the provider', async () => {
  await withLocalServer(async ({ port, token, catalogFile }) => {
    const before = fs.readFileSync(catalogFile, 'utf8');
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.conflicts.map((c) => c.kind), ['revoked_locally']);
    assert.equal(result.body.live, null);
    assert.equal(result.body.credential_values_read, false);
    assert.equal(fs.readFileSync(catalogFile, 'utf8'), before);
  }, { entry: { state: 'revoked' } });
});

test('auth_check reports an expired credential without contacting the provider', async () => {
  await withLocalServer(async ({ port, token }) => {
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.conflicts.map((c) => c.kind), ['credential_expired']);
    assert.equal(result.body.live, null);
    assert.equal(result.body.credential_values_read, false);
  }, { entry: { credential_expires_at: '2020-01-01T00:00:00.000Z' } });
});

test('auth_check reports an unreadable Keychain instead of failing', async () => {
  await withLocalServer(async ({ port, token }) => {
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(result.status, 200);
    assert.equal(result.body.live.status, 'keychain_locked');
    assert.deepEqual(result.body.conflicts.map((c) => c.kind), ['credential_unreadable']);
    assert.equal(result.body.credential_values_read, false);
  }, { reader: async () => { throw new Error('keychain_locked'); } });
});

test('auth_check surfaces a rejected token as provider_rejected_token', async () => {
  await withLocalServer(async ({ port, token, catalogFile }) => {
    const before = fs.readFileSync(catalogFile, 'utf8');
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(result.status, 200);
    assert.equal(result.body.live.status, 'invalid');
    assert.deepEqual(result.body.conflicts.map((c) => c.kind), ['provider_rejected_token']);
    // Still read-only even when the outcome is bad news.
    assert.equal(fs.readFileSync(catalogFile, 'utf8'), before);
  }, { verifier: async () => ({ status: 'invalid' }) });
});

test('auth_check marks inconclusive verification without calling the token invalid', async () => {
  await withLocalServer(async ({ port, token }) => {
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.conflicts.map((c) => c.kind), ['verification_inconclusive']);
    assert.equal(result.body.live.status, 'unavailable');
  }, { verifier: async () => ({ status: 'unavailable' }) });
});

test('auth_check reports a missing token field with a recovery hint', async () => {
  await withLocalServer(async ({ port, token }) => {
    const result = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work', token_field: 'renamed_field' }, token);
    assert.equal(result.status, 200);
    const conflict = result.body.conflicts.find((c) => c.kind === 'token_field_missing');
    assert.ok(conflict, 'token_field_missing conflict expected');
    assert.match(conflict.next_step, /rerun auth_check with token_field/);
  }, { verifier: async () => ({ status: 'credential_field_missing' }) });
});

test('auth_check returns 404 for an unknown connection and 409 when ambiguous', async () => {
  await withLocalServer(async ({ port, token, catalogFile }) => {
    const missing = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'nope' }, token);
    assert.equal(missing.status, 404);

    fs.writeFileSync(catalogFile, JSON.stringify([
      { connection_id: 'connection-1', provider: 'github', account_alias: 'work',
        storage: 'keychain:github-work', state: 'active', credential_expires_at: null },
      { connection_id: 'connection-2', provider: 'github', account_alias: 'work',
        storage: 'keychain:github-work-2', state: 'active', credential_expires_at: null },
    ]));
    const ambiguous = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(ambiguous.status, 409);
    assert.deepEqual(ambiguous.body.connection_ids, ['connection-1', 'connection-2']);
  });
});

test('auth_check rejects an account_id that is not a Cloudflare account id', async () => {
  await withLocalServer(async ({ port, token }) => {
    const wrong = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'cloudflare', account_alias: 'work', account_id: 'nope' }, token);
    assert.equal(wrong.status, 400);
    const wrongProvider = await call(port, 'POST', '/api/local/auth/check',
      { provider: 'github', account_alias: 'work', account_id: 'a'.repeat(32) }, token);
    assert.equal(wrongProvider.status, 400);
  });
});
