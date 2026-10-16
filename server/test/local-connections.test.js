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

async function withLocalServer(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-local-catalog-'));
  const port = await freePort();
  const token = 'local-test-token-' + 'x'.repeat(40);
  const catalogFile = path.join(root, 'connections.json');
  fs.writeFileSync(catalogFile, JSON.stringify([{
    connection_id: 'connection-1', provider: 'github', account_alias: 'work',
    storage: 'keychain:github-work', state: 'active', credential_expires_at: null,
    verification_status: 'unknown', created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
  }]));
  const app = createApp({
    adminToken: token,
    localMode: true,
    baseUrl: `http://127.0.0.1:${port}`,
    localCatalogFile: catalogFile,
    pendingDir: path.join(root, 'pending'),
    tokensDir: path.join(root, 'tokens'),
    destinationsFile: path.join(root, 'destinations.json'),
    integratorsFile: path.join(root, 'integrators.json'),
    signingKeyFile: path.join(root, 'signing-key.pem'),
    localCredentialReader: async () => ({ token: 'must-never-escape-test-secret' }),
    localCredentialVerifier: async () => ({ status: 'valid', identity: { id: '123', login: 'octocat' },
      permissions: ['repo'], permission_evidence: 'provider_verified' }),
  });
  await new Promise((resolve, reject) => { app.once('error', reject); app.listen(port, '127.0.0.1', resolve); });
  try { await run({ port, token, catalogFile }); }
  finally {
    await new Promise((resolve) => app.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('local verification requires admin auth and persists only value-free provider evidence', async () => {
  await withLocalServer(async ({ port, token }) => {
    const denied = await call(port, 'POST', '/api/local/connections/verify', { provider: 'github', account_alias: 'work' });
    assert.equal(denied.status, 401);
    const verified = await call(port, 'POST', '/api/local/connections/verify',
      { provider: 'github', account_alias: 'work' }, token);
    assert.equal(verified.status, 200);
    assert.equal(verified.body.verification, 'valid');
    assert.deepEqual(verified.body.identity, { id: '123', login: 'octocat' });
    assert.deepEqual(verified.body.permissions, ['repo']);
    assert.ok(!JSON.stringify(verified.body).includes('must-never-escape-test-secret'));

    const list = await call(port, 'GET', '/api/local/connections', undefined, token);
    assert.equal(list.status, 200);
    assert.equal(list.body.connections[0].verification_status, 'valid');
    assert.deepEqual(list.body.connections[0].verified_permissions, ['repo']);
    assert.ok(list.body.connections[0].last_verified_at);
  });
});
