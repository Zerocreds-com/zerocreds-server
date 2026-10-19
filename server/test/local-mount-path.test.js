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

function parseJson(raw) {
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function call(port, method, route, body, token) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? '' : JSON.stringify(body);
    const req = http.request({ hostname: '127.0.0.1', port, path: route, method, agent: false, headers: {
      ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    } }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => resolve({
        status: res.statusCode,
        body: parseJson(raw),
        raw,
      }));
    });
    req.once('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function withMountedServer(run, mountPath) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-mount-path-'));
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
    baseUrl: `http://127.0.0.1:${port}${mountPath}`,
    localCatalogFile: catalogFile,
    localProviderPolicies: { github: {
      login_url: 'https://github.com/login', auth_url: 'https://github.com/settings/profile',
      username_selector: '#login_field', password_selector: '#password',
      submit_selector: 'button[type=submit]', success_selector: '#signed-in',
      username_field: 'username', password_field: 'password',
    } },
    pendingDir: path.join(root, 'pending'),
    tokensDir: path.join(root, 'tokens'),
    destinationsFile: path.join(root, 'destinations.json'),
    integratorsFile: path.join(root, 'integrators.json'),
    signingKeyFile: path.join(root, 'signing-key.pem'),
  });
  await new Promise((resolve, reject) => { app.once('error', reject); app.listen(port, '127.0.0.1', resolve); });
  try { await run({ port, token }); }
  finally {
    await new Promise((resolve) => app.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('a mounted base path routes identically to the bare path', async () => {
  await withMountedServer(async ({ port, token }) => {
    const mounted = await call(port, 'GET', '/zerocreds/api/local/connections', undefined, token);
    const bare = await call(port, 'GET', '/api/local/connections', undefined, token);
    assert.equal(mounted.status, 200);
    assert.equal(bare.status, 200);
    assert.deepEqual(mounted.body, bare.body);

    const health = await call(port, 'GET', '/zerocreds/health');
    assert.equal(health.status, 200);
    assert.equal(health.body.ok, true);
  }, '/zerocreds');
});

test('a mounted base path keeps the prefix out of the bare routes', async () => {
  await withMountedServer(async ({ port }) => {
    const unknown = await call(port, 'GET', '/zerocreds/api/local/nope');
    assert.equal(unknown.status, 404);
  }, '/zerocreds');
});

test('generated links carry the mount prefix', async () => {
  await withMountedServer(async ({ port, token }) => {
    const grant = await call(port, 'POST', '/zerocreds/api/local/broker/grants', {
      provider: 'github', account_alias: 'work', run_id: '11111111-2222-3333-4444-555555555555',
    }, token);
    assert.equal(grant.status, 200);
    assert.equal(grant.body.broker_url, `http://127.0.0.1:${port}/zerocreds/api/local/broker/redeem`);
  }, '/zerocreds');
});

test('the about page shows the address the deployment actually uses', async () => {
  await withMountedServer(async ({ port }) => {
    const about = await call(port, 'GET', '/about');
    assert.equal(about.status, 200);
    assert.ok(about.raw.includes(`http://127.0.0.1:${port}/zerocreds`), 'the configured base URL is rendered');
    assert.ok(!about.raw.includes('localhost:3456'), 'the hardcoded address is gone');
  }, '/zerocreds');
});
