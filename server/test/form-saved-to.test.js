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
    const req = http.request({ hostname: '127.0.0.1', port, path: route, method, agent: false, headers: {
      ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    } }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => resolve({
        status: res.statusCode,
        body: raw ? (() => { try { return JSON.parse(raw); } catch { return null; } })() : null,
        raw,
      }));
    });
    req.once('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function withLocalServer(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-saved-to-'));
  const port = await freePort();
  const token = 'local-test-token-' + 'x'.repeat(40);
  const destinationsFile = path.join(root, 'destinations.json');
  fs.writeFileSync(destinationsFile, JSON.stringify({
    'mac-keychain': { type: 'macos_keychain', service: 'zerocreds', account: 'github-work' },
  }));
  const app = createApp({
    adminToken: token,
    localMode: true,
    baseUrl: `http://127.0.0.1:${port}/zerocreds`,
    localCatalogFile: path.join(root, 'connections.json'),
    pendingDir: path.join(root, 'pending'),
    tokensDir: path.join(root, 'tokens'),
    destinationsFile,
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

async function createForm(port, token, destination, extra = {}) {
  const created = await call(port, 'POST', '/api/session/create', {
    title: 'GitHub token',
    description: 'Paste the token',
    fields: [{ name: 'token', label: 'GitHub fine-grained PAT', level: 'secret' }],
    destination,
    ...extra,
  }, token);
  assert.equal(created.status, 200, JSON.stringify(created.body));
  const form = await call(port, 'GET', `/f/${created.body.token}`);
  assert.equal(form.status, 200);
  return form.raw;
}

test('the confirmation names the store and the item the value was written to', async () => {
  await withLocalServer(async ({ port, token }) => {
    const html = await createForm(port, token, 'mac-keychain');
    assert.ok(html.includes('id="zc-saved-to"'), 'the confirmation repeats the destination');
    assert.ok(html.includes('Saved to'), 'the row is labelled');
    assert.ok(html.includes('macOS Keychain on this Mac'), 'the store is named for the local case');
    assert.ok(html.includes('zerocreds/github-work'), 'the keychain item is named');
    assert.ok(!html.includes('not stored'), 'the destination is not reported as missing');
  });
});

test('the confirmation does not show a destination for a playground form', async () => {
  await withLocalServer(async ({ port, token }) => {
    const created = await call(port, 'POST', '/api/local/playground/forms', {
      title: 'ZeroCreds credential playground', rules: [{ type: 'matches', pattern: '^PLAYGROUND_SYNTHETIC_VALID_' }],
    }, token);
    assert.equal(created.status, 200, JSON.stringify(created.body));
    const form = await call(port, 'GET', `/f/${created.body.token}`);
    assert.equal(form.status, 200);
    assert.ok(form.raw.includes('Nothing was saved.'), 'the playground keeps its own wording');
    assert.ok(!form.raw.includes('id="zc-saved-to"'), 'nothing was stored, so nothing is named');
  });
});

test('the destination is named before the submit as well', async () => {
  await withLocalServer(async ({ port, token }) => {
    const html = await createForm(port, token, 'mac-keychain');
    assert.ok(html.includes('Sent to'), 'the form view names the destination before the submit');
    assert.ok(html.includes('macOS Keychain on this Mac'), 'the store is named for the local case');
  });
});
