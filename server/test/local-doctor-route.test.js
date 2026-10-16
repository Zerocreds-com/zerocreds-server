'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createApp } = require('../src/server');

function call(port, token) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: '/api/local/doctor', headers: {
      Host: '127.0.0.1', ...(token ? { Authorization: `Bearer ${token}` } : {}),
    } }, (res) => {
      let text = '';
      res.on('data', chunk => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(text) }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('local doctor route requires admin auth and returns a sanitized report', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-doctor-route-'));
  const adminToken = `local-doctor-admin-${'x'.repeat(32)}`;
  const helperPath = path.join(dir, 'helper');
  fs.writeFileSync(helperPath, '#!/bin/sh\nprintf \'{"status":"accessible"}\'\n', { mode: 0o700 });
  const destinationsFile = path.join(dir, 'destinations.json');
  fs.writeFileSync(destinationsFile, JSON.stringify({ 'mac-keychain': { type: 'macos_keychain' } }), { mode: 0o600 });
  const server = createApp({
    localMode: true, adminToken, baseUrl: 'http://127.0.0.1',
    keychainHelper: helperPath, defaultLocalDestination: 'mac-keychain', destinationsFile,
    localCatalogFile: path.join(dir, 'connections.json'),
    pendingDir: path.join(dir, 'pending'), tokensDir: path.join(dir, 'tokens'),
    signingKeyFile: path.join(dir, 'signing-key.pem'),
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    assert.equal((await call(server.address().port)).status, 401);
    const result = await call(server.address().port, adminToken);
    assert.equal(result.status, 200);
    assert.equal(result.body.overall, 'ok');
    assert.match(result.body.checks.find(check => check.name === 'server').detail, /ZeroCreds 0\.1\.0 \([0-9a-f]{12}\)/);
    assert.equal(result.body.catalog.connection_count, 0);
    assert.equal(result.body.credential_values_read, false);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
