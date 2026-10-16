'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createApp } = require('../src/server');

function call(port, token, method, route, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? '' : JSON.stringify(body);
    const req = http.request({ hostname: '127.0.0.1', port, method, path: route, headers: {
      Host: '127.0.0.1', ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
    } }, (res) => {
      let text = '';
      res.on('data', chunk => { text += chunk; });
      res.on('end', () => {
        let parsed = null;
        if (res.headers['content-type']?.includes('application/json') && text) parsed = JSON.parse(text);
        resolve({ status: res.statusCode, body: parsed, text });
      });
    });
    req.on('error', reject);
    req.end(data);
  });
}

test('local playground runs only fixed synthetic scenarios and validates rules', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-playground-'));
  const token = `local-playground-admin-${'x'.repeat(32)}`;
  const server = createApp({ localMode: true, adminToken: token, baseUrl: 'http://127.0.0.1',
    pendingDir: path.join(dir, 'pending'), tokensDir: path.join(dir, 'tokens'),
    destinationsFile: path.join(dir, 'destinations.json'), signingKeyFile: path.join(dir, 'key.pem'),
    localCatalogFile: path.join(dir, 'catalog.json') });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    assert.equal((await call(port, '', 'GET', '/api/local/playground/scenarios')).status, 401);
    const listed = await call(port, token, 'GET', '/api/local/playground/scenarios');
    assert.equal(listed.status, 200);
    assert.equal(listed.body.mode, 'synthetic_only');
    const run = await call(port, token, 'POST', '/api/local/playground/run', {
      rules: [{ type: 'matches', pattern: '^PLAYGROUND_SYNTHETIC_VALID_' }],
      scenarios: ['valid', 'invalid'],
    });
    assert.equal(run.status, 200);
    assert.deepEqual(run.body.results.map(item => item.matched_expectation), [true, true]);
    assert.equal(run.text.includes('7f3a'), false);
    assert.equal((await call(port, token, 'POST', '/api/local/playground/run', {
      rules: [{ type: 'matches', pattern: '(a+)+$' }],
    })).status, 400);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('playground form warns, evaluates in memory, discards submitted value, and stores status only', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-playground-form-'));
  const token = `local-playground-form-admin-${'x'.repeat(32)}`;
  const pendingDir = path.join(dir, 'pending');
  const server = createApp({ localMode: true, adminToken: token, baseUrl: 'http://127.0.0.1',
    pendingDir, tokensDir: path.join(dir, 'tokens'), destinationsFile: path.join(dir, 'destinations.json'),
    signingKeyFile: path.join(dir, 'key.pem'), localCatalogFile: path.join(dir, 'catalog.json') });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const synthetic = 'PLAYGROUND_SYNTHETIC_VALID_7f3a';
  try {
    const created = await call(port, token, 'POST', '/api/local/playground/forms', {
      rules: [{ type: 'matches', pattern: '^PLAYGROUND_SYNTHETIC_VALID_' }],
    });
    assert.equal(created.status, 200, created.text);
    assert.equal(created.status, 200);
    assert.match(created.body.warning, /DO NOT ENTER REAL CREDENTIALS/);
    const form = await call(port, '', 'GET', `/f/${created.body.token}`);
    assert.equal(form.status, 200, form.text.slice(0, 400));
    assert.match(form.text, /TEST PLAYGROUND — DO NOT ENTER REAL CREDENTIALS/);
    assert.match(form.text, /rules in memory, then discarded/);
    const submitted = await call(port, '', 'POST', `/f/${created.body.token}`, {
      t: created.body.token, fields: { synthetic_value: synthetic },
    });
    assert.equal(submitted.status, 200, submitted.text);
    assert.equal(submitted.body.value_returned, false);
    const done = fs.readFileSync(path.join(pendingDir, `${created.body.token}.done`), 'utf8');
    assert.equal(done.includes(synthetic), false);
    assert.equal(done.includes('PLAYGROUND_SYNTHETIC'), false);
    assert.equal(JSON.parse(done).playground_test, true);
    const failedCreate = await call(port, token, 'POST', '/api/local/playground/forms', {
      rules: [{ type: 'matches', pattern: '^PLAYGROUND_SYNTHETIC_VALID_' }],
    });
    assert.equal(failedCreate.status, 200, failedCreate.text);
    const failed = await call(port, '', 'POST', `/f/${failedCreate.body.token}`, {
      t: failedCreate.body.token, fields: { synthetic_value: 'not-a-match' },
    });
    assert.equal(failed.status, 422);
    assert.equal(failed.text.includes('not-a-match'), false);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
