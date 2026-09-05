'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { startServer, request } = require('./helpers');

let ctx;
before(async () => { ctx = await startServer(); });
after(async () => { await ctx.stop(); });

const auth = () => ({ Authorization: `Bearer ${ctx.adminToken}` });

function tokenDir(uid) { return path.join(ctx.tokensDir, String(uid)); }

async function createAndSubmit(fields, dest, destByLevel) {
  const body = { title: 'T', fields };
  if (destByLevel) body.destinations_by_level = destByLevel;
  else body.destination = dest;
  const r1 = await request(ctx.port, 'POST', '/api/session/create', body, auth());
  assert.equal(r1.status, 200);
  const token = r1.body.token;
  const submitted = {};
  for (const f of fields) submitted[f.name] = f.name + '-value';
  const r2 = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: submitted });
  return { createRes: r1.body, submitRes: r2, token };
}

function startMockServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () =>
      resolve({ port: srv.address().port, close: () => new Promise(r => srv.close(r)) }),
    );
  });
}

test('local_file — single destination → file written with fields', async () => {
  const uid = '88001';
  const dest = { type: 'local_file', uid, filename: 'creds' };
  const { submitRes } = await createAndSubmit(
    [{ name: 'tok', label: 'Token' }], dest);
  assert.equal(submitRes.status, 200);
  const written = JSON.parse(fs.readFileSync(path.join(tokenDir(uid), 'creds'), 'utf8'));
  assert.ok(written.tok || written.value, 'file should contain the submitted field');
});

test('destinations_by_level — secret+pii → two separate files', async () => {
  const uid = '88002';
  const destSecret = { type: 'local_file', uid, filename: 'creds-secret' };
  const destPii    = { type: 'local_file', uid, filename: 'creds-pii' };
  const { submitRes } = await createAndSubmit(
    [
      { name: 'apikey', label: 'API Key', level: 'secret' },
      { name: 'email',  label: 'Email',   level: 'pii' },
    ],
    null,
    { secret: destSecret, pii: destPii },
  );
  assert.equal(submitRes.status, 200);
  assert.ok(fs.existsSync(path.join(tokenDir(uid), 'creds-secret')));
  assert.ok(fs.existsSync(path.join(tokenDir(uid), 'creds-pii')));
  const secretData = JSON.parse(fs.readFileSync(path.join(tokenDir(uid), 'creds-secret'), 'utf8'));
  const piiData    = JSON.parse(fs.readFileSync(path.join(tokenDir(uid), 'creds-pii'), 'utf8'));
  assert.ok(secretData.apikey !== undefined || secretData.value !== undefined);
  assert.ok(piiData.email !== undefined || piiData.value !== undefined);
});

test('field without level → falls back to "default" in destinations_by_level', async () => {
  const uid = '88003';
  const destDefault = { type: 'local_file', uid, filename: 'creds-default' };
  const { submitRes } = await createAndSubmit(
    [{ name: 'tok', label: 'Token' }], // no level → groups as "default"
    null,
    { default: destDefault },
  );
  assert.equal(submitRes.status, 200);
  assert.ok(fs.existsSync(path.join(tokenDir(uid), 'creds-default')));
});

test('field without level, no default, no destination → warns but does not crash → 200', async () => {
  // destinations_by_level exists but has no "default" key and no fallback destination
  const uid = '88004';
  const destSecret = { type: 'local_file', uid, filename: 'creds-secret' };
  // Field has no level → key = "default", but destinations_by_level has no "default"
  const { submitRes } = await createAndSubmit(
    [{ name: 'tok', label: 'Token' }], // no level → "default"
    null,
    { secret: destSecret }, // no "default" key
  );
  // Should still return 200 — it just skips the field
  assert.equal(submitRes.status, 200);
});

test('http_post — upstream returns 200 → form submission succeeds', async () => {
  let receivedBody;
  const mock = await startMockServer((req, res) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      receivedBody = JSON.parse(data);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
  });

  try {
    const dest = { type: 'http_post', url: `http://127.0.0.1:${mock.port}/collect` };
    const { submitRes } = await createAndSubmit(
      [{ name: 'tok', label: 'Token' }], dest);
    assert.equal(submitRes.status, 200);
    assert.equal(submitRes.body.ok, true);
    assert.equal(receivedBody?.tok, 'tok-value');
  } finally {
    await mock.close();
  }
});

test('http_post — upstream returns 500 → form submission fails with 500', async () => {
  const mock = await startMockServer((req, res) => {
    req.resume();
    res.writeHead(500).end('Internal Error');
  });

  try {
    const dest = { type: 'http_post', url: `http://127.0.0.1:${mock.port}/collect` };
    const { submitRes } = await createAndSubmit(
      [{ name: 'tok', label: 'Token' }], dest);
    assert.equal(submitRes.status, 500);
  } finally {
    await mock.close();
  }
});
