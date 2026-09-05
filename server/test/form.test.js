'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startServer, request } = require('./helpers');

let ctx;
before(async () => { ctx = await startServer(); });
after(async () => { await ctx.stop(); });

const localDest = { type: 'local_file', uid: '99002', filename: 'form-test' };
const auth = () => ({ Authorization: `Bearer ${ctx.adminToken}` });

async function createSession(fields, dest) {
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'Form Test', fields: fields || [{ name: 'tok', label: 'Token' }], destination: dest || localDest },
    auth());
  assert.equal(r.status, 200);
  return r.body.token;
}

function expirePending(token) {
  const f = path.join(ctx.pendingDir, `${token}.json`);
  const d = JSON.parse(fs.readFileSync(f, 'utf8'));
  d.expires = Date.now() - 1000;
  fs.writeFileSync(f, JSON.stringify(d));
}

test('GET /f/:token — valid token → 200 HTML', async () => {
  const token = await createSession();
  const r = await request(ctx.port, 'GET', `/f/${token}`);
  assert.equal(r.status, 200);
  assert.ok(r.headers['content-type'].includes('text/html'));
  assert.ok(r.raw.includes('<form') || r.raw.includes('function submit'));
});

test('GET /f/:token — nonexistent token → 404', async () => {
  const r = await request(ctx.port, 'GET', `/f/${'a'.repeat(32)}`);
  assert.equal(r.status, 404);
});

test('GET /f/:token — expired token → 410', async () => {
  const token = await createSession();
  expirePending(token);
  const r = await request(ctx.port, 'GET', `/f/${token}`);
  assert.equal(r.status, 410);
});

test('POST /f/:token — all required fields → 200 { ok: true }', async () => {
  const token = await createSession([{ name: 'tok', label: 'Token', type: 'password' }]);
  const r = await request(ctx.port, 'POST', `/f/${token}`,
    { t: token, fields: { tok: 'secret-value' } });
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true);
});

test('POST /f/:token — missing required field → 400', async () => {
  const token = await createSession([
    { name: 'tok', label: 'Token' },
    { name: 'key', label: 'Key' },
  ]);
  const r = await request(ctx.port, 'POST', `/f/${token}`,
    { t: token, fields: { tok: 'value' } });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /missing required field/);
});

test('POST /f/:token — invalid URL in url-type field → 400', async () => {
  const token = await createSession([{ name: 'site', label: 'Site', type: 'url' }]);
  const r = await request(ctx.port, 'POST', `/f/${token}`,
    { t: token, fields: { site: 'not-a-url' } });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /invalid URL/);
});

test('POST /f/:token — second submission (token already used) → 403', async () => {
  const token = await createSession();
  await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { tok: 'val' } });
  const r = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { tok: 'val' } });
  assert.equal(r.status, 403);
});

test('POST /f/:token — token mismatch in body → 400', async () => {
  const token = await createSession();
  const r = await request(ctx.port, 'POST', `/f/${token}`,
    { t: 'a'.repeat(32), fields: { tok: 'val' } });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /token mismatch/);
});
