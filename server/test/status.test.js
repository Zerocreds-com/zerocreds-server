'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startServer, request } = require('./helpers');

let ctx;
before(async () => { ctx = await startServer(); });
after(async () => { await ctx.stop(); });

const localDest = { type: 'local_file', uid: '99003', filename: 'status-test' };
const auth = () => ({ Authorization: `Bearer ${ctx.adminToken}` });

async function createSession(fields, dest, destByLevel) {
  const body = {
    title: 'Status Test',
    fields: fields || [{ name: 'tok', label: 'Token' }],
  };
  if (destByLevel) body.destinations_by_level = destByLevel;
  else body.destination = dest || localDest;

  const r = await request(ctx.port, 'POST', '/api/session/create', body, auth());
  assert.equal(r.status, 200);
  return r.body.token;
}

async function submitForm(token, fields) {
  return request(ctx.port, 'POST', `/f/${token}`,
    { t: token, fields: fields || { tok: 'secret-value' } });
}

test('pending session → { status: "pending" }', async () => {
  const token = await createSession();
  const r = await request(ctx.port, 'GET', `/api/session/${token}/status`, undefined, auth());
  assert.equal(r.status, 200);
  assert.equal(r.body.status, 'pending');
});

test('after form submission → { status: "done" }', async () => {
  const token = await createSession();
  await submitForm(token);
  const r = await request(ctx.port, 'GET', `/api/session/${token}/status`, undefined, auth());
  assert.equal(r.status, 200);
  assert.equal(r.body.status, 'done');
});

test('nonexistent token → { status: "expired" }', async () => {
  const r = await request(ctx.port, 'GET', `/api/session/${'b'.repeat(32)}/status`, undefined, auth());
  assert.equal(r.status, 200);
  assert.equal(r.body.status, 'expired');
});

test('expired pending file → { status: "expired" }', async () => {
  const token = await createSession();
  const f = path.join(ctx.pendingDir, `${token}.json`);
  const d = JSON.parse(fs.readFileSync(f, 'utf8'));
  d.expires = Date.now() - 1000;
  fs.writeFileSync(f, JSON.stringify(d));
  const r = await request(ctx.port, 'GET', `/api/session/${token}/status`, undefined, auth());
  assert.equal(r.status, 200);
  assert.equal(r.body.status, 'expired');
});

test('done with single destination → has secret_id', async () => {
  const token = await createSession();
  await submitForm(token);
  const r = await request(ctx.port, 'GET', `/api/session/${token}/status`, undefined, auth());
  assert.equal(r.body.status, 'done');
  assert.ok(r.body.secret_id, 'expected secret_id in done response');
});

test('done with destinations_by_level → has secret_ids', async () => {
  const destA = { type: 'local_file', uid: '99003', filename: 'status-secret' };
  const destB = { type: 'local_file', uid: '99003', filename: 'status-pii' };
  const token = await createSession(
    [
      { name: 'apikey', label: 'API Key', level: 'secret' },
      { name: 'email', label: 'Email', level: 'pii' },
    ],
    null,
    { secret: destA, pii: destB },
  );
  await submitForm(token, { apikey: 'key123', email: 'user@example.com' });
  const r = await request(ctx.port, 'GET', `/api/session/${token}/status`, undefined, auth());
  assert.equal(r.body.status, 'done');
  assert.ok(r.body.secret_ids, 'expected secret_ids in done response');
  assert.ok(r.body.secret_ids.secret);
  assert.ok(r.body.secret_ids.pii);
});
