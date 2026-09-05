'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer, request } = require('./helpers');

let ctx;
before(async () => { ctx = await startServer(); });
after(async () => { await ctx.stop(); });

const localDest = { type: 'local_file', uid: '99001', filename: 'session-test' };
const auth = () => ({ Authorization: `Bearer ${ctx.adminToken}` });

test('valid request with destination → 200 + token/url/expires_at', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'Test', fields: [{ name: 'tok', label: 'Token' }], destination: localDest },
    auth());
  assert.equal(r.status, 200);
  assert.ok(r.body.token);
  assert.ok(r.body.url);
  assert.ok(r.body.expires_at);
});

test('valid request with destinations_by_level → 200', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L', level: 'secret' }],
      destinations_by_level: { secret: localDest } },
    auth());
  assert.equal(r.status, 200);
  assert.ok(r.body.token);
});

test('both destination + destinations_by_level → 200', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L' }],
      destination: localDest, destinations_by_level: { default: localDest } },
    auth());
  assert.equal(r.status, 200);
});

test('missing destination and destinations_by_level → 400', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L' }] },
    auth());
  assert.equal(r.status, 400);
});

test('invalid field name (space) → 400', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'a b', label: 'L' }], destination: localDest },
    auth());
  assert.equal(r.status, 400);
});

test('invalid field type → 400', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L', type: 'select' }], destination: localDest },
    auth());
  assert.equal(r.status, 400);
});

test('invalid field level → 400', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L', level: 'top_secret' }], destination: localDest },
    auth());
  assert.equal(r.status, 400);
});

test('unknown named destination → 400 with message', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L' }], destination: 'nonexistent' },
    auth());
  assert.equal(r.status, 400);
  assert.match(r.body.error, /unknown named destination/);
});

test('no Authorization → 401', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L' }], destination: localDest });
  assert.equal(r.status, 401);
});

test('ttl_minutes > 1440 clamped — expires_at ≤ now + 1440 min', async () => {
  const before = Date.now();
  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L' }], destination: localDest, ttl_minutes: 9999 },
    auth());
  assert.equal(r.status, 200);
  const exp = new Date(r.body.expires_at).getTime();
  const maxAllowed = before + 1440 * 60 * 1000 + 5000; // +5s tolerance
  assert.ok(exp <= maxAllowed, `expires_at ${r.body.expires_at} should be ≤ now + 1440 min`);
});
