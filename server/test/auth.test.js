'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startServer, request } = require('./helpers');
const { createApp } = require('../src/server');

let ctx;
before(async () => { ctx = await startServer(); });
after(async () => { await ctx.stop(); });

const adminAuth = () => ({ Authorization: `Bearer ${ctx.adminToken}` });
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const localDest = { type: 'local_file', uid: '99005', filename: 'auth-test' };
const sessionBody = { title: 'T', fields: [{ name: 'tok', label: 'L' }], destination: localDest };

// The proxy-set X-Real-IP is trusted from loopback (the test client), so each test
// group gets its own address and rate-limit bucket.
let ipCounter = 1;
const freshIp = () => ({ 'X-Real-IP': `10.0.${Math.floor(ipCounter / 255)}.${ipCounter++ % 255}` });

async function register(email = 'test@example.com') {
  const r = await request(ctx.port, 'POST', '/api/register', { email, category: 'ai_agent' }, freshIp());
  assert.equal(r.status, 200);
  return r.body;
}

test('POST /api/register — valid email + category → 200, token pending approval', async () => {
  const body = await register();
  assert.ok(body.token, 'should return token');
  assert.ok(body.base_url, 'should return base_url');
  assert.equal(body.status, 'pending_approval');
});

test('POST /api/register — without email → 400', async () => {
  const r = await request(ctx.port, 'POST', '/api/register',
    { category: 'ai_agent' }, freshIp());
  assert.equal(r.status, 400);
});

test('POST /api/register — non-string email → 400 (no crash)', async () => {
  const r = await request(ctx.port, 'POST', '/api/register',
    { email: ['a@b'], category: 'ai_agent' }, freshIp());
  assert.equal(r.status, 400);
});

test('POST /api/register — invalid category → 400', async () => {
  const r = await request(ctx.port, 'POST', '/api/register',
    { email: 'x@example.com', category: 'hacker' }, freshIp());
  assert.equal(r.status, 400);
});

test('rate limit — 4th registration from same proxy-reported IP → 429', async () => {
  const ip = { 'X-Real-IP': '192.0.2.1' };
  for (let i = 0; i < 3; i++) {
    const r = await request(ctx.port, 'POST', '/api/register',
      { email: `user${i}@example.com`, category: 'personal' }, ip);
    assert.equal(r.status, 200, `attempt ${i + 1} should succeed`);
  }
  const r = await request(ctx.port, 'POST', '/api/register',
    { email: 'user4@example.com', category: 'personal' }, ip);
  assert.equal(r.status, 429);
});

test('rate limit — rotating X-Forwarded-For does not bypass the limit', async () => {
  const srv = await startServer();
  try {
    const statuses = [];
    for (let i = 0; i < 5; i++) {
      const r = await request(srv.port, 'POST', '/api/register',
        { email: `xff${i}@example.com`, category: 'personal' }, { 'X-Forwarded-For': `203.0.113.${i}` });
      statuses.push(r.status);
    }
    assert.deepEqual(statuses, [200, 200, 200, 429, 429]);
  } finally {
    await srv.stop();
  }
});

test('self-registered integrator cannot create sessions until approved', async () => {
  const { token, id } = await register('pending@example.com');
  const r1 = await request(ctx.port, 'POST', '/api/session/create', sessionBody, bearer(token));
  assert.equal(r1.status, 401);

  const approve = await request(ctx.port, 'POST', '/admin/integrators/approve', { id }, adminAuth());
  assert.equal(approve.status, 200);
  assert.equal(approve.body.status, 'active');

  const r2 = await request(ctx.port, 'POST', '/api/session/create',
    { ...sessionBody, destination: 'shared' }, bearer(token));
  // Authenticated now: fails only on the (unknown) destination, not on auth.
  assert.equal(r2.status, 400);
  assert.match(r2.body.error, /unknown named destination/);
});

test('approve endpoint requires the admin token', async () => {
  const { token, id } = await register('selfapprove@example.com');
  const r = await request(ctx.port, 'POST', '/admin/integrators/approve', { id }, bearer(token));
  assert.equal(r.status, 401);
});

test('legacy self-registered integrator record (email, no status) is inactive', async () => {
  const integrators = {
    tok_legacy_selfreg: { id: 'u_legacy', name: 'u_legacy', email: 'old@example.com', category: 'other', destinations: {} },
    tok_legacy_admin: { id: 'legacy-admin-made', name: 'Legacy', destinations: {} },
  };
  const srv = await startServer({ integrators });
  try {
    const selfReg = await request(srv.port, 'POST', '/api/session/create',
      { ...sessionBody, destination: 'x' }, bearer('tok_legacy_selfreg'));
    assert.equal(selfReg.status, 401);
    const adminMade = await request(srv.port, 'POST', '/api/session/create',
      { ...sessionBody, destination: 'x' }, bearer('tok_legacy_admin'));
    assert.equal(adminMade.status, 400, 'admin-created legacy integrator stays active');
  } finally {
    await srv.stop();
  }
});

test('Object.prototype property names are never accepted as tokens', async () => {
  for (const t of ['toString', 'constructor', '__proto__', 'hasOwnProperty', 'valueOf']) {
    const create = await request(ctx.port, 'POST', '/api/session/create', sessionBody, bearer(t));
    assert.equal(create.status, 401, `session create with "${t}"`);
    const dest = await request(ctx.port, 'POST', '/api/destinations',
      { name: 'x', destination: localDest }, bearer(t));
    assert.equal(dest.status, 401, `destinations with "${t}"`);
    const list = await request(ctx.port, 'GET', '/api/destinations', undefined, bearer(t));
    assert.equal(list.status, 401, `list destinations with "${t}"`);
    const status = await request(ctx.port, 'GET', `/api/session/${'c'.repeat(32)}/status`, undefined, bearer(t));
    assert.equal(status.status, 401, `status with "${t}"`);
  }
  const health = await request(ctx.port, 'GET', '/health');
  assert.equal(health.status, 200, 'server still up');
});

test('createApp refuses to start without an admin token', () => {
  const saved = process.env.ZEROCREDS_ADMIN_TOKEN;
  delete process.env.ZEROCREDS_ADMIN_TOKEN;
  try {
    assert.throws(() => createApp({ pendingDir: path.join(ctx.tmpDir, 'p2'), tokensDir: path.join(ctx.tmpDir, 't2') }),
      /ZEROCREDS_ADMIN_TOKEN is required/);
    assert.throws(() => createApp({ adminToken: '' }), /ZEROCREDS_ADMIN_TOKEN is required/);
  } finally {
    if (saved !== undefined) process.env.ZEROCREDS_ADMIN_TOKEN = saved;
  }
});

test('no Authorization → 401 on session create', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create', sessionBody);
  assert.equal(r.status, 401);
});

test('POST /admin/integrators/create — admin → 200 { token, id, name }, active immediately', async () => {
  const r = await request(ctx.port, 'POST', '/admin/integrators/create',
    { id: 'test-int', name: 'Test Integrator' }, adminAuth());
  assert.equal(r.status, 200);
  assert.ok(r.body.token);
  assert.equal(r.body.id, 'test-int');
  assert.equal(r.body.name, 'Test Integrator');
  const dup = await request(ctx.port, 'POST', '/admin/integrators/create',
    { id: 'test-int', name: 'Dup' }, adminAuth());
  assert.equal(dup.status, 409);
});

test('admin endpoint with integrator token → 401', async () => {
  const createR = await request(ctx.port, 'POST', '/admin/integrators/create',
    { id: 'nonadmin', name: 'x' }, adminAuth());
  const r = await request(ctx.port, 'POST', '/admin/integrators/create',
    { id: 'x', name: 'x' }, bearer(createR.body.token));
  assert.equal(r.status, 401);
});

test('admin assigns a destination to an integrator; integrator local_file writes are scoped to it', async () => {
  const createR = await request(ctx.port, 'POST', '/admin/integrators/create',
    { id: 'scoped-int', name: 'Scoped' }, adminAuth());
  const intToken = createR.body.token;

  const destR = await request(ctx.port, 'POST', '/api/destinations',
    { name: 'my-store', destination: { type: 'local_file', uid: '99005', filename: 'scoped' }, integrator_id: 'scoped-int' },
    adminAuth());
  assert.equal(destR.status, 200);

  const sessionR = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L' }], destination: 'my-store' }, bearer(intToken));
  assert.equal(sessionR.status, 200);
  const token = sessionR.body.token;
  const submit = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { tok: 'v' } });
  assert.equal(submit.status, 200);

  assert.ok(fs.existsSync(path.join(ctx.tokensDir, '_integrators', 'scoped-int', '99005', 'scoped')),
    'written under the integrator subtree');
  assert.ok(!fs.existsSync(path.join(ctx.tokensDir, '99005', 'scoped')), 'not in the shared uid directory');
});

test('integrator cannot add server-local destinations itself, nor use inline local_file', async () => {
  const createR = await request(ctx.port, 'POST', '/admin/integrators/create',
    { id: 'no-local', name: 'NoLocal' }, adminAuth());
  const intToken = createR.body.token;

  const destR = await request(ctx.port, 'POST', '/api/destinations',
    { name: 'mine', destination: localDest }, bearer(intToken));
  assert.equal(destR.status, 403);

  const inline = await request(ctx.port, 'POST', '/api/session/create', sessionBody, bearer(intToken));
  assert.equal(inline.status, 400);
  assert.match(inline.body.error, /only available to the admin/);
});

test('reserved destination names are rejected', async () => {
  const r = await request(ctx.port, 'POST', '/api/destinations',
    { name: '__proto__', destination: localDest }, adminAuth());
  assert.equal(r.status, 400);
});

test('status — integrator cannot read another integrator\'s session', async () => {
  const a = await request(ctx.port, 'POST', '/admin/integrators/create', { id: 'owner-a', name: 'A' }, adminAuth());
  const b = await request(ctx.port, 'POST', '/admin/integrators/create', { id: 'owner-b', name: 'B' }, adminAuth());
  await request(ctx.port, 'POST', '/api/destinations',
    { name: 'a-store', destination: { type: 'local_file', uid: '1', filename: 'a' }, integrator_id: 'owner-a' }, adminAuth());
  const s = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L' }], destination: 'a-store' }, bearer(a.body.token));
  assert.equal(s.status, 200);
  const token = s.body.token;

  const own = await request(ctx.port, 'GET', `/api/session/${token}/status`, undefined, bearer(a.body.token));
  assert.equal(own.body.status, 'pending');
  const other = await request(ctx.port, 'GET', `/api/session/${token}/status`, undefined, bearer(b.body.token));
  assert.equal(other.body.status, 'expired', 'looks like an unknown token');

  await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { tok: 'v' } });
  const ownDone = await request(ctx.port, 'GET', `/api/session/${token}/status`, undefined, bearer(a.body.token));
  assert.equal(ownDone.body.status, 'done');
  assert.equal(ownDone.body._integrator_id, undefined, 'internal owner field is not exposed');
  const otherDone = await request(ctx.port, 'GET', `/api/session/${token}/status`, undefined, bearer(b.body.token));
  assert.equal(otherDone.body.status, 'expired');
  assert.equal(otherDone.body.secret_id, undefined);
});
