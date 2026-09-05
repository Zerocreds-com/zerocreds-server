'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer, request } = require('./helpers');

let ctx;
before(async () => { ctx = await startServer(); });
after(async () => { await ctx.stop(); });

const adminAuth = () => ({ Authorization: `Bearer ${ctx.adminToken}` });
const localDest = { type: 'local_file', uid: '99005', filename: 'auth-test' };

// Use unique fake IPs per test group to avoid polluting each other's rate-limit counters
let ipCounter = 1;
const freshIp = () => ({ 'X-Forwarded-For': `10.0.${Math.floor(ipCounter / 255)}.${ipCounter++ % 255}` });

test('POST /api/register — valid email + category → 200 { token, base_url }', async () => {
  const r = await request(ctx.port, 'POST', '/api/register',
    { email: 'test@example.com', category: 'ai_agent' }, freshIp());
  assert.equal(r.status, 200);
  assert.ok(r.body.token, 'should return token');
  assert.ok(r.body.base_url, 'should return base_url');
});

test('POST /api/register — without email → 400', async () => {
  const r = await request(ctx.port, 'POST', '/api/register',
    { category: 'ai_agent' }, freshIp());
  assert.equal(r.status, 400);
});

test('POST /api/register — invalid category → 400', async () => {
  const r = await request(ctx.port, 'POST', '/api/register',
    { email: 'x@example.com', category: 'hacker' }, freshIp());
  assert.equal(r.status, 400);
});

test('rate limit — 4th registration from same IP → 429', async () => {
  const ip = { 'X-Forwarded-For': '192.0.2.1' };
  for (let i = 0; i < 3; i++) {
    const r = await request(ctx.port, 'POST', '/api/register',
      { email: `user${i}@example.com`, category: 'personal' }, ip);
    assert.equal(r.status, 200, `attempt ${i + 1} should succeed`);
  }
  const r = await request(ctx.port, 'POST', '/api/register',
    { email: 'user4@example.com', category: 'personal' }, ip);
  assert.equal(r.status, 429);
});

test('integrator token — can create a session', async () => {
  // Register a new integrator
  const regR = await request(ctx.port, 'POST', '/api/register',
    { email: 'int@example.com', category: 'saas' }, freshIp());
  assert.equal(regR.status, 200);
  const intToken = regR.body.token;

  const r = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L' }], destination: localDest },
    { Authorization: `Bearer ${intToken}` });
  assert.equal(r.status, 200);
});

test('POST /admin/integrators/create — admin → 200 { token, id, name }', async () => {
  const r = await request(ctx.port, 'POST', '/admin/integrators/create',
    { id: 'test-int', name: 'Test Integrator' }, adminAuth());
  assert.equal(r.status, 200);
  assert.ok(r.body.token);
  assert.equal(r.body.id, 'test-int');
  assert.equal(r.body.name, 'Test Integrator');
});

test('admin endpoint with integrator token → 401', async () => {
  const regR = await request(ctx.port, 'POST', '/api/register',
    { email: 'nonadmin@example.com', category: 'internal' }, freshIp());
  const intToken = regR.body.token;

  const r = await request(ctx.port, 'POST', '/admin/integrators/create',
    { id: 'x', name: 'x' }, { Authorization: `Bearer ${intToken}` });
  assert.equal(r.status, 401);
});

test('integrator uses their own named destinations', async () => {
  // Create integrator via admin
  const createR = await request(ctx.port, 'POST', '/admin/integrators/create',
    { id: 'scoped-int', name: 'Scoped' }, adminAuth());
  const intToken = createR.body.token;

  // Register a named destination for this integrator
  const destR = await request(ctx.port, 'POST', '/api/destinations',
    { name: 'my-store', destination: localDest },
    { Authorization: `Bearer ${intToken}` });
  assert.equal(destR.status, 200);

  // Use the named destination in a session — should route correctly
  const sessionR = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L' }], destination: 'my-store' },
    { Authorization: `Bearer ${intToken}` });
  assert.equal(sessionR.status, 200);
});
