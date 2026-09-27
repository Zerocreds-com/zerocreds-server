'use strict';
// One-time link semantics, cleanup of stale session files, and on-disk permissions.
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
const fields = [{ name: 'tok', label: 'Token' }];

function startMockServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () =>
      resolve({ port: srv.address().port, close: () => new Promise(r => { srv.closeAllConnections(); srv.close(r); }) }),
    );
  });
}

test('concurrent submissions of one link — exactly one succeeds', async () => {
  let received = 0;
  const mock = await startMockServer((req, res) => {
    req.resume();
    req.on('end', () => { received++; setTimeout(() => res.writeHead(200).end('{}'), 200); });
  });
  try {
    const s = await request(ctx.port, 'POST', '/api/session/create',
      { title: 'T', fields, destination: { type: 'http_post', url: `http://127.0.0.1:${mock.port}/c` }, test_destination: false }, auth());
    const token = s.body.token;
    const results = await Promise.all([1, 2, 3].map(() =>
      request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { tok: 'v' } })));
    const statuses = results.map(r => r.status).sort();
    assert.deepEqual(statuses, [200, 403, 403]);
    assert.equal(received, 1, 'destination written once');
  } finally {
    await mock.close();
  }
});

test('failed save releases the link so the user can retry', async () => {
  let calls = 0;
  const mock = await startMockServer((req, res) => {
    req.resume();
    req.on('end', () => res.writeHead(++calls === 1 ? 500 : 200).end('{}'));
  });
  try {
    const s = await request(ctx.port, 'POST', '/api/session/create',
      { title: 'T', fields, destination: { type: 'http_post', url: `http://127.0.0.1:${mock.port}/c` }, test_destination: false }, auth());
    const token = s.body.token;
    const first = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { tok: 'v' } });
    assert.equal(first.status, 500);
    const second = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { tok: 'v' } });
    assert.equal(second.status, 200);
    const third = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { tok: 'v' } });
    assert.equal(third.status, 403);
  } finally {
    await mock.close();
  }
});

test('sweeper removes expired pending, stale claims and old .done files only', () => {
  const dir = ctx.pendingDir;
  const now = Date.now();
  const old = new Date(now - 2 * 24 * 60 * 60 * 1000);
  const write = (name, data, mtime) => {
    const f = path.join(dir, name);
    fs.writeFileSync(f, JSON.stringify(data));
    if (mtime) fs.utimesSync(f, mtime, mtime);
    return f;
  };
  const expired = write('1'.repeat(32) + '.json', { expires: now - 1000, destination: { credentials: 'x' } });
  const live = write('2'.repeat(32) + '.json', { expires: now + 60_000 });
  const oldDone = write('3'.repeat(32) + '.done', {}, old);
  const newDone = write('4'.repeat(32) + '.done', {});
  const staleClaim = write('5'.repeat(32) + '.claimed', { expires: now + 60_000 }, old);
  const freshClaim = write('6'.repeat(32) + '.claimed', { expires: now + 60_000 });

  ctx.server.sweepPending();

  assert.ok(!fs.existsSync(expired), 'expired pending removed');
  assert.ok(fs.existsSync(live), 'live pending kept');
  assert.ok(!fs.existsSync(oldDone), 'old done removed');
  assert.ok(fs.existsSync(newDone), 'recent done kept');
  assert.ok(!fs.existsSync(staleClaim), 'stale claim removed');
  assert.ok(fs.existsSync(freshClaim), 'in-flight claim kept');
});

test('server-created directories are private (0700)', { skip: process.platform === 'win32' }, async () => {
  const mode = (p) => fs.statSync(p).mode & 0o777;
  assert.equal(mode(ctx.pendingDir), 0o700);
  assert.equal(mode(ctx.tokensDir), 0o700);
  const s = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields, destination: { type: 'local_file', uid: '77001', filename: 'perm' } }, auth());
  await request(ctx.port, 'POST', `/f/${s.body.token}`, { t: s.body.token, fields: { tok: 'v' } });
  assert.equal(mode(path.join(ctx.tokensDir, '77001')), 0o700);
  assert.equal(mode(path.join(ctx.tokensDir, '77001', 'perm')), 0o600);
});

test('no "remember me": submitted values are never stored for pre-fill', async () => {
  const s = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'email', label: 'Email', type: 'email' }, { name: 'key', label: 'Key', level: 'secret' }],
      destination: { type: 'local_file', uid: '77002', filename: 'nosave' } }, auth());
  const token = s.body.token;
  const r = await request(ctx.port, 'POST', `/f/${token}`,
    { t: token, fields: { email: 'me@example.com', key: 'SECRET-KEY-VALUE' }, save: true });
  assert.equal(r.status, 200);
  assert.equal(r.headers['set-cookie'], undefined);

  const s2 = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T2', fields: [{ name: 'email', label: 'Email' }, { name: 'key', label: 'Key' }],
      destination: { type: 'local_file', uid: '77002', filename: 'nosave2' } }, auth());
  const page = await request(ctx.port, 'GET', `/f/${s2.body.token}`, undefined, { Cookie: 'zc_uid=00000000-0000-0000-0000-000000000000' });
  assert.ok(!page.raw.includes('me@example.com'));
  assert.ok(!page.raw.includes('SECRET-KEY-VALUE'));
});
