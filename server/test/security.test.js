'use strict';
// Robustness and injection regressions: malformed input must never crash the process,
// and user-controlled query parameters must never reach a page unescaped.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { startServer, request } = require('./helpers');

let ctx;
before(async () => { ctx = await startServer(); });
after(async () => { await ctx.stop(); });

const auth = () => ({ Authorization: `Bearer ${ctx.adminToken}` });
const localDest = { type: 'local_file', uid: '99010', filename: 'sec-test' };

async function assertAlive() {
  const r = await request(ctx.port, 'GET', '/health');
  assert.equal(r.status, 200, 'server must still be running');
}

function rawPost(port, urlPath, bodyStr, headers = {}) {
  return new Promise((resolve) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: urlPath, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr), ...headers } }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, raw: data }));
    });
    req.on('error', (e) => resolve({ status: 0, error: e.code }));
    req.end(bodyStr);
  });
}

test('nalog 2FA endpoint — non-string code → 400, no crash', async () => {
  const r = await request(ctx.port, 'POST', '/connect/nalog/code', { session: 'a'.repeat(32), code: 123 });
  assert.equal(r.status, 400);
  await assertAlive();
});

test('oversized body → rejected, no crash', async () => {
  const big = JSON.stringify({ title: 'x'.repeat(1_200_000) });
  for (const [p, h] of [['/connect/nalog/code', {}], ['/api/register', {}], ['/api/session/create', auth()]]) {
    const r = await rawPost(ctx.port, p, big, h);
    assert.ok(r.status === 413 || r.status === 0, `${p}: 413 or connection closed, got ${r.status}`);
    await assertAlive();
  }
});

test('non-object JSON bodies → 400, no crash', async () => {
  for (const body of ['null', '[]', '"str"', '42']) {
    for (const p of ['/api/session/create', '/api/destinations', '/connect/nalog', '/connect/nalog/code', `/f/${'a'.repeat(32)}`]) {
      const r = await rawPost(ctx.port, p, body);
      assert.ok([400, 401].includes(r.status), `${p} with ${body} → ${r.status}`);
    }
  }
  await assertAlive();
});

test('session create — malformed fields → 400, no crash', async () => {
  const cases = [
    [null],
    [1],
    ['str'],
    [{ name: 1, label: 'x' }],
    [{ name: 'a', label: {} }],
    [{ name: '__proto__', label: 'x' }],
    [{ name: 'constructor', label: 'x' }],
    [{ name: 'a', label: 'x', placeholder: {} }],
    [{ name: 'a', label: 'x', required: 'yes' }],
    [{ name: 'a', label: 'x' }, { name: 'a', label: 'dup' }],
  ];
  for (const fields of cases) {
    const r = await request(ctx.port, 'POST', '/api/session/create',
      { title: 'T', fields, destination: localDest }, auth());
    assert.equal(r.status, 400, `fields=${JSON.stringify(fields)}`);
  }
  await assertAlive();
});

test('session create — non-string title/description, bad ttl, bad notify → 400', async () => {
  const base = { title: 'T', fields: [{ name: 'a', label: 'A' }], destination: localDest };
  for (const patch of [{ title: {} }, { title: ['x'] }, { description: { a: 1 } }, { ttl_minutes: 'abc' },
    { notify: 'x' }, { notify: { tg_bot_token: 1, tg_chat_id: 2 } }, { destinations_by_level: { __proto__x: localDest } }]) {
    const r = await request(ctx.port, 'POST', '/api/session/create', { ...base, ...patch }, auth());
    assert.equal(r.status, 400, JSON.stringify(patch));
  }
  await assertAlive();
});

test('form submit — non-string values and prototype keys are rejected', async () => {
  const s = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'a', label: 'A' }], destination: localDest }, auth());
  const token = s.body.token;
  const r1 = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { a: { x: 1 } } });
  assert.equal(r1.status, 400);
  const r2 = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: [] });
  assert.equal(r2.status, 400);
  const r3 = await request(ctx.port, 'POST', `/f/${token}`, { t: 123, fields: { a: 'v' } });
  assert.equal(r3.status, 400);
  await assertAlive();
});

test('legacy connect pages — non-hex t is rejected, never reflected', async () => {
  const payload = encodeURIComponent('</script><script>alert(1)</script>');
  for (const svc of ['nalog', 'github', 'weeek', 'tilda']) {
    const r = await request(ctx.port, 'GET', `/connect/${svc}?t=${payload}`);
    assert.equal(r.status, 400, svc);
    assert.ok(!r.raw.includes('alert(1)'), `${svc} must not reflect t`);
    const empty = await request(ctx.port, 'GET', `/connect/${svc}`);
    assert.equal(empty.status, 400, `${svc} without t`);
  }
});

test('legacy connect pages — valid token renders with CSP nonce', async () => {
  const t = 'd'.repeat(32);
  const r = await request(ctx.port, 'GET', `/connect/nalog?t=${t}`);
  assert.equal(r.status, 200);
  const nonce = r.headers['content-security-policy'].match(/'nonce-([^']+)'/)[1];
  assert.ok(r.raw.includes(`<script nonce="${nonce}">`));
  assert.ok(r.raw.includes(`const T = "${t}";`));
  assert.ok(!/\son[a-z]+\s*=/i.test(r.raw), 'no inline event handlers');
  assert.equal(r.headers['x-frame-options'], 'DENY');
});

test('legacy connect POST — non-string value → 400, no crash', async () => {
  const r = await request(ctx.port, 'POST', '/connect/github', { t: 'e'.repeat(32), value: { a: 1 } });
  assert.equal(r.status, 400);
  const r2 = await request(ctx.port, 'POST', '/connect/nalog', { t: 'e'.repeat(32), login: 1, password: [] });
  assert.equal(r2.status, 400);
  await assertAlive();
});

test('JSON API responses are not cacheable', async () => {
  const r = await request(ctx.port, 'GET', '/health');
  assert.equal(r.headers['cache-control'], 'no-store');
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
});

test('nalog login does not write screenshots or log page text', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '../src/nalog-login.js'), 'utf8');
  assert.ok(!/\.screenshot\(/.test(src), 'no page screenshots');
  assert.ok(!/innerText/.test(src), 'no page text captured');
});
