'use strict';
// Z9: API-friendly forms — form spec (POST /api/forms), machine submit
// (POST /api/forms/:id/submit), "Copy as API request" in the form, handle in the signed receipt.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startServer, request } = require('./helpers');
const { canonicalJson, sha256Hex, verifySigned } = require('../src/receipts');

const OWNER = 'tok_forms_owner_0000000000000000000000';
const OTHER = 'tok_forms_other_0000000000000000000000';

let ctx, pubKey;
before(async () => {
  ctx = await startServer({
    namedDestinations: { 'creds-file': { type: 'local_file', uid: 'forms', filename: '{{name}}' } },
    integrators: {
      [OWNER]: { id: 'owner1', name: 'Owner One', status: 'active' },
      [OTHER]: { id: 'other1', name: 'Other', status: 'active' },
    },
  });
  const r = await request(ctx.port, 'GET', '/.well-known/zerocreds-signing-key');
  assert.equal(r.status, 200);
  assert.equal(r.body.alg, 'Ed25519');
  pubKey = r.body.public_key_pem;
});
after(async () => { await ctx.stop(); });

const admin = () => ({ Authorization: `Bearer ${ctx.adminToken}` });
const bearer = (t) => ({ Authorization: `Bearer ${t}` });

async function createForm(body = {}, headers = bearer(OWNER)) {
  const r = await request(ctx.port, 'POST', '/api/forms', { name: 'cloudflare', destination: 'creds-file', ...body }, headers);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body;
}

test('POST /api/forms — requires an owner key', async () => {
  const r = await request(ctx.port, 'POST', '/api/forms', { name: 'x', destination: 'creds-file' });
  assert.equal(r.status, 401);
});

test('POST /api/forms — returns form_id, URLs, one-time submit token and a signed manifest', async () => {
  const f = await createForm();
  assert.match(f.form_id, /^[a-f0-9]{32}$/);
  assert.equal(f.handle, 'cred:cloudflare');
  assert.equal(f.url, `http://test.local/f/${f.form_id}`);
  assert.equal(f.submit_url, `http://test.local/api/forms/${f.form_id}/submit`);
  assert.equal(f.status_url, `http://test.local/api/session/${f.form_id}/status`);
  assert.match(f.submit_token, /^zcs_[a-f0-9]{48}$/);

  const m = f.manifest;
  assert.equal(m.alg, 'Ed25519');
  assert.ok(verifySigned(pubKey, m), 'manifest signature verifies with the published key');
  assert.equal(m.manifest_id, sha256Hex(canonicalJson(m.payload)));
  assert.equal(m.payload.handle, 'cred:cloudflare');
  assert.equal(m.payload.kind, 'token');
  assert.equal(m.payload.owner, 'owner1');
  assert.deepEqual(m.payload.fields, [{ name: 'token', label: 'Token', type: 'password', required: true }]);
  assert.equal(m.payload.submit.url, f.submit_url);
  assert.match(m.payload.destination.target, /_integrators\/owner1\/forms\/cloudflare$/);
  assert.ok(!JSON.stringify(m).includes(f.submit_token), 'manifest never contains the submit token');

  // the pending file stores only a hash of the submit token
  const stored = fs.readFileSync(path.join(ctx.pendingDir, `${f.form_id}.json`), 'utf8');
  assert.ok(!stored.includes(f.submit_token));
});

test('POST /api/forms — kind picks default fields; explicit fields override', async () => {
  const login = await createForm({ name: 'site-x', kind: 'login' });
  assert.deepEqual(login.manifest.payload.fields.map(x => x.name), ['username', 'password']);
  const ssh = await createForm({ name: 'vm-prod-ssh', kind: 'ssh' });
  assert.deepEqual(ssh.manifest.payload.fields.map(x => x.name), ['private_key']);
  const custom = await createForm({ name: 'custom', fields: [{ name: 'api_key', label: 'API key', type: 'password' }] });
  assert.deepEqual(custom.manifest.payload.fields.map(x => x.name), ['api_key']);
});

test('POST /api/forms — rejects bad input', async () => {
  const cases = [
    [{ name: 'Bad Name' }, /name must match/],
    [{ name: '../x' }, /name must match/],
    [{ name: 123 }, /name must match/],
    [{ kind: 'cookie' }, /kind must be one of/],
    [{ kind: '__proto__' }, /kind must be one of/],
    [{ destination: undefined }, /missing destination/],
    [{ destination: 'nope' }, /unknown named destination/],
    [{ fields: [] }, /missing title or fields/],
    [{ fields: [{ name: '__proto__', label: 'x' }] }, /invalid field name/],
    [{ title: '' }, /title must be/],
    [{ ttl_minutes: 'soon' }, /ttl_minutes/],
  ];
  for (const [body, err] of cases) {
    const r = await request(ctx.port, 'POST', '/api/forms', { name: 'x', destination: 'creds-file', ...body }, bearer(OWNER));
    assert.equal(r.status, 400, JSON.stringify(body));
    assert.match(r.body.error, err);
  }
});

test('machine submit with the one-time token → signed receipt with handle, value saved', async () => {
  const f = await createForm({ name: 'cf-token' });
  const r = await request(ctx.port, 'POST', `/api/forms/${f.form_id}/submit`,
    { manifest_id: f.manifest.manifest_id, fields: { token: 'cf-secret-value' } }, bearer(f.submit_token));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.ok, true);
  assert.equal(r.body.handle, 'cred:cf-token');

  const rc = r.body.receipt;
  assert.ok(verifySigned(pubKey, rc), 'receipt signature verifies');
  assert.equal(rc.payload.type, 'zerocreds.receipt');
  assert.equal(rc.payload.handle, 'cred:cf-token');
  assert.equal(rc.payload.form_id, f.form_id);
  assert.equal(rc.payload.owner, 'owner1');
  assert.equal(rc.payload.manifest_id, f.manifest.manifest_id);
  assert.equal(rc.payload.submitted_via, 'api');
  assert.deepEqual(rc.payload.fields, ['token']);
  assert.equal(rc.payload.destination_ref, 'forms/cf-token');
  assert.ok(!JSON.stringify(r.body).includes('cf-secret-value'), 'receipt never contains values');

  const saved = JSON.parse(fs.readFileSync(path.join(ctx.tokensDir, '_integrators', 'owner1', 'forms', 'cf-token'), 'utf8'));
  assert.equal(saved.token, 'cf-secret-value');

  // tampering breaks the signature
  assert.equal(verifySigned(pubKey, { ...rc, payload: { ...rc.payload, handle: 'cred:other' } }), false);

  // owner can poll status and gets the same receipt
  const st = await request(ctx.port, 'GET', `/api/session/${f.form_id}/status`, undefined, bearer(OWNER));
  assert.equal(st.body.status, 'done');
  assert.equal(st.body.handle, 'cred:cf-token');
  assert.deepEqual(st.body.receipt, rc);
  assert.ok(!JSON.stringify(st.body).includes('cf-secret-value'));

  // one-time: the form cannot be submitted again
  const again = await request(ctx.port, 'POST', `/api/forms/${f.form_id}/submit`,
    { fields: { token: 'x' } }, bearer(f.submit_token));
  assert.equal(again.status, 404);
});

test('machine submit — owner key works; no key, wrong token or another integrator → 401', async () => {
  const f = await createForm({ name: 'auth-check' });
  const url = `/api/forms/${f.form_id}/submit`;
  const body = { fields: { token: 'v' } };
  for (const h of [{}, bearer('zcs_' + '0'.repeat(48)), bearer(OTHER), bearer('garbage'), { Authorization: f.submit_token }]) {
    const r = await request(ctx.port, 'POST', url, body, h);
    assert.equal(r.status, 401, JSON.stringify(h));
  }
  const ok = await request(ctx.port, 'POST', url, body, bearer(OWNER));
  assert.equal(ok.status, 200);
  assert.equal(ok.body.handle, 'cred:auth-check');

  const adminForm = await createForm({ name: 'admin-form', destination: { type: 'local_file', uid: 'adm', filename: 'x' } }, admin());
  const byAdmin = await request(ctx.port, 'POST', `/api/forms/${adminForm.form_id}/submit`, body, admin());
  assert.equal(byAdmin.status, 200);
  assert.equal(byAdmin.body.receipt.payload.owner, 'admin');
});

test('machine submit — validation, manifest binding, unknown and expired forms', async () => {
  const f = await createForm({ name: 'validate', kind: 'login' });
  const url = `/api/forms/${f.form_id}/submit`;
  const h = bearer(f.submit_token);

  let r = await request(ctx.port, 'POST', url, { fields: { username: 'u' } }, h);
  assert.equal(r.status, 400);
  assert.match(r.body.error, /missing required field: password/);
  r = await request(ctx.port, 'POST', url, { fields: { username: 'u', password: { x: 1 } } }, h);
  assert.equal(r.status, 400);
  r = await request(ctx.port, 'POST', url, { fields: 'nope' }, h);
  assert.equal(r.status, 400);
  r = await request(ctx.port, 'POST', url, { manifest_id: 'f'.repeat(64), fields: { username: 'u', password: 'p' } }, h);
  assert.equal(r.status, 409);
  // failed attempts do not consume the form
  r = await request(ctx.port, 'POST', url, { fields: { username: 'u', password: 'p', extra: 'dropped' } }, h);
  assert.equal(r.status, 200);
  const saved = JSON.parse(fs.readFileSync(path.join(ctx.tokensDir, '_integrators', 'owner1', 'forms', 'validate'), 'utf8'));
  assert.deepEqual(saved, { username: 'u', password: 'p' });

  r = await request(ctx.port, 'POST', `/api/forms/${'a'.repeat(32)}/submit`, { fields: {} }, admin());
  assert.equal(r.status, 404);

  const exp = await createForm({ name: 'expired' });
  const file = path.join(ctx.pendingDir, `${exp.form_id}.json`);
  const d = JSON.parse(fs.readFileSync(file, 'utf8'));
  d.expires = Date.now() - 1000;
  fs.writeFileSync(file, JSON.stringify(d));
  r = await request(ctx.port, 'POST', `/api/forms/${exp.form_id}/submit`, { fields: { token: 'v' } }, bearer(exp.submit_token));
  assert.equal(r.status, 404);
});

test('plain sessions are not forms: no machine submit, no copy-as-API block', async () => {
  const s = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'Plain', fields: [{ name: 'tok', label: 'Token' }], destination: 'creds-file' }, admin());
  assert.equal(s.status, 200);
  const r = await request(ctx.port, 'POST', `/api/forms/${s.body.token}/submit`, { fields: { tok: 'v' } }, admin());
  assert.equal(r.status, 404);
  const page = await request(ctx.port, 'GET', `/f/${s.body.token}`);
  assert.ok(!page.raw.includes('Copy as API request'));
});

test('human form shows handle and "Copy as API request" with placeholders, never the submit token', async () => {
  const f = await createForm({ name: 'site-y', kind: 'login', title: '<script>alert(1)</script>' });
  const page = await request(ctx.port, 'GET', `/f/${f.form_id}`);
  assert.equal(page.status, 200);
  assert.ok(page.raw.includes('Copy as API request'));
  assert.ok(page.raw.includes('cred:site-y'));
  assert.ok(page.raw.includes(`http://test.local/api/forms/${f.form_id}/submit`));
  assert.ok(page.raw.includes('$ZEROCREDS_SUBMIT_TOKEN'));
  assert.ok(page.raw.includes('--arg password &quot;$SITE_Y_PASSWORD&quot;'));
  assert.ok(page.raw.includes(f.manifest.manifest_id));
  assert.ok(page.raw.includes('sar cred put site-y --kind login'));
  assert.ok(!page.raw.includes(f.submit_token), 'submit token never rendered');
  assert.ok(!page.raw.includes('<script>alert(1)'), 'title is escaped');
  assert.match(page.headers['content-security-policy'], /script-src 'nonce-/);

  // the same snippets come back in the create response
  assert.ok(f.api_example.curl.includes(`/api/forms/${f.form_id}/submit`));
  assert.equal(f.api_example.sar, 'sar cred put site-y --kind login --from-file ./site-y.json   # {"username": "…", "password": "…"}');
  const one = await createForm({ name: 'one' });
  assert.equal(one.api_example.sar, 'sar cred put one --kind token --from-env ONE_TOKEN');
});

test('human submit of a form returns the same kind of signed receipt', async () => {
  const f = await createForm({ name: 'human' });
  const r = await request(ctx.port, 'POST', `/f/${f.form_id}`, { t: f.form_id, fields: { token: 'human-value' } });
  assert.equal(r.status, 200);
  assert.equal(r.body.handle, 'cred:human');
  assert.ok(verifySigned(pubKey, r.body.receipt));
  assert.equal(r.body.receipt.payload.submitted_via, 'form');
  assert.equal(r.body.receipt.payload.manifest_id, f.manifest.manifest_id);
  // and the machine endpoint is now closed too
  const again = await request(ctx.port, 'POST', `/api/forms/${f.form_id}/submit`, { fields: { token: 'x' } }, bearer(f.submit_token));
  assert.equal(again.status, 404);
});

test('signing key is created 0600 and reused across restarts', async () => {
  const mode = fs.statSync(ctx.signingKeyFile).mode & 0o777;
  assert.equal(mode, 0o600);
  const { createApp } = require('../src/server');
  const app2 = createApp({
    adminToken: 'x', pendingDir: path.join(ctx.tmpDir, 'p2'), tokensDir: path.join(ctx.tmpDir, 't2'),
    destinationsFile: ctx.destinationsFile, integratorsFile: ctx.integratorsFile, signingKeyFile: ctx.signingKeyFile,
  });
  await new Promise(r => app2.listen(0, '127.0.0.1', r));
  try {
    const a = await request(ctx.port, 'GET', '/.well-known/zerocreds-signing-key');
    const b = await request(app2.address().port, 'GET', '/.well-known/zerocreds-signing-key');
    assert.equal(a.body.key_id, b.body.key_id);
  } finally {
    app2.closeAllConnections();
    await new Promise(r => app2.close(r));
  }
});
