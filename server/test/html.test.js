'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer, request } = require('./helpers');

let ctx;
before(async () => { ctx = await startServer(); });
after(async () => { await ctx.stop(); });

const localDest = { type: 'local_file', uid: '99004', filename: 'html-test' };
const auth = () => ({ Authorization: `Bearer ${ctx.adminToken}` });

async function getFormHtml(sessionFields, sessionTitle, sessionDesc) {
  const r = await request(ctx.port, 'POST', '/api/session/create', {
    title: sessionTitle || 'Test Form',
    description: sessionDesc,
    fields: sessionFields || [{ name: 'tok', label: 'Token' }],
    destination: localDest,
  }, auth());
  assert.equal(r.status, 200);
  const formResp = await request(ctx.port, 'GET', `/f/${r.body.token}`);
  assert.equal(formResp.status, 200);
  return formResp.raw;
}

test('XSS in title — <script>alert(1)</script> is escaped in <title> and <h1>', async () => {
  const html = await getFormHtml(undefined, '<script>alert(1)</script>');
  assert.ok(!html.includes('<script>alert(1)</script>'), 'raw script tag must not appear');
  assert.ok(html.includes('&lt;script&gt;'), 'title should be HTML-escaped');
});

test('XSS in field label — escaped in output', async () => {
  const html = await getFormHtml([{ name: 'tok', label: '<img src=x onerror=alert(1)>' }]);
  assert.ok(!html.includes('<img src=x onerror=alert(1)>'), 'raw img tag must not appear in label');
  assert.ok(html.includes('&lt;img'), 'label should be HTML-escaped');
});

test('XSS in placeholder — escaped as attribute', async () => {
  const html = await getFormHtml([{ name: 'tok', label: 'Token', placeholder: '" onmouseover="alert(1)' }]);
  assert.ok(!html.includes('" onmouseover="alert(1)'), 'raw attribute injection must not appear');
  assert.ok(html.includes('&quot;'), 'placeholder should use attribute-safe escaping');
});

test('field with level: "secret" → HTML contains level-btn', async () => {
  const html = await getFormHtml([{ name: 'tok', label: 'Token', level: 'secret' }]);
  assert.ok(html.includes('class="level-btn"'), 'level-btn should appear for fields with a level');
  assert.ok(html.includes('🔒'), 'secret level icon should appear');
});

test('field without level → no level-btn', async () => {
  const html = await getFormHtml([{ name: 'tok', label: 'Token' }]);
  assert.ok(!html.includes('class="level-btn"'), 'level-btn should NOT appear for fields without level');
});

test('description with HTML tags — rendered as-is (trusted content)', async () => {
  const html = await getFormHtml(undefined, 'Test', 'Enter your <b>token</b> below.');
  assert.ok(html.includes('<b>token</b>'), 'description HTML should pass through unescaped');
});
