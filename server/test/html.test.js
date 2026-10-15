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
  assert.ok(html.includes('SECRET'), 'secret level chip should appear');
});

test('field without level → no level-btn', async () => {
  const html = await getFormHtml([{ name: 'tok', label: 'Token' }]);
  assert.ok(!html.includes('class="level-btn"'), 'level-btn should NOT appear for fields without level');
});

test('description is HTML-escaped', async () => {
  const html = await getFormHtml(undefined, 'Test', 'Enter your <b>token</b> <img src=x onerror=alert(1)>');
  assert.ok(!html.includes('<img src=x'), 'raw markup from description must not appear');
  assert.ok(html.includes('&lt;b&gt;token&lt;/b&gt;'), 'description should be HTML-escaped');
});

test('form page sends strict CSP with a nonce matching every script tag', async () => {
  const r1 = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'CSP', fields: [{ name: 'tok', label: 'Token', type: 'password', level: 'secret' }], destination: localDest }, auth());
  const r = await request(ctx.port, 'GET', `/f/${r1.body.token}`);
  const csp = r.headers['content-security-policy'];
  assert.ok(csp, 'CSP header present');
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /connect-src 'self'/);
  const nonce = csp.match(/'nonce-([^']+)'/)[1];
  const scripts = r.raw.match(/<script[^>]*>/g) || [];
  assert.ok(scripts.length > 0);
  for (const tag of scripts) assert.equal(tag, `<script nonce="${nonce}">`);
  assert.ok(!/\son[a-z]+\s*=/i.test(r.raw), 'no inline event handler attributes (blocked by CSP)');
  assert.equal(r.headers['x-frame-options'], 'DENY');
  assert.equal(r.headers['referrer-policy'], 'no-referrer');
  assert.equal(r.headers['cache-control'], 'no-store');
  assert.equal(r.headers['set-cookie'], undefined, 'no tracking cookie');

  const again = await request(ctx.port, 'GET', `/f/${r1.body.token}`);
  assert.notEqual(again.headers['content-security-policy'], csp, 'nonce is per response');
});

function beforeSubmit(html) {
  const i = html.indexOf('id="btn"');
  assert.ok(i > 0);
  return html.slice(0, i);
}

test('destination and requester are visible above Submit (not collapsed)', async () => {
  const html = await getFormHtml(undefined, 'Where');
  const head = beforeSubmit(html);
  assert.ok(head.includes('id="zc-destination"'));
  assert.ok(head.includes('Requested by'));
  assert.ok(head.includes('Operator of this ZeroCreds server'));
  assert.ok(head.includes('~/agent-tokens/99004/html-test'), 'exact file path shown');
  const box = head.slice(head.indexOf('id="zc-destination"'));
  assert.ok(!/display:\s*none/.test(box.slice(0, box.indexOf('</div>\n'))), 'destination box is not hidden');
});

test('http_post destination: exact host + path shown, no write-only wording', async () => {
  const r1 = await request(ctx.port, 'POST', '/api/session/create', {
    title: 'Post', fields: [{ name: 'tok', label: 'Token', level: 'secret' }],
    destination: { type: 'http_post', url: 'http://127.0.0.1:9/collect/path?key={tok}' },
    test_destination: false,
  }, auth());
  assert.equal(r1.status, 200);
  const html = (await request(ctx.port, 'GET', `/f/${r1.body.token}`)).raw;
  const head = beforeSubmit(html);
  assert.ok(head.includes('http://127.0.0.1:9/collect/path'), 'host and path visible above Submit');
  assert.ok(!head.includes('key={tok}'), 'query template not shown');
  assert.ok(/receives the values in readable form/.test(head));
  assert.ok(!/write-only/i.test(html), 'no write-only claim for http_post');
  assert.ok(!/straight into your secret store/i.test(html));
});

test('integrator session shows the integrator as requester', async () => {
  const c = await request(ctx.port, 'POST', '/admin/integrators/create', { id: 'acme-int', name: 'Acme <Corp>' }, auth());
  await request(ctx.port, 'POST', '/api/destinations',
    { name: 'acme', destination: { type: 'gcp_secret_manager', secret: 'projects/p/secrets/s', credentials: 'x' }, integrator_id: 'acme-int' }, auth());
  const s = await request(ctx.port, 'POST', '/api/session/create',
    { title: 'T', fields: [{ name: 'tok', label: 'L' }], destination: 'acme' }, { Authorization: `Bearer ${c.body.token}` });
  assert.equal(s.status, 200);
  const head = beforeSubmit((await request(ctx.port, 'GET', `/f/${s.body.token}`)).raw);
  assert.ok(head.includes('Acme &lt;Corp&gt; (integrator acme-int)'));
  assert.ok(head.includes('projects/p/secrets/s'));
});

// ── Z8 form design: CSP-friendly markup, theming, mobile ──

const designFields = [
  { name: 'user', label: 'User', level: 'attribute' },
  { name: 'pw', label: 'Password', type: 'password', level: 'secret' },
];

test('form markup has no inline event handlers and no inline style attributes', async () => {
  const html = await getFormHtml(designFields);
  assert.ok(!/<[^>]+\son[a-z]+\s*=/i.test(html), 'no on*= handler attributes (strict CSP)');
  assert.ok(!/<[^>]+\sstyle\s*=/i.test(html), 'no style= attributes (strict CSP)');
  assert.equal((html.match(/<script\b/g) || []).length, 1, 'exactly one inline script block');
  assert.ok(!/<script[^>]+src=/.test(html), 'no external scripts');
  assert.ok(!/<link[^>]+stylesheet/.test(html), 'no external stylesheets/fonts');
});

test('interactive controls are wired via data-action (show/hide, paste, info, submit, theme)', async () => {
  const html = await getFormHtml(designFields);
  for (const a of ['toggle-pw', 'paste', 'toggle-info', 'toggle-where', 'submit', 'theme']) {
    assert.ok(html.includes(`data-action="${a}"`), `data-action="${a}" present`);
  }
  assert.ok(html.includes('data-target="f_pw"'), 'password buttons target the password input');
});

test('light/dark theme: prefers-color-scheme default, explicit override, persisted choice', async () => {
  const html = await getFormHtml(designFields);
  assert.ok(html.includes('@media (prefers-color-scheme:dark){:root:not([data-theme="light"])'), 'dark default follows system');
  assert.ok(html.includes(':root[data-theme="dark"]'), 'explicit dark override');
  assert.ok(html.includes('<meta name="color-scheme" content="light dark">'));
  assert.ok(html.includes("localStorage.getItem('zc-theme')"), 'stored choice read');
  assert.ok(html.includes("localStorage.setItem('zc-theme'"), 'choice persisted');
  assert.ok(html.indexOf('<script') < html.indexOf('<body'), 'theme applied in <head> before first paint (no flash)');
  assert.ok(html.includes('id="theme-btn"'), 'toggle button rendered');
});

test('mobile: 16px inputs (no iOS zoom) and sticky submit on small screens', async () => {
  const html = await getFormHtml(designFields);
  assert.match(html, /input,textarea\{[^}]*font-size:16px/);
  assert.match(html, /@media \(max-width:560px\)\{[\s\S]*\.actions\{position:sticky;bottom:0/);
  assert.ok(html.includes('<div class="actions">'), 'submit wrapped in sticky actions bar');
});

test('level chips use theme classes, not inline colours', async () => {
  const html = await getFormHtml(designFields);
  assert.ok(html.includes('class="level-chip lvl-secret"'));
  assert.ok(html.includes('class="level-info lvl-secret" hidden'));
  assert.ok(html.includes('class="wl-chip lvl-attribute"'));
});
