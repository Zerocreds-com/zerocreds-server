'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { startServer, request } = require('./helpers');
const { destinationDisclosureHtml } = require('../src/destination-disclosure');

let ctx;
let destServer;          // shared http_post destination for form tests
let destPort;
let destHits = [];       // every request the destination received

before(async () => {
  ctx = await startServer();
  destServer = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      destHits.push({ url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
      res.writeHead(200);
      res.end('ok');
    });
  });
  await new Promise((r) => destServer.listen(0, '127.0.0.1', r));
  destPort = destServer.address().port;
});
after(async () => {
  await new Promise((r) => destServer.close(r));
  await ctx.stop();
});

const auth = () => ({ Authorization: `Bearer ${ctx.adminToken}` });
const localUrl = (p) => `http://127.0.0.1:${destPort}${p}`;

async function getForm(destination, extra = {}, fields = [{ name: 'tok', label: 'Token', type: 'password' }]) {
  const r = await request(ctx.port, 'POST', '/api/session/create', {
    title: 'Disclosure Test',
    fields,
    destination,
    ...extra,
  }, auth());
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const form = await request(ctx.port, 'GET', `/f/${r.body.token}`);
  assert.equal(form.status, 200);
  return form.raw;
}

// The single <details class="dest-dd"> block, extracted from the full page —
// lets us assert what the disclosure itself contains (the per-level
// "How is this data handled?" block shows some of the same strings).
function disclosure(html) {
  const start = html.indexOf('<details class="dest-dd">');
  assert.ok(start !== -1, 'disclosure <details> block must be rendered');
  const end = html.indexOf('</details>', start);
  assert.ok(end !== -1, 'disclosure block must be closed');
  return html.slice(start, end);
}

// ── rendering per destination type ───────────────────────────────────────────

test('local_file — disclosure shows the resolved ~/agent-tokens path', async () => {
  const html = await getForm({ type: 'local_file', uid: '99005', filename: 'disc-a' });
  const block = disclosure(html);
  assert.ok(block.includes('Where will your secrets go?'));
  assert.ok(block.includes('~/agent-tokens/99005/disc-a'), 'file path disclosed');
  assert.ok(block.includes('local_file'));
});

test('http_post — method + host/path, every header value masked, no real values in HTML', async () => {
  const HDR_AUTH = 'Bearer EXAMPLE_AUTH_HEADER_0001';
  const HDR_KEY = 'EXAMPLE_X_API_KEY_0002';
  const QUERY_SECRET = 'EXAMPLE_QUERY_API_KEY_0003';
  const QUERY_TEAM = 'EXAMPLE_TEAM_VALUE_0004';
  const BODY_LITERAL = 'EXAMPLE_BODY_LITERAL_0005';
  const html = await getForm({
    type: 'http_post',
    url: `${localUrl('/ingest')}?api_key=${QUERY_SECRET}&team=${QUERY_TEAM}&label={label}`,
    headers: { Authorization: HDR_AUTH, 'x-api-key': HDR_KEY },
    body: { value: '{fields_json}', note: BODY_LITERAL },
  });

  // addresses and structure are shown
  const block = disclosure(html);
  assert.ok(block.includes(`POST ${localUrl('/ingest')}`), 'method + host/path');
  assert.ok(block.includes('api_key=••••••'), 'secret query value masked');
  assert.ok(block.includes('team=••••••'), 'opaque-looking literal query value masked');
  assert.ok(block.includes('label={label}'), 'non-secret placeholder stays a placeholder');
  assert.ok(block.includes('Header Authorization') && block.includes('Header x-api-key'));

  // curl example: same call with <TOKEN> placeholders
  assert.ok(block.includes('curl -X POST'));
  assert.ok(block.includes(`-H 'Authorization: &lt;TOKEN&gt;'`));
  assert.ok(block.includes(`-H 'x-api-key: &lt;TOKEN&gt;'`));
  assert.ok(block.includes(`-d '{"value":"&lt;TOKEN&gt;","note":"&lt;TOKEN&gt;"}'`), 'body template keeps structure, values masked');
  assert.ok(block.includes('&lt;TOKEN&gt;'));

  // no real values anywhere in the page
  for (const secret of [HDR_AUTH, HDR_KEY, QUERY_SECRET, QUERY_TEAM, BODY_LITERAL]) {
    assert.ok(!html.includes(secret), `must not render: ${secret}`);
  }
  assert.ok(html.includes('••••••'));
});

test('gcp_secret_manager — resource name shown, service-account key never rendered', async () => {
  const saJson = JSON.stringify({
    client_email: 'sa@example.iam.gserviceaccount.com',
    private_key: 'EXAMPLE_PRIVATE_KEY_MATERIAL_NOT_A_REAL_KEY',
  });
  const credentials = Buffer.from(saJson).toString('base64');
  const resource = 'projects/example-prod/secrets/github-token';
  const html = await getForm({ type: 'gcp_secret_manager', secret: resource, credentials });

  const block = disclosure(html);
  assert.ok(block.includes(resource), 'secret resource name disclosed');
  assert.ok(block.includes('Service-account key') && block.includes('••••••'));
  assert.ok(block.includes('secretmanager.googleapis.com'), 'curl example for the real API');
  assert.ok(block.includes('Authorization: Bearer &lt;TOKEN&gt;'));

  assert.ok(!html.includes(credentials), 'base64 SA key must not appear');
  assert.ok(!html.includes('EXAMPLE_PRIVATE_KEY_MATERIAL'), 'private key material must not appear');
  assert.ok(!html.includes('client_email'), 'SA JSON must not appear');
});

test('aws_secrets_manager — arn and region shown, access keys never rendered', async () => {
  const ACCESS_KEY = 'EXAMPLE_ACCESS_KEY_ID_0006';
  const SECRET_KEY = 'EXAMPLE_SECRET_ACCESS_KEY_0007';
  const arn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:example/api-key-AbCd';
  const html = await getForm({
    type: 'aws_secrets_manager',
    secret_id: arn,
    region: 'us-east-1',
    access_key_id: ACCESS_KEY,
    secret_access_key: SECRET_KEY,
  });

  const block = disclosure(html);
  assert.ok(block.includes(arn), 'secret ARN disclosed');
  assert.ok(block.includes('us-east-1'), 'region disclosed');
  assert.ok(block.includes('secretsmanager.us-east-1.amazonaws.com'), 'curl host');
  assert.ok(block.includes('Access key ID') && block.includes('Secret access key'));
  assert.ok(block.includes('••••••'));

  assert.ok(!html.includes(ACCESS_KEY), 'access_key_id must not appear');
  assert.ok(!html.includes(SECRET_KEY), 'secret_access_key must not appear');
});

test('vault — address, path and role shown, token and secret_id never rendered', async () => {
  const VAULT_TOKEN = 'EXAMPLE_VAULT_TOKEN_0008';
  const VAULT_SECRET = 'EXAMPLE_VAULT_SECRET_ID_0009';
  const html = await getForm({
    type: 'vault',
    address: 'https://vault.example.test',
    path: 'secret/data/myapp',
    token: VAULT_TOKEN,
    role_id: 'example-role',
    secret_id: VAULT_SECRET,
  });

  const block = disclosure(html);
  assert.ok(block.includes('https://vault.example.test'), 'vault address disclosed');
  assert.ok(block.includes('secret/data/myapp'), 'secret path disclosed');
  assert.ok(block.includes('example-role'), 'role id disclosed');
  assert.ok(block.includes(`https://vault.example.test/v1/secret/data/myapp`), 'curl target');
  assert.ok(block.includes('X-Vault-Token: &lt;TOKEN&gt;'));
  assert.ok(block.includes('••••••'));

  assert.ok(!html.includes(VAULT_TOKEN), 'vault token must not appear');
  assert.ok(!html.includes(VAULT_SECRET), 'approle secret_id must not appear');
});

test('macos_keychain — store, service and account shown', async () => {
  const html = await getForm({ type: 'macos_keychain', service: 'zerocreds', account: 'github' });
  const block = disclosure(html);
  assert.ok(block.includes('macos_keychain'));
  assert.ok(block.includes('macOS Keychain'));
  assert.ok(block.includes('zerocreds') && block.includes('github'));
  assert.ok(!block.includes('curl -X'), 'no curl example for a keychain write');
});

test('windows_credential_manager and os_keychain — store and entry names shown', async () => {
  const win = disclosure(await getForm({ type: 'windows_credential_manager', service: 'zerocreds', account: 'gh-pat' }));
  assert.ok(win.includes('windows_credential_manager'));
  assert.ok(win.includes('Windows Credential Manager'));
  assert.ok(win.includes('zerocreds') && win.includes('gh-pat'));

  const os = disclosure(await getForm({ type: 'os_keychain', service: 'zerocreds', account: 'aws' }));
  assert.ok(os.includes('os_keychain'));
  assert.ok(os.includes('OS credential store'));
  assert.ok(os.includes('zerocreds') && os.includes('aws'));
});

test('unknown destination type — type name shown, every config value masked', async () => {
  const ENDPOINT = 'https://mystery.example.test/sink-12345';
  const SECRET = 'EXAMPLE_MYSTERY_SECRET_0010';
  const html = await getForm({ type: 'mystery_store', endpoint: ENDPOINT, api_secret: SECRET });

  const block = disclosure(html);
  assert.ok(block.includes('mystery_store'), 'type disclosed');
  assert.ok(block.includes('••••••'));
  assert.ok(!html.includes(ENDPOINT), 'unknown config value must not appear');
  assert.ok(!html.includes(SECRET), 'unknown config secret must not appear');
});

test('destinations_by_level — every level destination disclosed with its level chip', async () => {
  const r = await request(ctx.port, 'POST', '/api/session/create', {
    title: 'By Level',
    fields: [
      { name: 'tok', label: 'Token', type: 'password', level: 'secret' },
      { name: 'who', label: 'Name', level: 'pii' },
    ],
    destinations_by_level: {
      secret: { type: 'local_file', uid: '99011', filename: 'secret-part' },
      pii: { type: 'local_file', uid: '99011', filename: 'pii-part' },
    },
  }, auth());
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const form = await request(ctx.port, 'GET', `/f/${r.body.token}`);
  assert.equal(form.status, 200);

  const block = disclosure(form.raw);
  assert.ok(block.includes('~/agent-tokens/99011/secret-part'), 'secret destination disclosed');
  assert.ok(block.includes('~/agent-tokens/99011/pii-part'), 'pii destination disclosed');
  assert.ok(block.includes('<span class="wl-chip lvl-secret">SECRET</span>'));
  assert.ok(block.includes('<span class="wl-chip lvl-pii">PII DATA</span>'));
});

// ── safety: escaping, CSP, preflight ─────────────────────────────────────────

test('XSS in destination config — values escaped, no raw tags or handlers', async () => {
  const html = await getForm({
    type: 'http_post',
    url: `${localUrl('/ingest')}?note=<img src=x onerror=alert(1)>`,
    headers: { Authorization: 'Bearer EXAMPLE_XSS_0011' },
  });
  assert.ok(!html.includes('<img src=x onerror=alert(1)>'), 'raw tag must not appear');
  assert.ok(html.includes('&lt;img'), 'value must be HTML-escaped');
  assert.ok(!html.includes('Bearer EXAMPLE_XSS_0011'));
  assert.ok(!/<[^>]+\son[a-z]+\s*=/i.test(html), 'no event handler attributes');
  assert.ok(!/<[^>]+\sstyle\s*=/i.test(html), 'no inline style attributes');
  assert.equal((html.match(/<script\b/g) || []).length, 1, 'exactly one inline script block');
  assert.ok(html.includes('<details class="dest-dd">'), 'disclosure present in the checked page');
});

test('preflight — form render sends no probes, probe markers never rendered, submit still reaches destination', async () => {
  const AUTH = 'Bearer EXAMPLE_PREFLIGHT_SECRET_0012';
  const baseline = destHits.length;

  const create = await request(ctx.port, 'POST', '/api/session/create', {
    title: 'Preflight',
    fields: [{ name: 'tok', label: 'Token', type: 'password' }],
    destination: { type: 'http_post', url: localUrl('/hook'), headers: { Authorization: AUTH } },
  }, auth());
  assert.equal(create.status, 200, JSON.stringify(create.body));

  const probeHits = destHits.slice(baseline);
  assert.ok(probeHits.length >= 1, 'preflight probe ran during session create');
  assert.ok(probeHits.every((h) => h.headers['x-zerocreds-preflight'] === 'true'), 'probe carries the preflight header');
  assert.ok(probeHits.every((h) => h.body.includes('_zerocreds_preflight')), 'probe carries the preflight body marker');

  const beforeRender = destHits.length;
  const form = await request(ctx.port, 'GET', `/f/${create.body.token}`);
  assert.equal(form.status, 200);
  assert.equal(destHits.length, beforeRender, 'rendering the form must not call the destination');

  assert.ok(!form.raw.includes('_zerocreds_preflight'), 'probe body marker must not be rendered');
  assert.ok(!form.raw.includes('X-ZeroCreds-Preflight'), 'probe header must not be rendered');
  assert.ok(!form.raw.includes(AUTH), 'configured secret must not be rendered');
  assert.ok(form.raw.includes('••••••'), 'header value shown masked');

  const submit = await request(ctx.port, 'POST', `/f/${create.body.token}`, {
    t: create.body.token,
    fields: { tok: 'user-typed-value' },
  });
  assert.equal(submit.status, 200);
  assert.ok(destHits.length > beforeRender, 'real submission still reaches the destination');
});

// ── unit: pure renderer ──────────────────────────────────────────────────────

test('renderer returns empty string when the session has no destination', () => {
  assert.equal(destinationDisclosureHtml({ fields: [] }), '');
  assert.equal(destinationDisclosureHtml(null), '');
  assert.equal(destinationDisclosureHtml({ destination: null }), '');
});
