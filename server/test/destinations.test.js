'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const { startServer, request } = require('./helpers');

let ctx;
before(async () => { ctx = await startServer(); });
after(async () => { await ctx.stop(); });

const auth = () => ({ Authorization: `Bearer ${ctx.adminToken}` });

function tokenDir(uid) { return path.join(ctx.tokensDir, String(uid)); }

async function createAndSubmit(fields, dest, destByLevel) {
  const body = { title: 'T', fields };
  if (destByLevel) body.destinations_by_level = destByLevel;
  else body.destination = dest;
  const r1 = await request(ctx.port, 'POST', '/api/session/create', body, auth());
  assert.equal(r1.status, 200);
  const token = r1.body.token;
  const submitted = {};
  for (const f of fields) submitted[f.name] = f.name + '-value';
  const r2 = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: submitted });
  return { createRes: r1.body, submitRes: r2, token };
}

function startMockServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () =>
      resolve({ port: srv.address().port, close: () => new Promise(r => { srv.closeAllConnections(); srv.close(r); }) }),
    );
  });
}

test('local_file — single destination → file written with fields', async () => {
  const uid = '88001';
  const dest = { type: 'local_file', uid, filename: 'creds' };
  const { submitRes } = await createAndSubmit(
    [{ name: 'tok', label: 'Token' }], dest);
  assert.equal(submitRes.status, 200);
  const written = JSON.parse(fs.readFileSync(path.join(tokenDir(uid), 'creds'), 'utf8'));
  assert.ok(written.tok || written.value, 'file should contain the submitted field');
});

test('local_file — alphanumeric uid → accepted', async () => {
  const uid = 'john_doe-42';
  const dest = { type: 'local_file', uid, filename: 'creds' };
  const { submitRes } = await createAndSubmit(
    [{ name: 'tok', label: 'Token' }], dest);
  assert.equal(submitRes.status, 200);
  assert.ok(fs.existsSync(path.join(tokenDir(uid), 'creds')));
});

test('destinations_by_level — secret+pii → two separate files', async () => {
  const uid = '88002';
  const destSecret = { type: 'local_file', uid, filename: 'creds-secret' };
  const destPii    = { type: 'local_file', uid, filename: 'creds-pii' };
  const { submitRes } = await createAndSubmit(
    [
      { name: 'apikey', label: 'API Key', level: 'secret' },
      { name: 'email',  label: 'Email',   level: 'pii' },
    ],
    null,
    { secret: destSecret, pii: destPii },
  );
  assert.equal(submitRes.status, 200);
  assert.ok(fs.existsSync(path.join(tokenDir(uid), 'creds-secret')));
  assert.ok(fs.existsSync(path.join(tokenDir(uid), 'creds-pii')));
  const secretData = JSON.parse(fs.readFileSync(path.join(tokenDir(uid), 'creds-secret'), 'utf8'));
  const piiData    = JSON.parse(fs.readFileSync(path.join(tokenDir(uid), 'creds-pii'), 'utf8'));
  assert.ok(secretData.apikey !== undefined || secretData.value !== undefined);
  assert.ok(piiData.email !== undefined || piiData.value !== undefined);
});

test('field without level → falls back to "default" in destinations_by_level', async () => {
  const uid = '88003';
  const destDefault = { type: 'local_file', uid, filename: 'creds-default' };
  const { submitRes } = await createAndSubmit(
    [{ name: 'tok', label: 'Token' }], // no level → groups as "default"
    null,
    { default: destDefault },
  );
  assert.equal(submitRes.status, 200);
  assert.ok(fs.existsSync(path.join(tokenDir(uid), 'creds-default')));
});

test('field without a destination is rejected before the form is shown', async () => {
  const uid = '88004';
  const destSecret = { type: 'local_file', uid, filename: 'creds-secret' };
  const created = await request(ctx.port, 'POST', '/api/session/create', {
    title: 'T', fields: [{ name: 'tok', label: 'Token' }],
    destinations_by_level: { secret: destSecret },
  }, auth());
  assert.equal(created.status, 400);
  assert.match(created.body.error, /destination missing for field: tok/);
  assert.equal(fs.existsSync(path.join(tokenDir(uid), 'creds-secret')), false);
});

test('levels routed to the same destination are saved together', async () => {
  const uid = '88005';
  const shared = { type: 'local_file', uid, filename: 'combined' };
  const { submitRes } = await createAndSubmit([
    { name: 'token', label: 'Token', level: 'secret' },
    { name: 'email', label: 'Email', level: 'pii' },
  ], null, { secret: shared, pii: shared });
  assert.equal(submitRes.status, 200);
  const data = JSON.parse(fs.readFileSync(path.join(tokenDir(uid), 'combined'), 'utf8'));
  assert.deepEqual(Object.keys(data).sort(), ['email', 'token']);
});

test('http_post — upstream returns 200 → form submission succeeds', async () => {
  let receivedBody;
  const mock = await startMockServer((req, res) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      receivedBody = JSON.parse(data);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
  });

  try {
    const dest = { type: 'http_post', url: `http://127.0.0.1:${mock.port}/collect` };
    const { submitRes } = await createAndSubmit(
      [{ name: 'tok', label: 'Token' }], dest);
    assert.equal(submitRes.status, 200);
    assert.equal(submitRes.body.ok, true);
    assert.equal(receivedBody?.tok, 'tok-value');
  } finally {
    await mock.close();
  }
});

test('http_post — upstream returns 500 → form submission fails with 500', async () => {
  const mock = await startMockServer((req, res) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      // Preflight probe (sent at session-create time) must pass so the
      // session can be created; only the real submission should 500.
      let body = {};
      try { body = JSON.parse(data); } catch { /* ignore */ }
      if (body._zerocreds_preflight) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end('{}');
      }
      res.writeHead(500).end('Internal Error');
    });
  });

  try {
    const dest = { type: 'http_post', url: `http://127.0.0.1:${mock.port}/collect` };
    const { submitRes } = await createAndSubmit(
      [{ name: 'tok', label: 'Token' }], dest);
    assert.equal(submitRes.status, 500);
  } finally {
    await mock.close();
  }
});

test('http_post — destination preflight carries X-ZeroCreds-Preflight header', async () => {
  let preflightHeader;
  let preflightBody;
  const mock = await startMockServer((req, res) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      preflightHeader = req.headers['x-zerocreds-preflight'];
      try { preflightBody = JSON.parse(data); } catch { /* ignore */ }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
  });

  try {
    const dest = { type: 'http_post', url: `http://127.0.0.1:${mock.port}/collect` };
    const r = await request(ctx.port, 'POST', '/api/session/create',
      { title: 'T', fields: [{ name: 'tok', label: 'Token' }], destination: dest }, auth());
    assert.equal(r.status, 200);
    // The probe must be identifiable by header alone, so a destination never has to
    // parse the (templated, possibly nested) body to tell a probe from real data.
    assert.equal(preflightHeader, 'true');
    assert.equal(preflightBody?._zerocreds_preflight, true);
  } finally {
    await mock.close();
  }
});

test('vault static token — writes to vault path with X-Vault-Token header', async () => {
  let loginCalled = false;
  let writePath;
  let writeToken;

  const mock = await startMockServer((req, res) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      if (req.url === '/v1/auth/approle/login') {
        loginCalled = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ auth: { client_token: 'should-not-be-used' } }));
      } else {
        writePath = req.url;
        writeToken = req.headers['x-vault-token'];
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
      }
    });
  });

  try {
    const dest = {
      type: 'vault',
      address: `http://127.0.0.1:${mock.port}`,
      path: 'secret/data/myapp',
      token: 'hvs.statictoken',
    };
    const { submitRes } = await createAndSubmit(
      [{ name: 'apikey', label: 'API Key' }], dest);
    assert.equal(submitRes.status, 200);
    assert.equal(loginCalled, false, 'approle login should NOT be called when static token is given');
    assert.equal(writePath, '/v1/secret/data/myapp');
    assert.equal(writeToken, 'hvs.statictoken');
  } finally {
    await mock.close();
  }
});

test('vault AppRole — calls login then writes with returned client_token', async () => {
  let loginBody;
  let writePath;
  let writeToken;
  let writeBody;

  const mock = await startMockServer((req, res) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      if (req.url === '/v1/auth/approle/login') {
        loginBody = JSON.parse(data);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ auth: { client_token: 'approle-client-token' } }));
      } else {
        writePath = req.url;
        writeToken = req.headers['x-vault-token'];
        writeBody = JSON.parse(data);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
      }
    });
  });

  try {
    const dest = {
      type: 'vault',
      address: `http://127.0.0.1:${mock.port}`,
      path: 'secret/data/myapp',
      role_id: 'my-role-id',
      secret_id: 'my-secret-id',
    };
    const { submitRes } = await createAndSubmit(
      [{ name: 'apikey', label: 'API Key' }], dest);
    assert.equal(submitRes.status, 200);
    assert.deepEqual(loginBody, { role_id: 'my-role-id', secret_id: 'my-secret-id' });
    assert.equal(writePath, '/v1/secret/data/myapp');
    assert.equal(writeToken, 'approle-client-token');
    assert.ok(writeBody?.data?.apikey !== undefined, 'fields should be written under .data');
  } finally {
    await mock.close();
  }
});

test('vault AppRole — login returns 403 → form submission fails with 500', async () => {
  const mock = await startMockServer((req, res) => {
    req.resume();
    if (req.url === '/v1/auth/approle/login') {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ errors: ['permission denied'] }));
    } else {
      res.writeHead(200).end('{}');
    }
  });

  try {
    const dest = {
      type: 'vault',
      address: `http://127.0.0.1:${mock.port}`,
      path: 'secret/data/myapp',
      role_id: 'bad-role',
      secret_id: 'bad-secret',
    };
    const { submitRes } = await createAndSubmit(
      [{ name: 'apikey', label: 'API Key' }], dest);
    assert.equal(submitRes.status, 500);
  } finally {
    await mock.close();
  }
});

test('vault — missing token and role_id/secret_id → form submission fails with 500', async () => {
  const dest = {
    type: 'vault',
    address: 'http://127.0.0.1:19999',
    path: 'secret/data/myapp',
    // no token, no role_id/secret_id
  };
  const { submitRes } = await createAndSubmit(
    [{ name: 'apikey', label: 'API Key' }], dest);
  assert.equal(submitRes.status, 500);
});

test('named OpenBao KV-v2 destination probes owner path, confirms version, cleans up, then writes real value', async () => {
  const calls = [];
  const mock = await startMockServer((req, res) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      calls.push({ method: req.method, path: req.url, token: req.headers['x-vault-token'],
        body: body ? JSON.parse(body) : null });
      res.setHeader('Content-Type', 'application/json');
      if (req.url === '/v1/sys/capabilities-self') {
        return res.end(JSON.stringify({ capabilities: ['create', 'update'] }));
      }
      if (req.method === 'POST') return res.end(JSON.stringify({ data: { version: req.url.includes('/probes/') ? 1 : 4 } }));
      if (req.method === 'GET') return res.end(JSON.stringify({ data: { current_version: 1 } }));
      res.writeHead(204).end();
    });
  });
  const dest = { type: 'vault', address: `http://127.0.0.1:${mock.port}`,
    path: 'secret/data/owners/owner-a/connections/connection-a', token: 'writer-token',
    preflight_path_prefix: 'secret/data/owners/owner-a/probes',
    preflight_metadata_token: 'metadata-token' };
  const srv = await startServer({ namedDestinations: { 'owner-a-openbao': dest } });
  try {
    const create = await request(srv.port, 'POST', '/api/session/create', {
      title: 'Connect', fields: [{ name: 'api_key', label: 'API key', type: 'password' }],
      destination: 'owner-a-openbao',
    }, { Authorization: `Bearer ${srv.adminToken}` });
    assert.equal(create.status, 200, JSON.stringify(create.body));
    assert.equal(calls.length, 4);
    assert.deepEqual(calls.map(c => c.method), ['POST', 'POST', 'GET', 'DELETE']);
    assert.equal(calls[0].path, '/v1/sys/capabilities-self');
    assert.deepEqual(calls[0].body, { paths: [dest.path] });
    assert.match(calls[1].path, /^\/v1\/secret\/data\/owners\/owner-a\/probes\/[0-9a-f-]+$/);
    assert.equal(calls[1].token, 'writer-token');
    assert.deepEqual(calls[1].body, { data: { api_key: '__zerocreds_probe__' } });
    assert.equal(calls[2].token, 'metadata-token');
    assert.equal(calls[3].token, 'metadata-token');
    assert.equal(calls[2].path, calls[1].path.replace('/data/', '/metadata/'));
    assert.equal(calls[3].path, calls[2].path);
    const pending = fs.readFileSync(path.join(srv.pendingDir, `${create.body.token}.json`), 'utf8');
    assert.ok(!pending.includes('metadata-token'));
    assert.ok(!pending.includes('writer-token'));
    const form = await request(srv.port, 'GET', `/f/${create.body.token}`);
    assert.equal(form.status, 200);
    assert.match(form.raw, /Storage: OpenBao KV v2/);
    assert.match(form.raw, /Storage checked:/);
    assert.match(form.raw, /Wallet owner and profile: not verified/);
    assert.ok(!form.raw.includes('writer-token'));
    assert.ok(!form.raw.includes('metadata-token'));
    const submit = await request(srv.port, 'POST', `/f/${create.body.token}`,
      { t: create.body.token, fields: { api_key: 'real-secret' } });
    assert.equal(submit.status, 200);
    assert.equal(calls.length, 5);
    assert.equal(calls[4].path, '/v1/secret/data/owners/owner-a/connections/connection-a');
    assert.deepEqual(calls[4].body, { data: { api_key: 'real-secret' } });
    const done = JSON.parse(fs.readFileSync(path.join(srv.pendingDir, `${create.body.token}.done`), 'utf8'));
    assert.equal(done.version, 4);
    assert.equal(done.secret_id, dest.path);

    const second = await request(srv.port, 'POST', '/api/session/create', {
      title: 'Connect again', fields: [{ name: 'api_key', label: 'API key' }],
      destination: 'owner-a-openbao',
    }, { Authorization: `Bearer ${srv.adminToken}` });
    assert.equal(second.status, 200);
    const changed = await request(srv.port, 'POST', '/api/destinations', {
      name: 'owner-a-openbao', destination: { ...dest,
        path: 'secret/data/owners/owner-a/connections/connection-b' },
    }, { Authorization: `Bearer ${srv.adminToken}` });
    assert.equal(changed.status, 200);
    const callCount = calls.length;
    const submitAfterChange = await request(srv.port, 'POST', `/f/${second.body.token}`,
      { t: second.body.token, fields: { api_key: 'must-not-be-written' } });
    assert.equal(submitAfterChange.status, 409);
    assert.equal(submitAfterChange.body.error, 'destination_changed');
    assert.equal(calls.length, callCount);
  } finally {
    await srv.stop();
    await mock.close();
  }
});

test('OpenBao preflight refuses an unverified write and cannot be disabled', async () => {
  const mock = await startMockServer((req, res) => {
    req.resume();
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/v1/sys/capabilities-self') {
      return res.end(JSON.stringify({ capabilities: ['create', 'update'] }));
    }
    if (req.method === 'POST') return res.end(JSON.stringify({ data: { version: 1 } }));
    if (req.method === 'GET') return res.end(JSON.stringify({ data: { current_version: 2 } }));
    res.writeHead(204).end();
  });
  const srv = await startServer({ namedDestinations: { openbao: {
    type: 'vault', address: `http://127.0.0.1:${mock.port}`,
    path: 'secret/data/owners/owner-a/connections/connection-a', token: 'writer-token',
    preflight_path_prefix: 'secret/data/owners/owner-a/probes',
    preflight_metadata_token: 'metadata-token',
  } } });
  const body = { title: 'Connect', fields: [{ name: 'api_key', label: 'API key' }], destination: 'openbao' };
  try {
    const failed = await request(srv.port, 'POST', '/api/session/create', body,
      { Authorization: `Bearer ${srv.adminToken}` });
    assert.equal(failed.status, 400);
    assert.equal(failed.body.error, 'destination_unreachable');
    const disabled = await request(srv.port, 'POST', '/api/session/create',
      { ...body, test_destination: false }, { Authorization: `Bearer ${srv.adminToken}` });
    assert.equal(disabled.status, 400);
    assert.equal(disabled.body.error, 'openbao_preflight_required');
    const inline = await request(srv.port, 'POST', '/api/session/create',
      { ...body, destination: JSON.parse(fs.readFileSync(srv.destinationsFile, 'utf8')).openbao },
      { Authorization: `Bearer ${srv.adminToken}` });
    assert.equal(inline.status, 400);
    assert.equal(inline.body.error, 'openbao_preflight_requires_named_destination');
    const byLevel = await request(srv.port, 'POST', '/api/session/create',
      { title: body.title, fields: body.fields, destinations_by_level: { secret: 'openbao' } },
      { Authorization: `Bearer ${srv.adminToken}` });
    assert.equal(byLevel.status, 400);
    assert.equal(byLevel.body.error, 'openbao_preflight_requires_single_destination');
    assert.deepEqual(fs.readdirSync(srv.pendingDir), []);
  } finally {
    await srv.stop();
    await mock.close();
  }
});

test('OpenBao preflight blocks the form if probe cleanup is denied', async () => {
  const mock = await startMockServer((req, res) => {
    req.resume();
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/v1/sys/capabilities-self') {
      return res.end(JSON.stringify({ capabilities: ['create', 'update'] }));
    }
    if (req.method === 'POST') return res.end(JSON.stringify({ data: { version: 1 } }));
    if (req.method === 'GET') return res.end(JSON.stringify({ data: { current_version: 1 } }));
    res.writeHead(403).end(JSON.stringify({ errors: ['permission denied'] }));
  });
  const srv = await startServer({ namedDestinations: { openbao: {
    type: 'vault', address: `http://127.0.0.1:${mock.port}`,
    path: 'secret/data/owners/owner-a/connections/connection-a', token: 'writer-token',
    preflight_path_prefix: 'secret/data/owners/owner-a/probes',
    preflight_metadata_token: 'metadata-token',
  } } });
  try {
    const created = await request(srv.port, 'POST', '/api/session/create', {
      title: 'Connect', fields: [{ name: 'api_key', label: 'API key' }], destination: 'openbao',
    }, { Authorization: `Bearer ${srv.adminToken}` });
    assert.equal(created.status, 400);
    assert.equal(created.body.detail, 'openbao_preflight_metadata_delete_failed');
    assert.deepEqual(fs.readdirSync(srv.pendingDir), []);
  } finally {
    await srv.stop();
    await mock.close();
  }
});

test('OpenBao submission without a KV-v2 version receipt does not report done', async () => {
  const mock = await startMockServer((req, res) => {
    req.resume();
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/v1/sys/capabilities-self') {
      return res.end(JSON.stringify({ capabilities: ['create', 'update'] }));
    }
    if (req.method === 'POST') {
      return res.end(JSON.stringify(req.url.includes('/probes/') ? { data: { version: 1 } } : {}));
    }
    if (req.method === 'GET') return res.end(JSON.stringify({ data: { current_version: 1 } }));
    res.writeHead(204).end();
  });
  const srv = await startServer({ namedDestinations: { openbao: {
    type: 'vault', address: `http://127.0.0.1:${mock.port}`,
    path: 'secret/data/owners/owner-a/connections/connection-a', token: 'writer-token',
    preflight_path_prefix: 'secret/data/owners/owner-a/probes',
    preflight_metadata_token: 'metadata-token',
  } } });
  try {
    const created = await request(srv.port, 'POST', '/api/session/create', {
      title: 'Connect', fields: [{ name: 'api_key', label: 'API key' }], destination: 'openbao',
    }, { Authorization: `Bearer ${srv.adminToken}` });
    assert.equal(created.status, 200);
    const submitted = await request(srv.port, 'POST', `/f/${created.body.token}`,
      { t: created.body.token, fields: { api_key: 'real-secret' } });
    assert.equal(submitted.status, 500);
    assert.equal(submitted.body.error, 'failed to save credentials');
    assert.ok(fs.existsSync(path.join(srv.pendingDir, `${created.body.token}.json`)));
    assert.ok(!fs.existsSync(path.join(srv.pendingDir, `${created.body.token}.done`)));
  } finally {
    await srv.stop();
    await mock.close();
  }
});

test('macOS Keychain hashes long account identities deterministically before invoking helper', async () => {
  const { saveToDestination } = require('../src/destinations');
  const { spawn } = require('node:child_process');
  const originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
  const originalHelper = process.env.ZEROCREDS_KEYCHAIN_HELPER;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-keychain-helper-'));
  const argsFile = path.join(root, 'args.json');
  const helper = path.join(root, 'helper');
  fs.writeFileSync(helper, `#!/usr/bin/env node\nrequire('fs').writeFileSync(${JSON.stringify(argsFile)}, JSON.stringify(process.argv.slice(2))); process.stdin.resume(); process.stdin.on('end', () => process.exit(0));\n`, { mode: 0o700 });
  process.env.ZEROCREDS_KEYCHAIN_HELPER = helper;
  Object.defineProperty(process, 'platform', { value: 'darwin' });
  try {
    const requestedAccount = `hostland-${'a'.repeat(125)}`;
    const saved = await saveToDestination({ type: 'macos_keychain', service: 'zerocreds', account: '{{service}}-{{uid}}' },
      { password: 'synthetic-secret' }, { context: { service: 'hostland', uid: 'a'.repeat(125) } });
    const args = JSON.parse(fs.readFileSync(argsFile, 'utf8'));
    assert.equal(args[0], 'set');
    assert.equal(args[1], 'zerocreds');
    assert.match(args[2], /^zc-[a-f0-9]{64}$/);
    assert.equal(args[2], `zc-${require('node:crypto').createHash('sha256').update(requestedAccount).digest('hex')}`);
    assert.equal(saved.secret_id, `keychain:zerocreds/${args[2]}`);
    assert.ok(!args.includes('synthetic-secret'));
  } finally {
    if (originalPlatform) Object.defineProperty(process, 'platform', originalPlatform);
    else delete process.platform;
    if (originalHelper === undefined) delete process.env.ZEROCREDS_KEYCHAIN_HELPER;
    else process.env.ZEROCREDS_KEYCHAIN_HELPER = originalHelper;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('failed credential save returns safe diagnostics and form includes Copy details action', async () => {
  const originalHelper = process.env.ZEROCREDS_KEYCHAIN_HELPER;
  process.env.ZEROCREDS_KEYCHAIN_HELPER = '/nonexistent/zerocreds-keychain-for-test';
  try {
  const created = await request(ctx.port, 'POST', '/api/session/create', {
    title: 'Keychain diagnostics', fields: [{ name: 'password', label: 'Password', type: 'password' }],
    destination: { type: 'macos_keychain', service: 'zerocreds', account: 'test-account' },
  }, auth());
  assert.equal(created.status, 200);
  const form = await request(ctx.port, 'GET', created.body.url.replace('http://test.local', ''));
  assert.match(form.raw, /Copy details/);
  const submitted = await request(ctx.port, 'POST', `/f/${created.body.token}`,
    { t: created.body.token, fields: { password: 'synthetic-secret-must-not-return' } });
  assert.equal(submitted.status, 500);
  assert.equal(submitted.body.error_code, 'KEYCHAIN_WRITE_FAILED');
  assert.match(submitted.body.diagnostic, /^zc-[a-f0-9]{12}$/);
  assert.ok(submitted.body.message);
  assert.ok(!JSON.stringify(submitted.body).includes('synthetic-secret-must-not-return'));
  } finally {
    if (originalHelper === undefined) delete process.env.ZEROCREDS_KEYCHAIN_HELPER;
    else process.env.ZEROCREDS_KEYCHAIN_HELPER = originalHelper;
  }
});

// ── GET /api/destinations ──────────────────────────────────────────────────────

test('GET /api/destinations — returns named destination types, no credentials', async () => {
  // Start a fresh server with named destinations configured
  const namedDestinations = {
    'prod-gcp': { type: 'gcp_secret_manager', secret: 'projects/p/secrets/s', credentials: 'base64key' },
    'local-dev': { type: 'local_file', uid: '123', filename: 'gh' },
  };
  const srv = await startServer({ namedDestinations });
  try {
    const res = await request(srv.port, 'GET', '/api/destinations', undefined,
      { Authorization: `Bearer ${srv.adminToken}` });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.destinations, {
      'prod-gcp': { type: 'gcp_secret_manager' },
      'local-dev': { type: 'local_file' },
    });
    // Must not expose credentials
    assert.equal(res.body.destinations['prod-gcp'].credentials, undefined);
    assert.equal(res.body.destinations['local-dev'].uid, undefined);
  } finally {
    await srv.stop();
  }
});

test('GET /api/destinations — unauthenticated → 401', async () => {
  const res = await request(ctx.port, 'GET', '/api/destinations');
  assert.equal(res.status, 401);
});

test('GET /api/destinations — integrator sees admin + own destinations merged', async () => {
  const namedDestinations = {
    'admin-dest': { type: 'gcp_secret_manager', secret: 'projects/p/secrets/s', credentials: 'key' },
  };
  const integratorToken = 'test-integrator-token-abc';
  const integrators = {
    [integratorToken]: {
      id: 'myintegrator',
      name: 'My Integrator',
      destinations: {
        'my-dest': { type: 'local_file', uid: '99', filename: 'mine' },
        'admin-dest': { type: 'local_file', uid: '00', filename: 'override' }, // overrides admin
      },
      created: new Date().toISOString(),
    },
  };
  const srv = await startServer({ namedDestinations, integrators });
  try {
    const res = await request(srv.port, 'GET', '/api/destinations', undefined,
      { Authorization: `Bearer ${integratorToken}` });
    assert.equal(res.status, 200);
    // Integrator's admin-dest overrides the admin one
    assert.deepEqual(res.body.destinations['admin-dest'], { type: 'local_file' });
    assert.deepEqual(res.body.destinations['my-dest'], { type: 'local_file' });
    // No credentials leaked
    assert.equal(res.body.destinations['my-dest'].uid, undefined);
  } finally {
    await srv.stop();
  }
});

// ── {{uid}} template in local_file destination ────────────────────────────────

test('local_file — {{uid}} template in uid field → resolved from session uid', async () => {
  const sessionUid = '88099';
  const dest = { type: 'local_file', uid: '{{uid}}', filename: 'creds' };
  const body = { title: 'T', fields: [{ name: 'tok', label: 'Token' }], destination: dest, uid: sessionUid };
  const r1 = await request(ctx.port, 'POST', '/api/session/create', body, auth());
  assert.equal(r1.status, 200);
  const token = r1.body.token;
  const r2 = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { tok: 'secret123' } });
  assert.equal(r2.status, 200);
  const written = JSON.parse(fs.readFileSync(path.join(tokenDir(sessionUid), 'creds'), 'utf8'));
  assert.ok(written.tok === 'secret123' || written.value === 'secret123');
});

test('local_file — {{uid}} template in filename → resolved from session uid', async () => {
  const sessionUid = '88098';
  const dest = { type: 'local_file', uid: '88098', filename: '{{uid}}' };
  const body = { title: 'T', fields: [{ name: 'tok', label: 'Token' }], destination: dest, uid: sessionUid };
  const r1 = await request(ctx.port, 'POST', '/api/session/create', body, auth());
  assert.equal(r1.status, 200);
  const token = r1.body.token;
  const r2 = await request(ctx.port, 'POST', `/f/${token}`, { t: token, fields: { tok: 'val' } });
  assert.equal(r2.status, 200);
  assert.ok(fs.existsSync(path.join(tokenDir('88098'), sessionUid)));
});

test('partial multi-destination save is uncertain and cannot be submitted again', async () => {
  const mock = await startMockServer((req, res) => {
    req.resume();
    req.on('end', () => res.writeHead(500).end('{}'));
  });
  try {
    const created = await request(ctx.port, 'POST', '/api/session/create', {
      title: 'T', fields: [
        { name: 'token', label: 'Token', level: 'secret' },
        { name: 'email', label: 'Email', level: 'pii' },
      ],
      destinations_by_level: {
        secret: { type: 'local_file', uid: 'partial-audit', filename: 'first' },
        pii: { type: 'http_post', url: `http://127.0.0.1:${mock.port}/second` },
      }, test_destination: false,
    }, auth());
    assert.equal(created.status, 200);
    const token = created.body.token;
    const payload = { t: token, fields: { token: 'invented', email: 'invented@example.test' } };
    const submitted = await request(ctx.port, 'POST', `/f/${token}`, payload);
    assert.equal(submitted.status, 500);
    assert.equal(submitted.body.outcome, 'unknown');
    assert.equal(submitted.body.retry_safe, false);
    assert.equal(fs.existsSync(path.join(tokenDir('partial-audit'), 'first')), true);
    const status = await request(ctx.port, 'GET', `/api/session/${token}/status`, undefined, auth());
    assert.equal(status.body.status, 'unknown');
    assert.equal((await request(ctx.port, 'POST', `/f/${token}`, payload)).status, 403);
  } finally { await mock.close(); }
});
