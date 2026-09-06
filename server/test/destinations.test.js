'use strict';
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

test('field without level, no default, no destination → warns but does not crash → 200', async () => {
  // destinations_by_level exists but has no "default" key and no fallback destination
  const uid = '88004';
  const destSecret = { type: 'local_file', uid, filename: 'creds-secret' };
  // Field has no level → key = "default", but destinations_by_level has no "default"
  const { submitRes } = await createAndSubmit(
    [{ name: 'tok', label: 'Token' }], // no level → "default"
    null,
    { secret: destSecret }, // no "default" key
  );
  // Should still return 200 — it just skips the field
  assert.equal(submitRes.status, 200);
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
    req.resume();
    res.writeHead(500).end('Internal Error');
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
