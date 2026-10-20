'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const crypto = require('crypto');
const { saveToDestination, testDestination, validateDestination, readZerocredsVault } = require('../src/destinations');

const SERVICE_TOKEN = 'service-token-with-at-least-thirty-two-characters';

function startMockServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () =>
      resolve({ port: srv.address().port, close: () => new Promise(r => { srv.closeAllConnections(); srv.close(r); }) }));
  });
}

function custodyDestination(port, overrides = {}) {
  return {
    type: 'zerocreds_vault',
    vault_url: `http://127.0.0.1:${port}`,
    service_token: SERVICE_TOKEN,
    data_key: crypto.randomBytes(32).toString('base64'),
    key_ref: 'k1',
    connection_id: 'conn_1',
    owner_id: 'owner_1',
    profile_id: 'profile_1',
    provider: 'github',
    ...overrides,
  };
}

test('zerocreds_vault — the value is encrypted before it leaves the wallet', async () => {
  let received = null;
  const srv = await startMockServer((req, res) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      received = { method: req.method, url: req.url, headers: req.headers, body: data ? JSON.parse(data) : null };
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ version: 1, key_ref: 'k1' }));
    });
  });
  try {
    const destination = custodyDestination(srv.port);
    const result = await saveToDestination(destination, { token: 'super-secret-value' }, { allowPrivate: true });
    assert.equal(result.version, 1);
    assert.equal(received.method, 'PUT');
    assert.equal(received.url, '/internal/vault/values/conn_1');
    assert.equal(received.headers.authorization, `Bearer ${SERVICE_TOKEN}`);
    assert.equal(received.body.alg, 'A256GCM');
    assert.equal(received.body.owner_id, 'owner_1');
    assert.equal(received.body.profile_id, 'profile_1');
    assert.ok(!JSON.stringify(received.body).includes('super-secret-value'));

    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(destination.data_key, 'base64'),
      Buffer.from(received.body.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(received.body.tag, 'base64'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(received.body.ciphertext, 'base64')),
      decipher.final(),
    ]).toString('utf8');
    assert.deepEqual(JSON.parse(plain), { token: 'super-secret-value' });
  } finally {
    await srv.close();
  }
});

test('zerocreds_vault — a store that reports no version is an error', async () => {
  const srv = await startMockServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ version: 0 }));
  });
  try {
    await assert.rejects(
      () => saveToDestination(custodyDestination(srv.port), { token: 'v' }, { allowPrivate: true }),
      /did not report a version/);
  } finally {
    await srv.close();
  }
});

test('zerocreds_vault — a stored value comes back only for the run it is granted to', async () => {
  const dataKey = crypto.randomBytes(32).toString('base64');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(dataKey, 'base64'), iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(JSON.stringify({ token: 'stored-value' }), 'utf8')), cipher.final()]);
  let received = null;
  const srv = await startMockServer((req, res) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      received = { method: req.method, url: req.url, headers: req.headers, body: data ? JSON.parse(data) : null };
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ connection_id: 'conn_1', version: 4, ciphertext: ciphertext.toString('base64'),
        iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), alg: 'A256GCM', key_ref: 'k1' }));
    });
  });
  try {
    const destination = custodyDestination(srv.port, { data_key: dataKey });
    const stored = await readZerocredsVault(destination, 'run_abc_123', { allowPrivate: true });
    assert.deepEqual(stored.fields, { token: 'stored-value' });
    assert.equal(stored.version, 4);
    assert.equal(received.method, 'POST');
    assert.equal(received.url, '/internal/vault/values/conn_1/read');
    assert.equal(received.headers.authorization, `Bearer ${SERVICE_TOKEN}`);
    assert.deepEqual(received.body, { owner_id: 'owner_1', profile_id: 'profile_1', run_id: 'run_abc_123' });
    assert.ok(!JSON.stringify(received).includes('stored-value'), 'the request never carries the value');

    await assert.rejects(() => readZerocredsVault(destination, '', { allowPrivate: true }), /run reference is required/);
    await assert.rejects(() => readZerocredsVault(destination, 'run with spaces', { allowPrivate: true }), /run reference is required/);
  } finally {
    await srv.close();
  }
});

test('zerocreds_vault — a value that does not authenticate is refused', async () => {
  const iv = crypto.randomBytes(12);
  const other = crypto.createCipheriv('aes-256-gcm', crypto.randomBytes(32), iv);
  const foreign = Buffer.concat([other.update(Buffer.from('{"token":"x"}', 'utf8')), other.final()]);
  const srv = await startMockServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ connection_id: 'conn_1', version: 1, ciphertext: foreign.toString('base64'),
      iv: iv.toString('base64'), tag: other.getAuthTag().toString('base64'), alg: 'A256GCM', key_ref: 'k1' }));
  });
  try {
    await assert.rejects(
      () => readZerocredsVault(custodyDestination(srv.port), 'run_abc_123', { allowPrivate: true }),
      /did not authenticate/);
  } finally {
    await srv.close();
  }
});

test('zerocreds_vault — the configuration is validated', () => {
  const base = custodyDestination(1234);
  assert.equal(validateDestination(base, { allowPrivate: true }), null);
  assert.match(validateDestination({ ...base, data_key: Buffer.from('short').toString('base64') }, { allowPrivate: true }), /32 bytes/);
  assert.match(validateDestination({ ...base, service_token: 'short' }, { allowPrivate: true }), /service token/);
  assert.match(validateDestination({ ...base, key_ref: 'not a key ref' }, { allowPrivate: true }), /key ref/);
  assert.match(validateDestination({ ...base, connection_id: 'not a connection' }, { allowPrivate: true }), /connection id/);
  assert.match(validateDestination({ ...base, vault_url: undefined }, { allowPrivate: true }), /vault url/);
});

test('zerocreds_vault — the preflight needs a reachable store and a free slot', async () => {
  const free = await startMockServer((req, res) => {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'connection_unavailable' }));
  });
  const taken = await startMockServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ state: 'active', version: 1 }));
  });
  try {
    const ok = await testDestination(custodyDestination(free.port), { allowPrivate: true }, []);
    assert.equal(ok.checked, true);
    await assert.rejects(
      () => testDestination(custodyDestination(taken.port), { allowPrivate: true }, []),
      /already holds a value/);
  } finally {
    await free.close();
    await taken.close();
  }
});
