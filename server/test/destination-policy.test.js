'use strict';
// Production destination policy: named destinations only, https-only http_post to an
// allowlist, no private/loopback/link-local targets, and no upstream bodies echoed back.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { startServer, request } = require('./helpers');
const { saveToDestination, validateDestination, isBlockedAddress } = require('../src/destinations');

function startMockServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () =>
      resolve({ port: srv.address().port, close: () => new Promise(r => { srv.closeAllConnections(); srv.close(r); }) }),
    );
  });
}

const fields = [{ name: 'tok', label: 'Token' }];

test('strict mode — inline destination objects are rejected, named ones work', async () => {
  const srv = await startServer({ strict: true, namedDestinations: { local: { type: 'local_file', uid: '1', filename: 'n' } } });
  try {
    const auth = { Authorization: `Bearer ${srv.adminToken}` };
    const inline = await request(srv.port, 'POST', '/api/session/create',
      { title: 'T', fields, destination: { type: 'local_file', uid: '1', filename: 'x' } }, auth);
    assert.equal(inline.status, 400);
    assert.match(inline.body.error, /inline destinations are disabled/);
    const byLevel = await request(srv.port, 'POST', '/api/session/create',
      { title: 'T', fields, destinations_by_level: { default: { type: 'local_file', uid: '1', filename: 'x' } } }, auth);
    assert.equal(byLevel.status, 400);
    const named = await request(srv.port, 'POST', '/api/session/create', { title: 'T', fields, destination: 'local' }, auth);
    assert.equal(named.status, 200);
  } finally {
    await srv.stop();
  }
});

test('strict mode — integrators cannot register their own destinations', async () => {
  const srv = await startServer({ strict: true, integrators: { tok_i: { id: 'i1', name: 'I', status: 'active', destinations: {} } } });
  try {
    const r = await request(srv.port, 'POST', '/api/destinations',
      { name: 'evil', destination: { type: 'http_post', url: 'https://example.com/x' } }, { Authorization: 'Bearer tok_i' });
    assert.equal(r.status, 403);
  } finally {
    await srv.stop();
  }
});

test('strict mode — http_post must be https and on the allowlist', async () => {
  const srv = await startServer({ strict: true, app: { httpPostAllowedHosts: ['hooks.example.com'] } });
  try {
    const auth = { Authorization: `Bearer ${srv.adminToken}` };
    const add = (url) => request(srv.port, 'POST', '/api/destinations',
      { name: 'p', destination: { type: 'http_post', url } }, auth);
    assert.equal((await add('http://hooks.example.com/x')).status, 400, 'plain http rejected');
    assert.equal((await add('https://other.example.com/x')).status, 400, 'host not on allowlist');
    assert.equal((await add('https://{tok}.example.com/x')).status, 400, 'templated host');
    assert.equal((await add('https://user:pw@hooks.example.com/x')).status, 400, 'userinfo in url');
    assert.equal((await add('https://hooks.example.com/x')).status, 200);
  } finally {
    await srv.stop();
  }
});

test('http_post with no allowlist configured is disabled', () => {
  assert.match(validateDestination({ type: 'http_post', url: 'https://example.com/x' }, {}), /allowlist/);
});

test('private, loopback, link-local and metadata addresses are blocked', () => {
  for (const a of ['127.0.0.1', '10.0.0.1', '172.16.5.4', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
    '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:a9fe:a9fe', '64:ff9b::a9fe:a9fe']) {
    assert.equal(isBlockedAddress(a), true, a);
  }
  for (const a of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(isBlockedAddress(a), false, a);
  }
});

test('outbound requests refuse private targets — literal IPs and hostnames resolved at connect time', async () => {
  const opts = { httpPostAllowedHosts: ['127.0.0.1', 'localhost', '169.254.169.254', '[::1]', '::1'] };
  for (const url of ['https://127.0.0.1/x', 'https://169.254.169.254/latest/meta-data', 'https://[::1]/x', 'https://[::ffff:7f00:1]/x']) {
    await assert.rejects(saveToDestination({ type: 'http_post', url }, { a: '1' }, opts), /not allowed|allowlist/, url);
  }
  // A hostname passes static checks; the resolved address is checked when connecting.
  await assert.rejects(
    saveToDestination({ type: 'http_post', url: 'https://localhost:1/x' }, { a: '1' }, opts),
    (e) => e.code === 'EDESTBLOCKED',
  );
  await assert.rejects(
    saveToDestination({ type: 'vault', address: 'https://localhost:1', path: 'secret/x', token: 't' }, { a: '1' }, {}),
    (e) => e.code === 'EDESTBLOCKED',
  );
  assert.match(validateDestination({ type: 'vault', address: 'http://vault.example.com' }, {}), /https/);
  assert.match(validateDestination({ type: 'aws_secrets_manager', region: 'x.evil.com/#' }, {}), /region/);
});

test('upstream response bodies are never returned to the caller', async () => {
  const MARKER = 'UPSTREAM-BODY-MARKER';
  const mock = await startMockServer((req, res) => {
    req.resume();
    req.on('end', () => res.writeHead(req.url.includes('approle') ? 403 : 500).end(MARKER));
  });
  const srv = await startServer();
  try {
    const auth = { Authorization: `Bearer ${srv.adminToken}` };
    const url = `http://127.0.0.1:${mock.port}/collect`;

    const pre = await request(srv.port, 'POST', '/api/session/create',
      { title: 'T', fields, destination: { type: 'http_post', url } }, auth);
    assert.equal(pre.status, 400);
    assert.equal(pre.body.detail, 'HTTP 500');
    assert.ok(!pre.raw.includes(MARKER), 'preflight must not echo upstream body');

    for (const destination of [
      { type: 'http_post', url },
      { type: 'vault', address: `http://127.0.0.1:${mock.port}`, path: 'secret/x', token: 't' },
      { type: 'vault', address: `http://127.0.0.1:${mock.port}`, path: 'secret/x', role_id: 'r', secret_id: 's' },
    ]) {
      const s = await request(srv.port, 'POST', '/api/session/create',
        { title: 'T', fields, destination, test_destination: false }, auth);
      assert.equal(s.status, 200);
      const sub = await request(srv.port, 'POST', `/f/${s.body.token}`, { t: s.body.token, fields: { tok: 'v' } });
      assert.equal(sub.status, 500);
      assert.ok(!sub.raw.includes(MARKER), `${destination.type}: submit must not echo upstream body`);
      assert.equal(sub.body.detail, undefined);
    }
  } finally {
    await srv.stop();
    await mock.close();
  }
});
