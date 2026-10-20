'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { createApp } = require('../src/server');

async function freePort() {
  const probe = net.createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  return port;
}

async function listen(app, port = 0) {
  await new Promise(resolve => app.listen(port, '127.0.0.1', resolve));
  return `http://127.0.0.1:${app.address().port}`;
}

async function request(origin, method, route, token, body) {
  const response = await fetch(`${origin}${route}`, { method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(10000) });
  return { status: response.status, body: await response.json() };
}

test('local API sends an existing connection through remote relay and stores it on the receiver', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-share-routes-'));
  const credential = 'synthetic-value-never-in-api-results';
  const token = 'local-share-admin-' + 'x'.repeat(40);
  const sourceId = 'a'.repeat(32);
  const receiverWrites = [];
  const sourceCatalog = path.join(root, 'source-connections.json');
  const receiverCatalog = path.join(root, 'receiver-connections.json');
  fs.writeFileSync(sourceCatalog, JSON.stringify([{ connection_id: sourceId, provider: 'example',
    account_alias: 'work', storage: 'keychain:zerocreds/example-work', state: 'active',
    credential_version: 'v1', credential_expires_at: null }]));
  const relay = createApp({ adminToken: token, localMode: false, shareRelayEnabled: true,
    pendingDir: path.join(root, 'relay-pending'), tokensDir: path.join(root, 'relay-tokens'),
    integratorsFile: path.join(root, 'relay-integrators.json'), destinationsFile: path.join(root, 'relay-destinations.json'),
    signingKeyFile: path.join(root, 'relay-signing.pem') });
  const relayUrl = await listen(relay);
  const sourcePort = await freePort();
  const recipientPort = await freePort();
  function localOptions(name, catalogFile, port) {
    return { adminToken: token, localMode: true, shareRelayUrl: relayUrl, allowLoopbackShares: true,
      baseUrl: `http://127.0.0.1:${port}`,
      localCatalogFile: catalogFile, pendingDir: path.join(root, `${name}-pending`),
      tokensDir: path.join(root, `${name}-tokens`), destinationsFile: path.join(root, `${name}-destinations.json`),
      integratorsFile: path.join(root, `${name}-integrators.json`), signingKeyFile: path.join(root, `${name}-signing.pem`) };
  }
  const source = createApp({ ...localOptions('source', sourceCatalog, sourcePort),
    localCredentialExists: async () => 'present', localCredentialReader: async () => ({ token: credential }) });
  const recipient = createApp({ ...localOptions('recipient', receiverCatalog, recipientPort),
    localCredentialExists: async () => 'missing',
    localCredentialWriter: async (destination, fields) => {
      receiverWrites.push({ destination, fields });
      return { secret_id: `keychain:${destination.service}/${destination.account}` };
    } });
  const sourceUrl = await listen(source, sourcePort);
  const recipientUrl = await listen(recipient, recipientPort);
  try {
    const denied = await request(sourceUrl, 'POST', '/api/local/shares', undefined,
      { connection_id: sourceId, setup_prompt: 'Configure the example service.' });
    assert.equal(denied.status, 401);
    const created = await request(sourceUrl, 'POST', '/api/local/shares', token,
      { connection_id: sourceId, setup_prompt: 'Configure the example service.', ttl_minutes: 1 });
    assert.equal(created.status, 200);
    assert.equal(created.body.provider, 'example');
    assert.ok(!JSON.stringify(created.body).includes(credential));
    const claimed = await request(recipientUrl, 'POST', '/api/local/shares/claim', token,
      { share_url: created.body.share_url });
    assert.equal(claimed.status, 200);
    assert.equal(claimed.body.status, 'saved');
    assert.equal(claimed.body.setup_prompt, 'Configure the example service.');
    assert.ok(!JSON.stringify(claimed.body).includes(credential));
    assert.deepEqual(receiverWrites[0].fields, { token: credential });
    const catalog = JSON.parse(fs.readFileSync(receiverCatalog, 'utf8'));
    assert.equal(catalog.length, 1);
    assert.equal(catalog[0].provider, 'example');
    assert.ok(!JSON.stringify(catalog).includes(credential));
    const repeated = await request(recipientUrl, 'POST', '/api/local/shares/claim', token,
      { share_url: created.body.share_url });
    assert.equal(repeated.status, 409);
  } finally {
    await Promise.all([source, recipient, relay].map(app => new Promise(resolve => app.close(resolve))));
    fs.rmSync(root, { recursive: true, force: true });
  }
});
