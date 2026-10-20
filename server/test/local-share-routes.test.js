'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { createApp } = require('../src/server');
const { createPeerShare } = require('../src/local-share');

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
    const options = await request(sourceUrl, 'GET', '/api/local/shares/options', token);
    assert.equal(options.body.relay_url, relayUrl);
    assert.equal(options.body.choice_required, true);
    const withoutChoice = await request(sourceUrl, 'POST', '/api/local/shares', token,
      { connection_id: sourceId, setup_prompt: 'Configure the example service.' });
    assert.equal(withoutChoice.status, 409);
    assert.equal(withoutChoice.body.error, 'transport_selection_required');
    const created = await request(sourceUrl, 'POST', '/api/local/shares', token,
      { connection_id: sourceId, setup_prompt: 'Configure the example service.', ttl_minutes: 1, transport: 'relay' });
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

test('local API shares by direct IP after explicit choice, with no hosted relay request', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-direct-share-routes-'));
  const adminToken = 'direct-share-admin-' + 'x'.repeat(40);
  const sourceId = 'b'.repeat(32);
  const directPort = await freePort();
  const sourcePort = await freePort();
  const recipientPort = await freePort();
  const sourceCatalog = path.join(root, 'source.json');
  const recipientCatalog = path.join(root, 'recipient.json');
  let signalCreation;
  const creationStarted = new Promise(resolve => { signalCreation = resolve; });
  let continueCreation;
  const creationReleased = new Promise(resolve => { continueCreation = resolve; });
  fs.writeFileSync(sourceCatalog, JSON.stringify([{ connection_id: sourceId, provider: 'example',
    account_alias: 'work', storage: 'keychain:zerocreds/example-work', state: 'active',
    credential_version: 'v1', credential_expires_at: null }]));
  const options = (name, catalog) => ({ adminToken, localMode: true, allowLoopbackShares: true,
    shareRelayUrl: 'https://zerocreds.ru', localCatalogFile: catalog,
    pendingDir: path.join(root, `${name}-pending`), tokensDir: path.join(root, `${name}-tokens`),
    destinationsFile: path.join(root, `${name}-destinations.json`),
    integratorsFile: path.join(root, `${name}-integrators.json`),
    signingKeyFile: path.join(root, `${name}-signing.pem`) });
  const source = createApp({ ...options('source', sourceCatalog),
    baseUrl: `http://127.0.0.1:${sourcePort}`,
    shareDirectConfigFile: path.join(root, 'direct-config.json'),
    directShareSweepIntervalMs: 25,
    peerShareCreator: async input => {
      signalCreation();
      await creationReleased;
      return createPeerShare(input);
    },
    localCredentialExists: async () => 'present',
    localCredentialReader: async () => ({ token: 'synthetic-direct-credential' }) });
  const writes = [];
  const recipient = createApp({ ...options('recipient', recipientCatalog),
    baseUrl: `http://127.0.0.1:${recipientPort}`,
    localCredentialExists: async () => 'missing',
    localCredentialWriter: async (destination, fields) => {
      writes.push(fields);
      return { secret_id: `keychain:${destination.service}/${destination.account}` };
    } });
  const sourceUrl = await listen(source, sourcePort);
  const recipientUrl = await listen(recipient, recipientPort);
  try {
    const setup = await request(sourceUrl, 'POST', '/api/local/shares/direct/setup', adminToken,
      { public_url: `http://127.0.0.1:${directPort}` });
    assert.equal(setup.status, 200);
    assert.equal(setup.body.local_listener_ready, true);
    assert.equal(setup.body.external_reachability_verified, false);
    assert.equal(JSON.parse(fs.readFileSync(path.join(root, 'direct-config.json'))).public_url,
      `http://127.0.0.1:${directPort}`);
    const optionsResult = await request(sourceUrl, 'GET', '/api/local/shares/options', adminToken);
    assert.equal(optionsResult.body.direct_configured, true);
    const withoutChoice = await request(sourceUrl, 'POST', '/api/local/shares', adminToken,
      { connection_id: sourceId, setup_prompt: 'Configure the example service.' });
    assert.equal(withoutChoice.status, 409);
    const creating = request(sourceUrl, 'POST', '/api/local/shares', adminToken,
      { connection_id: sourceId, setup_prompt: 'Configure the example service.', ttl_minutes: 1, transport: 'direct' });
    await Promise.race([creationStarted, creating.then(() => { throw new Error('share creation finished before the pause'); })]);
    await new Promise(resolve => setTimeout(resolve, 100));
    const stillOpen = await fetch(`http://127.0.0.1:${directPort}/api/share-relay/invite/${'c'.repeat(32)}`);
    assert.equal(stillOpen.status, 200, 'cleanup cannot close the listener while a share is being created');
    continueCreation();
    const created = await creating;
    assert.equal(created.status, 200);
    assert.equal(created.body.transport, 'direct');
    assert.match(created.body.share_url, new RegExp(`^http://127\\.0\\.0\\.1:${directPort}/api/share-relay/invite/`));
    const page = await fetch(created.body.share_url);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Your colleague shared access with you/);
    const claimed = await request(recipientUrl, 'POST', '/api/local/shares/claim', adminToken,
      { share_url: created.body.share_url });
    assert.equal(claimed.status, 200);
    assert.deepEqual(writes, [{ token: 'synthetic-direct-credential' }]);
    let status;
    for (let attempt = 0; attempt < 30; attempt++) {
      status = (await request(sourceUrl, 'GET', `/api/local/shares/${created.body.share_id}`, adminToken)).body.status;
      if (status === 'complete') break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.equal(status, 'complete');
    let closed = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { await fetch(`http://127.0.0.1:${directPort}/api/local/connections`, { signal: AbortSignal.timeout(1000) }); }
      catch { closed = true; break; }
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert.equal(closed, true, 'direct listener closes after the last share completes');
  } finally {
    continueCreation();
    await Promise.all([source, recipient].map(app => new Promise(resolve => app.close(resolve))));
    fs.rmSync(root, { recursive: true, force: true });
  }
});
