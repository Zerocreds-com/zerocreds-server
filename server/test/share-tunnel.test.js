'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { createApp } = require('../src/server');
const { createPeerShare, claimPeerShare, parseInvite } = require('../src/local-share');
const { createDirectShareEndpoints, tunnelOrigin } = require('../src/direct-share');

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
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const text = await response.text();
  let parsed = {};
  try { parsed = JSON.parse(text); } catch { parsed = { raw: text }; }
  return { status: response.status, body: parsed };
}

// A stand-in for a tunnel client: it accepts plain HTTP on a public-looking
// address and forwards every request to the loopback port the sender started.
// It sees the ciphertext only, exactly like a real tunnel operator.
function startFakeTunnel(targetPort) {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const fwdHeaders = { 'Content-Type': req.headers['content-type'] || 'application/json' };
        if (req.headers['authorization']) fwdHeaders.Authorization = req.headers['authorization'];
        const upstream = await fetch(`http://127.0.0.1:${targetPort}${req.url}`, {
          method: req.method, headers: fwdHeaders,
          ...(chunks.length ? { body: Buffer.concat(chunks) } : {}), redirect: 'error' });
        res.writeHead(upstream.status, { 'Content-Type': upstream.headers.get('content-type') || 'application/json' });
        res.end(Buffer.from(await upstream.arrayBuffer()));
      } catch { res.writeHead(502).end(); }
    });
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({
    // "localhost" is used instead of the numeric address so the tunnel origin
    // policy applies exactly as it does for a real https tunnel hostname.
    url: `http://localhost:${server.address().port}`,
    stop: () => new Promise(done => server.close(done)) })));
}

test('tunnel origins accept only plain https hosts and reject everything else', () => {
  assert.equal(tunnelOrigin('https://example.trycloudflare.com'), 'https://example.trycloudflare.com');
  assert.equal(tunnelOrigin('https://example.com:8443'), 'https://example.com:8443');
  for (const value of ['http://example.com', 'http://8.8.8.8:3457', 'https://user:pass@example.com',
    'https://example.com/path', 'https://example.com/?x=1', 'https://example.com/#f', 'example.com', '']) {
    assert.throws(() => tunnelOrigin(value), /tunnel share URL/);
  }
  // Loopback is reachable only in tests, never in production.
  assert.throws(() => tunnelOrigin('http://127.0.0.1:3458'));
  assert.equal(tunnelOrigin('http://127.0.0.1:3458', { allowLoopback: true }), 'http://127.0.0.1:3458');
});

test('a tunnel invitation is accepted only from a confirmed origin', () => {
  const link = `https://abc.trycloudflare.com/api/share-relay/invite/${'a'.repeat(32)}#${'b'.repeat(64)}`;
  const parsed = parseInvite(link, 'https://zerocreds.ru');
  assert.equal(parsed.origin, 'https://abc.trycloudflare.com');
  assert.equal(parsed.trust_class, 'tunnel');
  assert.equal(parsed.trusted, false);
  const trusted = parseInvite(link, 'https://zerocreds.ru', { allowedOrigins: ['https://abc.trycloudflare.com'] });
  assert.equal(trusted.trusted, true);
  const relay = parseInvite(`https://zerocreds.ru/api/share-relay/invite/${'a'.repeat(32)}#${'b'.repeat(64)}`,
    'https://zerocreds.ru');
  assert.equal(relay.trust_class, 'relay');
  assert.equal(relay.trusted, true);
});

test('a claim from an unconfirmed tunnel origin is refused before anything is written', async () => {
  const tunnelPort = await freePort();
  const tunnel = await startFakeTunnel(tunnelPort);
  const tunnelUrl = tunnel.url;
  const endpoint = createDirectShareEndpoints({ publicUrl: tunnelUrl, tunnelPort, allowLoopback: true });
  const { localUrl, publicUrl } = await endpoint.start();
  let share;
  try {
    share = await createPeerShare({ relayUrl: localUrl, publicUrl, allowLoopback: true,
      pollIntervalMs: 10, ttlMinutes: 1,
      metadata: { provider: 'example', account_alias: 'work', setup_prompt: 'Set up the example project.' },
      readCredential: async () => ({ token: 'synthetic-tunnel-value' }) });
    const writes = [];
    await assert.rejects(() => claimPeerShare(share.url, async (_meta, fields) => {
      writes.push(fields);
      return { connection_id: 'tunnel-recipient' };
    }, { relayUrl: 'https://zerocreds.ru', allowLoopback: true, pollIntervalMs: 10 }), error => {
      assert.equal(error.code, 'origin_confirmation_required');
      assert.equal(error.origin, tunnelUrl);
      assert.equal(error.trust_class, 'tunnel');
      return true;
    });
    assert.deepEqual(writes, [], 'nothing may be written before the origin is confirmed');
  } finally {
    share?.close();
    await endpoint.stop();
    await tunnel.stop();
  }
});

test('a confirmed tunnel origin delivers the sealed credential to the recipient', async () => {
  const tunnelPort = await freePort();
  const tunnel = await startFakeTunnel(tunnelPort);
  const tunnelUrl = tunnel.url;
  const endpoint = createDirectShareEndpoints({ publicUrl: tunnelUrl, tunnelPort, allowLoopback: true });
  const { localUrl, publicUrl } = await endpoint.start();
  let share;
  try {
    share = await createPeerShare({ relayUrl: localUrl, publicUrl, allowLoopback: true,
      pollIntervalMs: 10, ttlMinutes: 1,
      metadata: { provider: 'example', account_alias: 'work', setup_prompt: 'Set up the example project.' },
      readCredential: async () => ({ token: 'synthetic-tunnel-value' }) });
    const writes = [];
    const saved = await claimPeerShare(share.url, async (_meta, fields) => {
      writes.push(fields);
      return { connection_id: 'tunnel-recipient' };
    }, { relayUrl: 'https://zerocreds.ru', allowLoopback: true, pollIntervalMs: 10,
      allowedOrigins: [tunnelUrl], confirmOrigin: true });
    assert.equal(saved.status, 'saved');
    assert.deepEqual(writes, [{ token: 'synthetic-tunnel-value' }]);
    assert.ok(!JSON.stringify(saved).includes('synthetic-tunnel-value'));
  } finally {
    share?.close();
    await endpoint.stop();
    await tunnel.stop();
  }
});

test('the tunnel endpoint keeps owner operations on loopback and serves only recipient operations publicly', async () => {
  const tunnelPort = await freePort();
  const endpoint = createDirectShareEndpoints({ publicUrl: 'https://abc.trycloudflare.com',
    tunnelPort, allowLoopback: true });
  const { localUrl } = await endpoint.start();
  try {
    assert.equal((await fetch(`http://127.0.0.1:${tunnelPort}/api/local/connections`)).status, 404);
    assert.equal((await fetch(`http://127.0.0.1:${tunnelPort}/api/share-relay/sessions`, { method: 'POST' })).status, 404);
    assert.equal((await fetch(`http://127.0.0.1:${tunnelPort}/api/share-relay/sessions/${'a'.repeat(32)}/poll`)).status, 404);
    const page = await fetch(`http://127.0.0.1:${tunnelPort}/api/share-relay/invite/${'a'.repeat(32)}`);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /Your colleague shared access with you/);
    assert.doesNotMatch(html, /<script/i);
    // The owner side still works over the internal loopback listener.
    assert.equal((await fetch(`${localUrl}/api/share-relay/probe/${'b'.repeat(32)}`)).status, 404);
  } finally {
    await endpoint.stop();
  }
});

test('the local API publishes a share through a tunnel without touching the ZeroCreds website', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-tunnel-share-'));
  const adminToken = 'tunnel-share-admin-' + 'x'.repeat(32);
  const sourcePort = await freePort();
  const recipientPort = await freePort();
  const tunnelLocalPort = await freePort();
  const sourceId = 'a'.repeat(32);
  const sourceCatalog = path.join(root, 'source-catalog.json');
  fs.writeFileSync(sourceCatalog, JSON.stringify([{ connection_id: sourceId, provider: 'example',
    account_alias: 'work', storage: 'keychain:zerocreds/example-work', state: 'active',
    credential_version: 'v1', credential_expires_at: null }]));
  const options = (name, catalog) => ({ adminToken, localMode: true, allowLoopbackShares: true,
    shareRelayUrl: 'https://zerocreds.ru', localCatalogFile: catalog,
    pendingDir: path.join(root, `${name}-pending`), tokensDir: path.join(root, `${name}-tokens`),
    destinationsFile: path.join(root, `${name}-destinations.json`),
    integratorsFile: path.join(root, `${name}-integrators.json`),
    signingKeyFile: path.join(root, `${name}-signing.pem`),
    shareTunnelConfigFile: path.join(root, `${name}-tunnel.json`),
    shareTrustedOriginsFile: path.join(root, `${name}-origins.json`) });
  const source = createApp({ ...options('source', sourceCatalog),
    baseUrl: `http://127.0.0.1:${sourcePort}`,
    localCredentialExists: async () => 'present',
    localCredentialReader: async () => ({ token: 'synthetic-tunnel-credential' }) });
  const recipientCatalog = path.join(root, 'recipient-catalog.json');
  fs.writeFileSync(recipientCatalog, '[]');
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
  let tunnel;
  try {
    // The tunnel client forwards to the sender's loopback port.
    tunnel = await startFakeTunnel(tunnelLocalPort);
    const tunnelUrl = tunnel.url;
    const setup = await request(sourceUrl, 'POST', '/api/local/shares/tunnel/setup', adminToken,
      { base_url: tunnelUrl, local_port: tunnelLocalPort });
    assert.equal(setup.status, 200, JSON.stringify(setup.body));
    assert.equal(setup.body.probe, 'ok');
    assert.equal(setup.body.trust_class, 'network-provider');
    assert.equal(setup.body.tunnel_url, tunnelUrl);
    const saved = JSON.parse(fs.readFileSync(path.join(root, 'source-tunnel.json')));
    assert.equal(saved.base_url, tunnelUrl);
    assert.ok(saved.verified_at);

    const listed = await request(sourceUrl, 'GET', '/api/local/shares/options', adminToken);
    assert.equal(listed.body.tunnel_configured, true);
    assert.equal(listed.body.tunnel_url, tunnelUrl);
    const tunnelDescriptor = listed.body.transports.find(item => item.kind === 'tunnel');
    assert.equal(tunnelDescriptor.available, true);
    assert.equal(tunnelDescriptor.can_read_credential, false);
    assert.equal(tunnelDescriptor.trust, 'network-provider');
    assert.ok(tunnelDescriptor.description.length > 0);
    for (const descriptor of listed.body.transports) {
      assert.equal(descriptor.can_read_credential, false);
      assert.ok(descriptor.description.length > 0);
    }

    const created = await request(sourceUrl, 'POST', '/api/local/shares', adminToken,
      { connection_id: sourceId, setup_prompt: 'Configure the example service.', ttl_minutes: 1, transport: 'tunnel' });
    assert.equal(created.status, 200, JSON.stringify(created.body));
    assert.equal(created.body.transport, 'tunnel');
    assert.equal(created.body.trust_class, 'network-provider');
    assert.ok(created.body.share_url.startsWith(`${tunnelUrl}/api/share-relay/invite/`));

    // The recipient must confirm the unfamiliar host before anything is saved.
    const refused = await request(recipientUrl, 'POST', '/api/local/shares/claim', adminToken,
      { share_url: created.body.share_url });
    assert.equal(refused.status, 409);
    assert.equal(refused.body.error, 'origin_confirmation_required');
    assert.equal(refused.body.origin, tunnelUrl);
    assert.equal(refused.body.trust_class, 'tunnel');
    assert.deepEqual(writes, []);

    const claimed = await request(recipientUrl, 'POST', '/api/local/shares/claim', adminToken,
      { share_url: created.body.share_url, confirm_origin: true });
    assert.equal(claimed.status, 200, JSON.stringify(claimed.body));
    assert.deepEqual(writes, [{ token: 'synthetic-tunnel-credential' }]);
    // The confirmed host is remembered for this machine.
    const remembered = JSON.parse(fs.readFileSync(path.join(root, 'recipient-origins.json')));
    assert.deepEqual(remembered, [tunnelUrl]);
  } finally {
    await tunnel?.stop();
    await Promise.all([source, recipient].map(app => new Promise(resolve => app.close(resolve))));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the tunnel listener stays bound so the tunnel keeps forwarding after a share ends', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-tunnel-persist-'));
  const adminToken = 'tunnel-persist-admin-' + 'x'.repeat(32);
  const sourcePort = await freePort();
  const tunnelLocalPort = await freePort();
  const sourceId = 'a'.repeat(32);
  const sourceCatalog = path.join(root, 'source-catalog.json');
  fs.writeFileSync(sourceCatalog, JSON.stringify([{ connection_id: sourceId, provider: 'example',
    account_alias: 'work', storage: 'keychain:zerocreds/example-work', state: 'active',
    credential_version: 'v1', credential_expires_at: null }]));
  const source = createApp({ adminToken, localMode: true, allowLoopbackShares: true,
    baseUrl: `http://127.0.0.1:${sourcePort}`, shareRelayUrl: 'https://zerocreds.ru',
    localCatalogFile: sourceCatalog, pendingDir: path.join(root, 'pending'),
    tokensDir: path.join(root, 'tokens'), destinationsFile: path.join(root, 'destinations.json'),
    integratorsFile: path.join(root, 'integrators.json'), signingKeyFile: path.join(root, 'signing.pem'),
    shareTunnelConfigFile: path.join(root, 'tunnel.json'),
    directShareSweepIntervalMs: 25,
    localCredentialExists: async () => 'present',
    localCredentialReader: async () => ({ token: 'synthetic-persist-value' }) });
  const sourceUrl = await listen(source, sourcePort);
  const tunnel = await startFakeTunnel(tunnelLocalPort);
  try {
    const setup = await request(sourceUrl, 'POST', '/api/local/shares/tunnel/setup', adminToken,
      { base_url: tunnel.url, local_port: tunnelLocalPort });
    assert.equal(setup.status, 200, JSON.stringify(setup.body));
    const created = await request(sourceUrl, 'POST', '/api/local/shares', adminToken,
      { connection_id: sourceId, setup_prompt: 'Configure the example service.', ttl_minutes: 1, transport: 'tunnel' });
    assert.equal(created.status, 200, JSON.stringify(created.body));
    // The tunnel target must still answer after the share is over: a tunnel
    // that loses its local target usually refuses new connections.
    await new Promise(resolve => setTimeout(resolve, 150));
    const probe = await fetch(`${tunnel.url}/api/share-relay/invite/${'a'.repeat(32)}`,
      { signal: AbortSignal.timeout(5000) });
    assert.equal(probe.status, 200);
    await probe.body?.cancel().catch(() => {});
  } finally {
    await tunnel.stop();
    await new Promise(resolve => source.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a tunnel URL that does not reach this computer never becomes an invitation link', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-tunnel-unreachable-'));
  const adminToken = 'tunnel-unreachable-admin-' + 'x'.repeat(32);
  const sourcePort = await freePort();
  const sourceId = 'a'.repeat(32);
  const sourceCatalog = path.join(root, 'source-catalog.json');
  fs.writeFileSync(sourceCatalog, JSON.stringify([{ connection_id: sourceId, provider: 'example',
    account_alias: 'work', storage: 'keychain:zerocreds/example-work', state: 'active',
    credential_version: 'v1', credential_expires_at: null }]));
  const source = createApp({ adminToken, localMode: true, allowLoopbackShares: true,
    baseUrl: `http://127.0.0.1:${sourcePort}`, shareRelayUrl: 'https://zerocreds.ru',
    localCatalogFile: sourceCatalog, pendingDir: path.join(root, 'pending'),
    tokensDir: path.join(root, 'tokens'), destinationsFile: path.join(root, 'destinations.json'),
    integratorsFile: path.join(root, 'integrators.json'), signingKeyFile: path.join(root, 'signing.pem'),
    shareTunnelConfigFile: path.join(root, 'tunnel.json'),
    localCredentialExists: async () => 'present',
    localCredentialReader: async () => ({ token: 'synthetic-unreachable-value' }) });
  const sourceUrl = await listen(source, sourcePort);
  try {
    const deadPort = await freePort();
    const setup = await request(sourceUrl, 'POST', '/api/local/shares/tunnel/setup', adminToken,
      { base_url: `http://127.0.0.1:${deadPort}`, local_port: await freePort() });
    assert.equal(setup.status, 503);
    assert.match(setup.body.error, /tunnel setup failed/);
    assert.ok(setup.body.next_step.includes('127.0.0.1'));
    const created = await request(sourceUrl, 'POST', '/api/local/shares', adminToken,
      { connection_id: sourceId, setup_prompt: 'Configure the example service.', transport: 'tunnel' });
    assert.equal(created.status, 503);
    assert.equal(created.body.error, 'tunnel share unavailable');
  } finally {
    await new Promise(resolve => source.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a tunnel that went stale never becomes an invitation link', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-tunnel-stale-'));
  const adminToken = 'tunnel-stale-admin-' + 'x'.repeat(32);
  const sourcePort = await freePort();
  const tunnelLocalPort = await freePort();
  const sourceId = 'a'.repeat(32);
  const sourceCatalog = path.join(root, 'source-catalog.json');
  fs.writeFileSync(sourceCatalog, JSON.stringify([{ connection_id: sourceId, provider: 'example',
    account_alias: 'work', storage: 'keychain:zerocreds/example-work', state: 'active',
    credential_version: 'v1', credential_expires_at: null }]));
  const source = createApp({ adminToken, localMode: true, allowLoopbackShares: true,
    baseUrl: `http://127.0.0.1:${sourcePort}`, shareRelayUrl: 'https://zerocreds.ru',
    localCatalogFile: sourceCatalog, pendingDir: path.join(root, 'pending'),
    tokensDir: path.join(root, 'tokens'), destinationsFile: path.join(root, 'destinations.json'),
    integratorsFile: path.join(root, 'integrators.json'), signingKeyFile: path.join(root, 'signing.pem'),
    shareTunnelConfigFile: path.join(root, 'tunnel.json'),
    localCredentialExists: async () => 'present',
    localCredentialReader: async () => ({ token: 'synthetic-stale-value' }) });
  const sourceUrl = await listen(source, sourcePort);
  let tunnel;
  try {
    tunnel = await startFakeTunnel(tunnelLocalPort);
    const setup = await request(sourceUrl, 'POST', '/api/local/shares/tunnel/setup', adminToken,
      { base_url: tunnel.url, local_port: tunnelLocalPort });
    assert.equal(setup.status, 200, JSON.stringify(setup.body));

    // The tunnel client dies: the local listener stays bound, but the public
    // address no longer reaches this computer.
    await tunnel.stop();
    const created = await request(sourceUrl, 'POST', '/api/local/shares', adminToken,
      { connection_id: sourceId, setup_prompt: 'Configure the example service.', ttl_minutes: 1, transport: 'tunnel' });
    assert.equal(created.status, 503);
    assert.match(created.body.error, /^tunnel_unreachable/);
    assert.ok(created.body.next_step.includes('share_tunnel_start'));
    assert.equal(created.body.share_url, undefined);
  } finally {
    await tunnel?.stop();
    await new Promise(resolve => source.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a share request still refuses to guess the transport', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-tunnel-choice-'));
  const adminToken = 'tunnel-choice-admin-' + 'x'.repeat(32);
  const sourcePort = await freePort();
  const source = createApp({ adminToken, localMode: true, allowLoopbackShares: true,
    baseUrl: `http://127.0.0.1:${sourcePort}`, shareRelayUrl: 'https://zerocreds.ru',
    localCatalogFile: path.join(root, 'catalog.json'), pendingDir: path.join(root, 'pending'),
    tokensDir: path.join(root, 'tokens'), destinationsFile: path.join(root, 'destinations.json'),
    integratorsFile: path.join(root, 'integrators.json'), signingKeyFile: path.join(root, 'signing.pem') });
  const sourceUrl = await listen(source, sourcePort);
  try {
    const withoutChoice = await request(sourceUrl, 'POST', '/api/local/shares', adminToken,
      { connection_id: 'a'.repeat(32), setup_prompt: 'Configure the example service.' });
    assert.equal(withoutChoice.status, 409);
    assert.equal(withoutChoice.body.error, 'transport_selection_required');
    assert.equal(withoutChoice.body.tunnel_configured, false);
    const badTransport = await request(sourceUrl, 'POST', '/api/local/shares', adminToken,
      { connection_id: 'a'.repeat(32), setup_prompt: 'Configure the example service.', transport: 'mailbox' });
    assert.equal(badTransport.status, 400);
    // The plain string form stays accepted for the existing transports.
    const legacy = await request(sourceUrl, 'POST', '/api/local/shares', adminToken,
      { connection_id: 'a'.repeat(32), setup_prompt: 'Configure the example service.', transport: 'relay' });
    assert.equal(legacy.status, 404, 'the connection itself is missing, but the transport was accepted');
  } finally {
    await new Promise(resolve => source.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});
