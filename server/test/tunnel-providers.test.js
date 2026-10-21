'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { createApp } = require('../src/server');
const { findTunnelProvider, tunnelProviderCatalog, TUNNEL_PROVIDERS } = require('../src/tunnel-providers');
const { startTunnelProcess, stopTunnelProcess, isProcessAlive, processStartTime } = require('../src/tunnel-runner');

const FIXTURE_DIR = path.join(__dirname, 'fixtures');
const FIXTURE = path.join(FIXTURE_DIR, 'fake-tunnel-client.js');
const adminToken = 'tunnel-provider-admin-token-1234567890';

async function freePort() {
  const probe = net.createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  return port;
}

async function request(origin, method, route, body) {
  const response = await fetch(`${origin}${route}`, { method,
    headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const text = await response.text();
  let parsed = {};
  try { parsed = JSON.parse(text); } catch { parsed = { raw: text }; }
  return { status: response.status, body: parsed };
}

// Wait until the condition holds or the deadline passes, so the tests do not
// depend on a fixed sleep.
async function until(condition, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (condition()) return true;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  return condition();
}

// A provider that runs the fixture instead of a real tunnel client. The
// command comes from the catalog, exactly like a real one.
function syntheticProvider(port) {
  return {
    id: 'synthetic',
    label: 'Synthetic tunnel used by the tests',
    operator: 'Synthetic operator',
    trust_class: 'network-provider',
    binary: process.execPath,
    account: null,
    command: () => [process.execPath, FIXTURE, String(port)],
    url_pattern: /http:\/\/localhost:\d+/i,
    notes: 'Synthetic provider.',
  };
}

function localConfig(root, extra = {}) {
  return { adminToken, localMode: true, allowLoopbackShares: true,
    baseUrl: 'http://127.0.0.1:0', shareRelayUrl: 'https://zerocreds.ru',
    localCatalogFile: path.join(root, 'connections.json'),
    pendingDir: path.join(root, 'pending'), tokensDir: path.join(root, 'tokens'),
    destinationsFile: path.join(root, 'destinations.json'),
    integratorsFile: path.join(root, 'integrators.json'), signingKeyFile: path.join(root, 'signing.pem'),
    shareTunnelConfigFile: path.join(root, 'tunnel.json'),
    directShareSweepIntervalMs: 25,
    localCredentialExists: async () => 'present',
    localCredentialReader: async () => ({ token: 'synthetic-value' }), ...extra };
}

test('the catalog carries a ready command for every provider', () => {
  const catalog = tunnelProviderCatalog(3458);
  assert.equal(catalog.length, TUNNEL_PROVIDERS.length);
  for (const entry of catalog) {
    assert.ok(entry.id && entry.label && entry.operator, `${entry.id} is described`);
    assert.ok(entry.command.includes('3458'), `${entry.id} points at the local port`);
    assert.equal(entry.trust_class, 'network-provider', `${entry.id} states its trust class`);
    assert.ok(entry.notes.length > 10, `${entry.id} explains itself to the owner`);
  }
  const byId = Object.fromEntries(catalog.map(entry => [entry.id, entry]));
  assert.match(byId['localhost-run'].command, /-R 80:localhost:3458 nokey@localhost\.run/);
  assert.match(byId['cloudflared'].command, /--url http:\/\/127\.0\.0\.1:3458/);
  assert.match(byId.ngrok.command, /http 3458/);
  assert.equal(byId.ngrok.needs_account, true);
  assert.equal(byId.ngrok.missing.includes('account:ngrok'), true);
});

test('the command of a provider is an argument list, never a shell string', () => {
  for (const provider of TUNNEL_PROVIDERS) {
    const args = provider.command(3458);
    assert.ok(Array.isArray(args) && args.length > 0, `${provider.id} runs an argument list`);
    assert.ok(args.every(argument => typeof argument === 'string'), `${provider.id} uses strings only`);
    assert.equal(args.some(argument => /[;&|`$]/.test(argument)), false,
      `${provider.id} carries no shell operator`);
  }
});

test('an unknown provider is not found', () => {
  assert.equal(findTunnelProvider('nope'), null);
  assert.equal(findTunnelProvider(''), null);
  assert.equal(findTunnelProvider(undefined), null);
  assert.equal(findTunnelProvider('localhost-run').id, 'localhost-run');
});

test('each provider reads its own published address out of the captured output', () => {
  const samples = {
    'localhost-run': { file: 'localhost-run-output.txt', expected: 'https://synthetic0000.lhr.life' },
    cloudflared: { file: 'cloudflared-output.txt', expected: 'https://synthetic0000.trycloudflare.com' },
    ngrok: { file: 'ngrok-output.txt', expected: 'https://synthetic0000.ngrok-free.app' },
  };
  for (const provider of TUNNEL_PROVIDERS) {
    const sample = samples[provider.id];
    assert.ok(sample, `${provider.id} has a captured output`);
    const text = fs.readFileSync(path.join(FIXTURE_DIR, sample.file), 'utf8');
    const match = text.match(provider.url_pattern);
    assert.ok(match, `${provider.id} finds its address in the captured output`);
    assert.equal(match[0], sample.expected);
    assert.equal(provider.url_pattern.test('https://unrelated.invalid/x'), false);
  }
});

test('a provider whose client is missing is reported as unavailable', () => {
  const [entry] = tunnelProviderCatalog(3458, [{
    id: 'absent', label: 'Absent provider', operator: 'Nobody', trust_class: 'network-provider',
    binary: 'zerocreds-absent-tunnel-client', account: null,
    command: () => ['zerocreds-absent-tunnel-client'], url_pattern: /https:\/\/[a-z0-9-]+\.invalid/i,
    notes: 'Synthetic provider.' }]);
  assert.equal(entry.installed, false);
  assert.equal(entry.available, false);
  assert.deepEqual(entry.missing, ['binary:zerocreds-absent-tunnel-client']);
});

test('the tunnel process publishes an address and can be stopped', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-tunnel-runner-'));
  const logFile = path.join(root, 'tunnel.log');
  let started;
  try {
    started = await startTunnelProcess({ command: [process.execPath, FIXTURE, String(await freePort())],
      urlPattern: /http:\/\/localhost:\d+/i, logFile, label: 'Synthetic tunnel' });
    assert.match(started.url, /^http:\/\/localhost:\d+$/);
    assert.ok(started.pid > 0);
    assert.ok(fs.existsSync(logFile));
    // The log holds the published address of the tunnel, so it stays private.
    assert.equal(fs.statSync(logFile).mode & 0o077, 0);
    assert.match(fs.readFileSync(logFile, 'utf8'), /synthetic0000\.synthetic-tunnel\.test/);
    assert.equal(isProcessAlive(started.pid), true);
    assert.equal(stopTunnelProcess(started.pid), true);
    assert.equal(await until(() => !isProcessAlive(started.pid)), true);
  } finally {
    if (started) stopTunnelProcess(started.pid);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a stale address from an earlier run is not taken for the new one', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-tunnel-stale-'));
  const logFile = path.join(root, 'tunnel.log');
  // A log that already holds the address of an earlier tunnel.
  fs.writeFileSync(logFile, 'https://stale0000.lhr.life tunneled with tls termination\n', { mode: 0o600 });
  let started;
  try {
    started = await startTunnelProcess({ command: [process.execPath, FIXTURE, String(await freePort())],
      urlPattern: /http:\/\/localhost:\d+/i, logFile, label: 'Synthetic tunnel' });
    assert.match(started.url, /^http:\/\/localhost:\d+$/);
    assert.equal(started.url.includes('stale0000'), false);
  } finally {
    if (started) stopTunnelProcess(started.pid);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a missing tunnel client fails in plain words', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-tunnel-missing-'));
  try {
    await assert.rejects(() => startTunnelProcess({ command: ['zerocreds-absent-tunnel-client'],
      urlPattern: /https:\/\/[a-z0-9-]+\.invalid/i, logFile: path.join(root, 'tunnel.log'),
      label: 'Absent provider' }), /not installed on this computer/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the server lists the ready-made providers and raises one of them', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-tunnel-providers-'));
  const tunnelPort = await freePort();
  const serverPort = await freePort();
  const app = createApp(localConfig(root, { baseUrl: `http://127.0.0.1:${serverPort}`,
    shareTunnelPort: tunnelPort, shareTunnelProviders: [syntheticProvider(tunnelPort)] }));
  await new Promise(resolve => app.listen(serverPort, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${serverPort}`;
  try {
    const providers = await request(origin, 'GET', '/api/local/shares/tunnel/providers');
    assert.equal(providers.status, 200);
    assert.equal(providers.body.providers.length, 1);
    assert.equal(providers.body.providers[0].id, 'synthetic');
    assert.equal(providers.body.providers[0].available, true);
    assert.equal(providers.body.local_port, tunnelPort);
    assert.equal(providers.body.configured, false);
    assert.equal(providers.body.configured_by, null);

    const started = await request(origin, 'POST', '/api/local/shares/tunnel/start', { provider: 'synthetic' });
    assert.equal(started.status, 200, JSON.stringify(started.body));
    assert.equal(started.body.probe, 'ok');
    assert.equal(started.body.provider, 'synthetic');
    assert.match(started.body.tunnel_url, /^http:\/\/localhost:\d+$/);
    assert.equal(started.body.trust_class, 'network-provider');
    assert.ok(fs.existsSync(started.body.log_file));

    const options = await request(origin, 'GET', '/api/local/shares/options');
    assert.equal(options.status, 200);
    const tunnel = options.body.transports.find(entry => entry.kind === 'tunnel');
    assert.equal(tunnel.available, true);
    assert.equal(tunnel.running, true);
    assert.equal(tunnel.providers.length, 1);
    assert.equal(tunnel.operator, 'network-provider');
    assert.equal(tunnel.operator_name, 'Synthetic operator');
    // Every transport says who is in the path and what that party can see.
    for (const entry of options.body.transports) {
      assert.ok(entry.who_is_in_the_path && entry.what_they_can_see && entry.what_the_recipient_confirms);
      assert.equal(entry.can_read_credential, false);
      assert.equal(entry.credential_protection, 'sealed-before-egress');
      assert.ok(Array.isArray(entry.parties_in_path));
    }
    const relay = options.body.transports.find(entry => entry.kind === 'relay');
    assert.deepEqual(relay.parties_in_path, ['zerocreds-website']);
    assert.deepEqual(tunnel.parties_in_path, ['tunnel-operator']);
    assert.deepEqual(options.body.transports.find(entry => entry.kind === 'direct').parties_in_path, []);

    const stopped = await request(origin, 'POST', '/api/local/shares/tunnel/stop', {});
    assert.equal(stopped.status, 200);
    assert.equal(stopped.body.stopped, true);
  } finally {
    await new Promise(resolve => app.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a second start replaces the tunnel this computer started', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-tunnel-replace-'));
  const tunnelPort = await freePort();
  const serverPort = await freePort();
  const app = createApp(localConfig(root, { baseUrl: `http://127.0.0.1:${serverPort}`,
    shareTunnelPort: tunnelPort, shareTunnelProviders: [syntheticProvider(tunnelPort)] }));
  await new Promise(resolve => app.listen(serverPort, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${serverPort}`;
  try {
    const first = await request(origin, 'POST', '/api/local/shares/tunnel/start', { provider: 'synthetic' });
    assert.equal(first.status, 200, JSON.stringify(first.body));
    const second = await request(origin, 'POST', '/api/local/shares/tunnel/start', { provider: 'synthetic' });
    assert.equal(second.status, 200, JSON.stringify(second.body));
    assert.notEqual(second.body.tunnel_url, first.body.tunnel_url);
    const providers = await request(origin, 'GET', '/api/local/shares/tunnel/providers');
    assert.equal(providers.body.configured_by, 'zerocreds');
    assert.equal(providers.body.running, true);
  } finally {
    await new Promise(resolve => app.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a tunnel the owner configured is only replaced on an explicit confirmation', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-tunnel-owner-'));
  const tunnelPort = await freePort();
  const serverPort = await freePort();
  // A tunnel the owner started themselves: it is configured, but this
  // computer did not start it.
  const app = createApp(localConfig(root, { baseUrl: `http://127.0.0.1:${serverPort}`,
    shareTunnelPort: tunnelPort, shareTunnelProviders: [syntheticProvider(tunnelPort)],
    shareTunnelUrl: 'https://owner0000.lhr.life' }));
  await new Promise(resolve => app.listen(serverPort, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${serverPort}`;
  try {
    const refused = await request(origin, 'POST', '/api/local/shares/tunnel/start', { provider: 'synthetic' });
    assert.equal(refused.status, 503);
    assert.match(refused.body.error, /already configured/);
    assert.equal(refused.body.configured_url, 'https://owner0000.lhr.life');
  } finally {
    await new Promise(resolve => app.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('an unknown provider is refused without reaching a shell', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-tunnel-unknown-'));
  const serverPort = await freePort();
  // A shell that leaves a trace if anything runs it.
  const shellDir = path.join(root, 'bin');
  fs.mkdirSync(shellDir, { recursive: true });
  const sentinel = path.join(root, 'shell-ran');
  for (const name of ['sh', 'bash', 'zsh']) {
    const file = path.join(shellDir, name);
    fs.writeFileSync(file, `#!/bin/sh\ntouch "${sentinel}"\n`, { mode: 0o755 });
  }
  const originalPath = process.env.PATH;
  process.env.PATH = `${shellDir}:${originalPath}`;
  const app = createApp(localConfig(root, { baseUrl: `http://127.0.0.1:${serverPort}` }));
  await new Promise(resolve => app.listen(serverPort, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${serverPort}`;
  try {
    const started = await request(origin, 'POST', '/api/local/shares/tunnel/start', { provider: 'nope' });
    assert.equal(started.status, 503);
    assert.match(started.body.error, /unknown tunnel provider/);
    assert.equal(fs.existsSync(sentinel), false);
  } finally {
    process.env.PATH = originalPath;
    await new Promise(resolve => app.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a provider whose client is missing fails in plain words through the route', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-tunnel-noclient-'));
  const serverPort = await freePort();
  const app = createApp(localConfig(root, { baseUrl: `http://127.0.0.1:${serverPort}` }));
  await new Promise(resolve => app.listen(serverPort, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${serverPort}`;
  try {
    const catalog = await request(origin, 'GET', '/api/local/shares/tunnel/providers');
    const cloudflared = catalog.body.providers.find(entry => entry.id === 'cloudflared');
    if (cloudflared.available) return; // The client is installed here, so the request would really run it.
    const started = await request(origin, 'POST', '/api/local/shares/tunnel/start', { provider: 'cloudflared' });
    // The client is not part of the test machine, so the request has to say
    // what is missing instead of failing somewhere deep.
    assert.equal(started.status, 503);
    assert.match(started.body.error, /cloudflared/);
    assert.match(started.body.error, /not installed/);
  } finally {
    await new Promise(resolve => app.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a tunnel that does not reach this computer is refused and the working one stays', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-tunnel-unreachable-'));
  const tunnelPort = await freePort();
  const serverPort = await freePort();
  // A provider that publishes an address where nothing listens.
  const broken = { id: 'broken', label: 'Broken tunnel used by the tests', operator: 'Synthetic operator',
    trust_class: 'network-provider', binary: process.execPath, account: null,
    command: () => [process.execPath, '-e', "console.log('http://localhost:9'); setInterval(() => {}, 1000);"],
    url_pattern: /http:\/\/localhost:\d+/i, notes: 'Synthetic provider.' };
  const app = createApp(localConfig(root, { baseUrl: `http://127.0.0.1:${serverPort}`,
    shareTunnelPort: tunnelPort, shareTunnelProviders: [syntheticProvider(tunnelPort), broken] }));
  await new Promise(resolve => app.listen(serverPort, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${serverPort}`;
  try {
    const good = await request(origin, 'POST', '/api/local/shares/tunnel/start', { provider: 'synthetic' });
    assert.equal(good.status, 200, JSON.stringify(good.body));
    const failed = await request(origin, 'POST', '/api/local/shares/tunnel/start', { provider: 'broken' });
    assert.equal(failed.status, 503);
    assert.match(failed.body.error, /tunnel setup failed/);
    // The tunnel that worked before is still configured and still running.
    const providers = await request(origin, 'GET', '/api/local/shares/tunnel/providers');
    assert.equal(providers.body.configured_url, good.body.tunnel_url);
    assert.equal(providers.body.running, true);
  } finally {
    await new Promise(resolve => app.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the start time of a process tells a reused pid from the original one', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-tunnel-pid-'));
  const logFile = path.join(root, 'tunnel.log');
  let started;
  try {
    started = await startTunnelProcess({ command: [process.execPath, FIXTURE, String(await freePort())],
      urlPattern: /http:\/\/localhost:\d+/i, logFile, label: 'Synthetic tunnel' });
    const startedAt = processStartTime(started.pid);
    assert.ok(startedAt && startedAt.length > 0, 'the start time is known');
    assert.equal(processStartTime(started.pid), startedAt);
    assert.equal(processStartTime(999999), null);
  } finally {
    if (started) stopTunnelProcess(started.pid);
    fs.rmSync(root, { recursive: true, force: true });
  }
});
