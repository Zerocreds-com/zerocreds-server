'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { createShareRelay } = require('../src/share-relay');
const { createPeerShare, claimPeerShare, parseInvite } = require('../src/local-share');
const { createDirectShareEndpoints, directOrigin } = require('../src/direct-share');

async function freePort() {
  const probe = net.createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  return port;
}

test('direct IP invitation uses only the sender endpoint and never exposes the local API', async () => {
  const port = await freePort();
  const endpoint = createDirectShareEndpoints({ publicUrl: `http://127.0.0.1:${port}`, allowLoopback: true });
  const { localUrl, publicUrl } = await endpoint.start();
  let share;
  try {
    share = await createPeerShare({ relayUrl: localUrl, publicUrl, allowLoopback: true,
      pollIntervalMs: 10, ttlMinutes: 1,
      metadata: { provider: 'example', account_alias: 'work', setup_prompt: 'Set up the example project.' },
      readCredential: async () => ({ token: 'synthetic-direct-value' }) });
    assert.ok(share.url.startsWith(`${publicUrl}/api/i/`));
    const page = await fetch(share.url);
    const html = await page.text();
    assert.equal(page.status, 200);
    assert.match(html, /Your colleague shared access with you/);
    assert.match(html, /Receive the credential using the one-time ZeroCreds invite/);
    assert.match(html, /Portable receiver commands and protocol/);
    assert.doesNotMatch(html, /<script|synthetic-direct-value/i);
    assert.ok(!html.includes(share.url.split('#')[1]));
    const russianPage = await fetch(share.url, { headers: { 'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8' } });
    const russianHtml = await russianPage.text();
    assert.match(russianHtml, /<html lang="ru">/);
    assert.match(russianHtml, /Коллега поделился с вами доступом/);
    assert.match(russianHtml, /Получи credential по одноразовому ZeroCreds invite/);
    assert.doesNotMatch(russianHtml, /<script|synthetic-direct-value/i);
    const englishPreferred = await fetch(share.url, { headers: { 'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8' } });
    assert.match(await englishPreferred.text(), /<html lang="en">/);
    assert.equal((await fetch(`${publicUrl}/api/local/connections`)).status, 404);
    assert.equal((await fetch(`${publicUrl}/api/share-relay/sessions`, { method: 'POST' })).status, 404);
    const writes = [];
    const saved = await claimPeerShare(share.url, async (_metadata, fields) => {
      writes.push(fields);
      return { connection_id: 'direct-recipient' };
    }, { relayUrl: 'https://zerocreds.ru', allowLoopback: true, pollIntervalMs: 10 });
    assert.equal(saved.status, 'saved');
    assert.deepEqual(writes, [{ token: 'synthetic-direct-value' }]);
  } finally {
    share?.close();
    await endpoint.stop();
  }
});

test('direct invitations accept only numeric public IPs, with loopback limited to tests', () => {
  assert.equal(directOrigin('http://8.8.8.8:3457'), 'http://8.8.8.8:3457');
  for (const value of ['http://192.168.1.7:3457', 'http://169.254.169.254:3457',
    'http://127.0.0.1:3457', 'http://example.com:3457', 'http://8.8.8.8:3457/path',
    'http://8.8.8.8:3457/?x=1']) assert.throws(() => directOrigin(value));
  const link = `http://192.168.1.7:3457/api/share-relay/invite/${'a'.repeat(32)}#${'b'.repeat(64)}`;
  assert.throws(() => parseInvite(link, 'https://zerocreds.ru'), /invalid share link/);
});

test('an invitation link stays short and keeps the older link readable', async () => {
  await withRelay(async (relayUrl, relay) => {
    const share = await createPeerShare({ relayUrl, allowLoopback: true, pollIntervalMs: 10,
      ttlMinutes: 1, metadata: { provider: 'example', account_alias: 'work', setup_prompt: '' },
      readCredential: async () => ({ token: 'synthetic-secret' }) });
    try {
      assert.match(share.url, /^https?:\/\/[^/]+\/api\/i\/[A-Za-z0-9_-]{14}#[A-Za-z0-9_-]{22}$/);
      // The whole link has to survive a chat message without being rewritten.
      assert.ok(share.url.length < 100, `${share.url.length} characters`);
      // A link that was already in flight keeps working after the update.
      const legacy = `https://zerocreds.ru/api/share-relay/invite/${'a'.repeat(32)}#${'b'.repeat(64)}`;
      const parsed = parseInvite(legacy, 'https://zerocreds.ru');
      assert.equal(parsed.id, 'a'.repeat(32));
      assert.equal(parsed.secret.length, 32);
      // The relay keeps accepting a session that was created with the old id.
      const created = await fetch(`${relayUrl}/api/share-relay/sessions`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: 'a'.repeat(32), owner_token: 'c'.repeat(64), ttl_minutes: 1 }) });
      assert.equal(created.status, 201);
      assert.ok(relay.sessions.has('a'.repeat(32)));
    } finally { share.close(); }
  });
});

async function withRelay(run, options) {
  const relay = createShareRelay(options);
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    Promise.resolve(relay.handle(req, res, url)).then(handled => {
      if (!handled) res.writeHead(404).end();
    }).catch(() => res.writeHead(500).end());
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await run(`http://127.0.0.1:${server.address().port}`, relay); }
  finally { relay.stop(); await new Promise(resolve => server.close(resolve)); }
}

test('port probe checks only the caller public address and returns no credential data', async () => {
  const observed = [];
  await withRelay(async relayUrl => {
    const token = 'c'.repeat(64);
    const response = await fetch(`${relayUrl}/api/share-relay/probe`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ port: 3457, token }) });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { public_ip: '8.8.8.8', port: 3457, reachable: true });
    const invalid = await fetch(`${relayUrl}/api/share-relay/probe`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ port: 80, token }) });
    assert.equal(invalid.status, 400);
  }, { clientIp: () => '8.8.8.8', probePort: async (ip, port, token) => {
    observed.push({ ip, port, token });
    return true;
  } });
  assert.deepEqual(observed, [{ ip: '8.8.8.8', port: 3457, token: 'c'.repeat(64) }]);
  await withRelay(async relayUrl => {
    const response = await fetch(`${relayUrl}/api/share-relay/probe`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port: 3457, token: 'c'.repeat(64) }) });
    assert.equal(response.status, 400);
  }, { clientIp: () => '192.168.1.20', probePort: async () => assert.fail('must reject private source address') });
});

test('port probe rate limit tells the caller when to retry', async () => {
  await withRelay(async relayUrl => {
    const probe = () => fetch(`${relayUrl}/api/share-relay/probe`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port: 3457, token: 'd'.repeat(64) }) });
    assert.equal((await probe()).status, 200);
    const limited = await probe();
    assert.equal(limited.status, 429);
    assert.deepEqual(await limited.json(), {
      error: 'port check rate limit; wait before retrying', retry_after_seconds: 10,
    });
  }, { clientIp: () => '8.8.4.4', probePort: async () => false });
});

test('sender and receiver on separate clients transfer once through a ciphertext-only relay', async () => {
  await withRelay(async (relayUrl, relay) => {
    const secret = 'synthetic-secret-that-must-never-appear';
    const prompt = 'Configure the example project after checking with the recipient.';
    const share = await createPeerShare({ relayUrl, allowLoopback: true, pollIntervalMs: 10,
      ttlMinutes: 1, metadata: { provider: 'example', account_alias: 'work', setup_prompt: prompt },
      readCredential: async () => ({ token: secret }) });
    try {
      assert.equal(share.status(), 'pending');
      assert.ok(!share.url.includes(secret));
      const writes = [];
      const result = await claimPeerShare(share.url, async (meta, fields) => {
        writes.push({ meta, fields });
        return { connection_id: 'recipient-connection' };
      }, { relayUrl, allowLoopback: true, pollIntervalMs: 10 });
      assert.equal(result.status, 'saved');
      assert.equal(result.setup_prompt, prompt);
      assert.equal(result.source, 'sender_supplied_untrusted_text');
      assert.deepEqual(writes[0].fields, { token: secret });
      assert.equal(writes.length, 1);
      assert.ok(!JSON.stringify(result).includes(secret));
      assert.ok(!JSON.stringify([...relay.sessions.values()]).includes(secret));
      assert.ok(!JSON.stringify([...relay.sessions.values()]).includes(prompt));
      await assert.rejects(() => claimPeerShare(share.url, async () => {},
        { relayUrl, allowLoopback: true, pollIntervalMs: 10 }));
    } finally { share.close(); }
  });
});

test('wrong invitation code cannot read or consume a share', async () => {
  await withRelay(async relayUrl => {
    let reads = 0;
    const share = await createPeerShare({ relayUrl, allowLoopback: true, pollIntervalMs: 10,
      ttlMinutes: 1, metadata: { provider: 'example', account_alias: 'work', setup_prompt: '' },
      readCredential: async () => { reads++; return { token: 'synthetic-secret' }; } });
    try {
      const wrong = share.url.replace(/.$/, c => c === '0' ? '1' : '0');
      await assert.rejects(() => claimPeerShare(wrong, async () => {},
        { relayUrl, allowLoopback: true, pollIntervalMs: 10 }), /denied/);
      assert.equal(reads, 0);
      assert.equal(parseInvite(share.url, relayUrl, { allowLoopback: true }).origin, relayUrl);
      assert.throws(() => parseInvite(share.url, relayUrl), /invalid share relay URL/);
      const result = await claimPeerShare(share.url, async () => ({ connection_id: 'recipient' }),
        { relayUrl, allowLoopback: true, pollIntervalMs: 10 });
      assert.equal(result.status, 'saved');
      assert.equal(reads, 1);
    } finally { share.close(); }
  });
});

test('relay rejects a second claim while the first is waiting', async () => {
  await withRelay(async relayUrl => {
    const share = await createPeerShare({ relayUrl, allowLoopback: true, pollIntervalMs: 10,
      ttlMinutes: 1, metadata: { provider: 'example', account_alias: 'work', setup_prompt: '' },
      readCredential: async () => ({ token: 'synthetic-secret' }) });
    try {
      const first = claimPeerShare(share.url, async () => {
        await new Promise(resolve => setTimeout(resolve, 80));
        return { connection_id: 'first' };
      }, { relayUrl, allowLoopback: true, pollIntervalMs: 10 });
      await new Promise(resolve => setTimeout(resolve, 25));
      await assert.rejects(() => claimPeerShare(share.url, async () => ({ connection_id: 'second' }),
        { relayUrl, allowLoopback: true, pollIntervalMs: 10 }), /already in progress/);
      assert.equal((await first).connection_id, 'first');
    } finally { share.close(); }
  });
});

test('recipient can retry after a failed local write without rereading the source credential', async () => {
  await withRelay(async relayUrl => {
    let reads = 0;
    const share = await createPeerShare({ relayUrl, allowLoopback: true, pollIntervalMs: 10,
      ttlMinutes: 1, metadata: { provider: 'example', account_alias: 'work', setup_prompt: '' },
      readCredential: async () => { reads++; return { token: 'synthetic-secret' }; } });
    try {
      await assert.rejects(() => claimPeerShare(share.url, async () => {
        throw new Error('synthetic Keychain write failure');
      }, { relayUrl, allowLoopback: true, pollIntervalMs: 10 }), /write failure/);
      const saved = await claimPeerShare(share.url, async (_meta, fields) => {
        assert.equal(fields.token, 'synthetic-secret');
        return { connection_id: 'retry-ok' };
      }, { relayUrl, allowLoopback: true, pollIntervalMs: 10 });
      assert.equal(saved.connection_id, 'retry-ok');
      assert.equal(reads, 1);
    } finally { share.close(); }
  });
});
