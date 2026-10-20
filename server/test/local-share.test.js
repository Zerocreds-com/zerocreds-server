'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createShareRelay } = require('../src/share-relay');
const { createPeerShare, claimPeerShare, parseInvite } = require('../src/local-share');

async function withRelay(run) {
  const relay = createShareRelay();
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
