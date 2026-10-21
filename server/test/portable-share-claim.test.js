'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createShareRelay } = require('../src/share-relay');
const { createPeerShare } = require('../src/local-share');
const { claimPortableShare } = require('../src/portable-share-claim');

async function withRelay(run) {
  const relay = createShareRelay();
  const server = http.createServer((req, res) => {
    Promise.resolve(relay.handle(req, res, new URL(req.url, 'http://localhost')))
      .then(handled => { if (!handled) res.writeHead(404).end(); })
      .catch(() => res.writeHead(500).end());
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await run(`http://127.0.0.1:${server.address().port}`, relay); }
  finally { relay.stop(); await new Promise(resolve => server.close(resolve)); }
}

test('portable claim stores an encrypted share without exposing its fields in the receipt', async () => {
  await withRelay(async relayUrl => {
    const secret = 'synthetic-portable-secret';
    const share = await createPeerShare({ relayUrl, allowLoopback: true, pollIntervalMs: 5, ttlMinutes: 1,
      metadata: { provider: 'github', account_alias: 'personal', setup_prompt: 'Sender supplied instructions.' },
      readCredential: async () => ({ token: secret }) });
    const writes = [];
    try {
      const result = await claimPortableShare(share.url, async (destination, fields) => {
        writes.push({ destination, fields });
      }, { relayUrl, allowLoopback: true });
      assert.equal(result.status, 'saved');
      assert.equal(result.provider, 'github');
      assert.equal(result.account_alias, 'personal');
      assert.equal(result.storage, 'zerocreds/github-personal');
      assert.deepEqual(writes, [{ destination: { service: 'zerocreds', account: 'github-personal', create_only: true },
        fields: { token: secret } }]);
      assert.ok(!JSON.stringify(result).includes(secret));
    } finally { share.close(); }
  });
});

test('portable claim rejects an invalid invitation before it can save anything', async () => {
  await assert.rejects(() => claimPortableShare('not an invitation', async () => {}), /invalid share link/);
});
