'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const http = require('http');
const { startServer, request } = require('./helpers');

async function listen(handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => server.close(resolve)) };
}

function jwt(privateKey, claims, kid = 'host-key-1') {
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const head = encode({ alg: 'EdDSA', typ: 'JWT', kid });
  const body = encode(claims);
  const input = `${head}.${body}`;
  return `${input}.${crypto.sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
}

test('wallet host assertions bind audience, owner, profile, caller, operation, expiry and one-time jti', async () => {
  const owner = 'owner_a';
  const profile = 'profile_a';
  const connectionId = 'connection_123';
  const serviceToken = 'wallet-service-token-12345678901234567890';
  const seenAssertions = new Set();
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const worker = await listen(async (req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${serviceToken}`);
    if (req.url === '/internal/assertions/claim') {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const { jti_hash: jtiHash, expires_at: expiresAt } = JSON.parse(raw);
      if (expiresAt <= Date.now() || expiresAt > Date.now() + 300_000) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'invalid_assertion_claim' }));
      } else if (seenAssertions.has(jtiHash)) {
        res.writeHead(409, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'assertion_replayed' }));
      } else {
        seenAssertions.add(jtiHash);
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ claimed: true }));
      }
      return;
    }
    assert.equal(req.headers['x-wallet-owner'], owner);
    assert.equal(req.headers['x-wallet-profile'], profile);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ connection_id: connectionId, provider: 'github', state: 'active', kv_version: 2, updated_at: 123 }));
  });
  const srv = await startServer({ namedDestinations: { wallet: { type: 'vault', address: 'https://vault.example', path: 'secret/data/x', token: 'vault-token' } },
    app: {
      walletWorkerUrl: worker.url,
      walletServiceToken: serviceToken,
      walletAssertionIssuers: {
        'https://trained-assist.example': {
          keys: { 'host-key-1': publicKey.export({ type: 'spki', format: 'pem' }).toString() },
          profiles: { [profile]: { owner_id: owner, profile_id: profile, destination: 'wallet', callers: ['human', 'machine'] } },
        },
      },
    } });
  const now = Math.floor(Date.now() / 1000);
  const claims = (overrides = {}) => ({ iss: 'https://trained-assist.example', aud: 'zerocreds-wallet:human',
    owner_id: owner, profile_id: profile, caller_class: 'human', operations: ['wallet.connections.status'],
    iat: now, exp: now + 240, jti: crypto.randomBytes(20).toString('base64url'), ...overrides });
  const auth = body => ({ Authorization: `Bearer ${jwt(privateKey, body)}` });
  try {
    const validToken = jwt(privateKey, claims());
    const ok = await request(srv.port, 'GET', `/api/wallet/connections/${connectionId}`, undefined,
      { Authorization: `Bearer ${validToken}` });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.deepEqual(ok.body, { connection_id: connectionId, provider: 'github', state: 'active', kv_version: 2, updated_at: 123 });
    assert.equal(JSON.stringify(ok.body).includes('vault-token'), false);
    const replay = await request(srv.port, 'GET', `/api/wallet/connections/${connectionId}`, undefined,
      { Authorization: `Bearer ${validToken}` });
    assert.equal(replay.status, 401);

    for (const invalid of [
      claims({ aud: 'zerocreds-wallet:machine' }),
      claims({ exp: now + 301 }),
      claims({ exp: now - 1 }),
      claims({ owner_id: 'owner_b' }),
      claims({ profile_id: 'unconfigured-profile' }),
      claims({ caller_class: 'machine' }),
      claims({ operations: ['wallet.forms.create'] }),
      claims({ run_id: 'human-must-not-have-run-id' }),
    ]) {
      const result = await request(srv.port, 'GET', `/api/wallet/connections/${connectionId}`, undefined, auth(invalid));
      assert.equal(result.status, 401, JSON.stringify(invalid));
    }
    const parts = jwt(privateKey, claims()).split('.');
    parts[2] = `${parts[2][0] === 'A' ? 'B' : 'A'}${parts[2].slice(1)}`;
    const tampered = parts.join('.');
    assert.equal((await request(srv.port, 'GET', `/api/wallet/connections/${connectionId}`, undefined,
      { Authorization: `Bearer ${tampered}` })).status, 401);

    const machine = claims({ caller_class: 'machine', aud: 'zerocreds-wallet:machine', run_id: 'run_20261016_01' });
    const machineResult = await request(srv.port, 'GET', `/api/wallet/connections/${connectionId}`, undefined, auth(machine));
    assert.equal(machineResult.status, 200);
  } finally {
    await srv.stop();
    await worker.close();
  }
});
