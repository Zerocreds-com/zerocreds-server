'use strict';
// A run-scoped grant: the host that acts for a run asks the wallet for the value
// of one connection it owns. Only a machine assertion may ask, and the store
// records the run that consumed the value.
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

function send(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(value));
}

function jwt(privateKey, claims, kid = 'host-key-1') {
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${encode({ alg: 'EdDSA', typ: 'JWT', kid })}.${encode(claims)}`;
  return `${input}.${crypto.sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
}

const owner = 'owner_grant';
const profile = 'profile_grant';
const serviceToken = 'wallet-grant-service-token-1234567890';

test('a run-scoped grant hands the stored value to a machine caller and nobody else', async () => {
  const connectionId = 'connection_grant_1';
  const secret = { token: `ghp_grant_${Date.now()}` };
  const dataKey = crypto.randomBytes(32).toString('base64');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(dataKey, 'base64'), iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(secret), 'utf8')), cipher.final()]);
  const reads = [];
  const claimed = new Set();
  let live = true;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

  const worker = await listen(async (req, res) => {
    const url = new URL(req.url, 'http://worker');
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const payload = raw ? JSON.parse(raw) : {};
    if (req.headers.authorization !== `Bearer ${serviceToken}`) return send(res, 401, { error: 'unauthorized' });
    if (url.pathname === '/internal/assertions/claim') {
      // The store refuses a replayed assertion; the wallet must then refuse too.
      if (claimed.has(payload.jti_hash)) return send(res, 409, { error: 'assertion_replayed' });
      claimed.add(payload.jti_hash);
      return send(res, 200, { claimed: true });
    }
    if (url.pathname === `/internal/vault/values/${connectionId}/read`) {
      // The store is the truth about scope: a foreign owner learns nothing.
      if (payload.owner_id !== owner || payload.profile_id !== profile || !live) {
        return send(res, 404, { error: 'value_unavailable' });
      }
      reads.push(payload);
      return send(res, 200, { connection_id: connectionId, version: 3,
        ciphertext: ciphertext.toString('base64'), iv: iv.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'), alg: 'A256GCM', key_ref: 'k1',
        replay: reads.length > 1 });
    }
    return send(res, 404, { error: 'not_found' });
  });

  const srv = await startServer({
    namedDestinations: { wallet_custody: { type: 'zerocreds_vault', vault_url: worker.url,
      service_token: serviceToken, data_key: dataKey, key_ref: 'k1' } },
    app: {
      walletWorkerUrl: worker.url,
      walletServiceToken: serviceToken,
      walletAssertionIssuers: { 'https://trained-assist.example': {
        keys: { 'host-key-1': publicKey.export({ type: 'spki', format: 'pem' }).toString() },
        profiles: { [profile]: { owner_id: owner, profile_id: profile, destination: 'wallet_custody',
          callers: ['human', 'machine'] } },
      } },
    },
  });

  const now = Math.floor(Date.now() / 1000);
  const claims = (overrides = {}) => ({ iss: 'https://trained-assist.example', aud: 'zerocreds-wallet:machine',
    owner_id: owner, profile_id: profile, caller_class: 'machine', operations: ['wallet.connections.grant'],
    run_id: 'run_2b1c0f6d9a4e_9f4e2a1b', iat: now, exp: now + 120,
    jti: crypto.randomBytes(20).toString('base64url'), ...overrides });
  const auth = body => ({ Authorization: `Bearer ${jwt(privateKey, body)}` });

  try {
    const granted = await request(srv.port, 'POST', `/api/wallet/connections/${connectionId}/grants`, {}, auth(claims()));
    assert.equal(granted.status, 200, JSON.stringify(granted.body));
    assert.deepEqual(granted.body.value, secret);
    assert.equal(granted.body.connection_id, connectionId);
    assert.equal(granted.body.version, 3);
    assert.ok(Date.parse(granted.body.expires_at) > Date.now(), 'a grant carries its own expiry');
    assert.equal(reads.length, 1, 'the store was read once');
    assert.equal(reads[0].run_id, 'run_2b1c0f6d9a4e_9f4e2a1b', 'the store records the run');
    assert.equal(reads[0].owner_id, owner);

    // A human caller may never ask for a value: the profile allows both classes,
    // so the refusal has to come from the grant route itself.
    const human = claims({ caller_class: 'human', aud: 'zerocreds-wallet:human', run_id: undefined });
    const refused = await request(srv.port, 'POST', `/api/wallet/connections/${connectionId}/grants`, {}, auth(human));
    assert.equal(refused.status, 403, JSON.stringify(refused.body));
    assert.equal(reads.length, 1, 'a refused grant never reaches the store');

    // The same run asking again is the same grant: the value is still answered
    // (the run needs it to work), and the host is told it is a replay so it
    // can count the deliveries itself.
    const again = await request(srv.port, 'POST', `/api/wallet/connections/${connectionId}/grants`, {},
      auth(claims({ jti: crypto.randomBytes(20).toString('base64url') })));
    assert.equal(again.status, 200, JSON.stringify(again.body));
    assert.deepEqual(again.body.value, secret);
    assert.equal(again.body.replay, true, 'the host learns the run already held this grant');
    assert.equal(reads.length, 2, 'the repeat reached the store');
    assert.equal(granted.body.replay, false, 'the first grant of a run is not a replay');

    // An assertion without the grant operation is rejected before anything else.
    const unscoped = claims({ operations: ['wallet.connections.status'], jti: crypto.randomBytes(20).toString('base64url') });
    assert.equal((await request(srv.port, 'POST', `/api/wallet/connections/${connectionId}/grants`, {}, auth(unscoped))).status, 401);
    // A replayed assertion is rejected.
    const replayed = auth(claims());
    await request(srv.port, 'POST', `/api/wallet/connections/${connectionId}/grants`, {}, replayed);
    assert.equal((await request(srv.port, 'POST', `/api/wallet/connections/${connectionId}/grants`, {}, replayed)).status, 401);

    // Another owner is told nothing about the connection.
    const foreign = claims({ owner_id: 'owner_other', jti: crypto.randomBytes(20).toString('base64url') });
    assert.equal((await request(srv.port, 'POST', `/api/wallet/connections/${connectionId}/grants`, {}, auth(foreign))).status, 401);

    // A value that is gone fails closed.
    live = false;
    const gone = await request(srv.port, 'POST', `/api/wallet/connections/${connectionId}/grants`, {},
      auth(claims({ jti: crypto.randomBytes(20).toString('base64url') })));
    assert.equal(gone.status, 404, JSON.stringify(gone.body));
    assert.equal(JSON.stringify(gone.body).includes(secret.token), false, 'a refusal never echoes the value');
  } finally {
    await srv.stop();
    await worker.close();
  }
});
