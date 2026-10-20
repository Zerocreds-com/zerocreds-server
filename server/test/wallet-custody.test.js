'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const crypto = require('crypto');
const { startServer, request } = require('./helpers');

async function listen(handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => server.close(resolve)) };
}
async function body(req) {
  let value = '';
  for await (const chunk of req) value += chunk;
  return value ? JSON.parse(value) : {};
}
function send(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(value));
}

const owner = 'owner_custody';
const profile = 'main';
const clientToken = 'wallet-custody-client-token-1234567890';
const serviceToken = 'wallet-custody-service-token-1234567890';
const dataKey = crypto.randomBytes(32).toString('base64');

test('wallet form: the value reaches the custody store as ciphertext', async () => {
  const connectionId = crypto.randomUUID();
  const openbaoPath = `zc_wallet_sandbox/data/owners/${owner}/connections/${connectionId}`;
  const custodyWrites = [];
  let connectionState = 'allocated';
  let registeredForm = '';

  const worker = await listen(async (req, res) => {
    const payload = req.method === 'POST' || req.method === 'PUT' ? await body(req) : {};
    if (req.headers.authorization !== `Bearer ${serviceToken}`) return send(res, 401, { error: 'unauthorized' });
    if (req.url === '/internal/assertions/claim') return send(res, 200, { claimed: true });
    if (req.url === '/internal/connections/allocate') {
      return send(res, 200, { connection_id: connectionId, openbao_path: openbaoPath, state: 'allocated' });
    }
    if (req.url === '/internal/forms') { registeredForm = payload.form_id; return send(res, 200, { state: 'pending' }); }
    if (req.url === `/internal/forms/${registeredForm}/complete`) return send(res, 200, { state: 'written' });
    if (req.url === `/internal/connections/${connectionId}`) {
      return send(res, 200, { connection_id: connectionId, provider: 'github', state: connectionState,
        openbao_path: openbaoPath, kv_version: connectionState === 'active' ? 1 : null, updated_at: 123 });
    }
    if (req.url === `/internal/vault/values/${connectionId}` && req.method === 'GET') {
      return send(res, 200, { connection_id: connectionId, state: connectionState === 'active' ? 'active' : 'missing',
        version: connectionState === 'active' ? 1 : null, updated_at: 123 });
    }
    if (req.url === `/internal/vault/values/${connectionId}` && req.method === 'PUT') {
      custodyWrites.push(payload);
      connectionState = 'active';
      return send(res, 200, { connection_id: connectionId, version: 1, key_ref: payload.key_ref });
    }
    if (req.url === `/internal/vault/values/${connectionId}/revoke`) {
      connectionState = 'missing';
      return send(res, 200, { connection_id: connectionId, state: 'revoked', versions_revoked: 1 });
    }
    return send(res, 404, { error: 'not_found' });
  });

  const srv = await startServer({
    namedDestinations: { wallet_custody: {
      type: 'zerocreds_vault', vault_url: worker.url, service_token: serviceToken,
      data_key: dataKey, key_ref: 'k1',
    } },
    app: { walletWorkerUrl: worker.url, walletServiceToken: serviceToken,
      walletClients: { [clientToken]: { owner_id: owner, profile_id: profile, destination: 'wallet_custody' } } },
  });

  try {
    const auth = { Authorization: `Bearer ${clientToken}` };
    const create = await request(srv.port, 'POST', '/api/wallet/forms',
      { provider: 'github', kind: 'token', title: 'custody probe' }, auth);
    assert.equal(create.status, 200, JSON.stringify(create.body));
    assert.ok(create.body.form_id, 'the form has an id');
    assert.ok(create.body.url, 'the form has a url');

    const secret = `ghp_custody_${Date.now()}`;
    const submitted = await request(srv.port, 'POST', `/f/${create.body.form_id}`,
      { t: create.body.form_id, fields: { token: secret } }, auth);
    assert.equal(submitted.status, 200, JSON.stringify(submitted.body));
    assert.ok(!JSON.stringify(submitted.body).includes(secret), 'the answer never echoes the value');

    assert.equal(custodyWrites.length, 1, 'the custody store was written once');
    const write = custodyWrites[0];
    assert.equal(write.alg, 'A256GCM');
    assert.equal(write.owner_id, owner);
    assert.equal(write.profile_id, profile);
    assert.ok(!JSON.stringify(write).includes(secret), 'the store never receives the plaintext');

    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(dataKey, 'base64'), Buffer.from(write.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(write.tag, 'base64'));
    const plain = Buffer.concat([decipher.update(Buffer.from(write.ciphertext, 'base64')), decipher.final()]).toString('utf8');
    assert.deepEqual(JSON.parse(plain), { token: secret });

    const status = await request(srv.port, 'GET', `/api/wallet/connections/${connectionId}`, null, auth);
    assert.equal(status.status, 200, JSON.stringify(status.body));
    assert.equal(status.body.state, 'active', 'the connection reads active while the value is there');
  } finally {
    await srv.stop();
    await worker.close();
  }
});
