'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
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

test('wallet form: scoped agent request, OpenBao write, D1 completion, value-free status', async () => {
  const owner = 'owner_a';
  const profile = 'main';
  const token = 'test-wallet-api-token-12345678901234567890';
  const otherToken = 'other-wallet-api-token-12345678901234567890';
  const serviceToken = 'wallet-service-token-12345678901234567890';
  const connectionId = crypto.randomUUID();
  const openbaoPath = `secret/data/owners/${owner}/connections/${connectionId}`;
  const calls = [];
  let savedValue;
  let completionFails = true;
  let connectionState = 'allocated';
  const worker = await listen(async (req, res) => {
    const payload = req.method === 'POST' ? await body(req) : {};
    if (req.headers.authorization !== `Bearer ${serviceToken}`) return send(res, 401, { error: 'unauthorized' });
    if (req.url === '/internal/connections/allocate') {
      assert.equal(payload.owner_id, owner);
      assert.equal(payload.profile_id, profile);
      return send(res, 200, { connection_id: connectionId, openbao_path: openbaoPath, state: connectionState });
    }
    if (req.url === '/internal/forms') return send(res, 200, { state: 'pending' });
    if (req.url === `/internal/connections/${connectionId}`) {
      if (req.headers['x-wallet-owner'] !== owner || req.headers['x-wallet-profile'] !== profile) {
        return send(res, 404, { error: 'connection_unavailable' });
      }
      return send(res, 200, { connection_id: connectionId, openbao_path: openbaoPath, state: connectionState });
    }
    if (/^\/internal\/forms\/[a-f0-9]{32}\/complete$/.test(req.url)) {
      calls.push({ operation: 'complete', payload });
      if (completionFails) return send(res, 503, { error: 'wallet_unavailable' });
      connectionState = 'active';
      return send(res, 200, { connection_id: connectionId, state: 'written', kv_version: payload.kv_version });
    }
    return send(res, 404, { error: 'not_found' });
  });
  const bao = await listen(async (req, res) => {
    const payload = req.method === 'POST' ? await body(req) : {};
    calls.push({ operation: 'bao', method: req.method, path: req.url, payload });
    if (req.url === '/v1/sys/capabilities-self') return send(res, 200, { capabilities: ['create', 'update'] });
    if (req.method === 'GET') return send(res, 200, { data: { current_version: 1 } });
    if (req.method === 'DELETE') return send(res, 200, {});
    if (req.url.endsWith(`/connections/${connectionId}`)) {
      assert.deepEqual(payload.options, { cas: 0 });
      assert.equal(savedValue, undefined, 'create-only write must run just once');
      savedValue = payload.data.password;
    }
    return send(res, 200, { data: { version: 1 } });
  });
  let srv;
  try {
    srv = await startServer({ namedDestinations: { wallet: {
      type: 'vault', address: bao.url,
      path: 'secret/data/owners/placeholder/connections/placeholder',
      preflight_path_prefix: 'secret/data/owners/placeholder/probes',
      token: 'writer-token', preflight_metadata_token: 'metadata-token',
    } }, app: { walletWorkerUrl: worker.url, walletServiceToken: serviceToken,
      walletClients: {
        [token]: { owner_id: owner, profile_id: profile, destination: 'wallet' },
        [otherToken]: { owner_id: 'owner_b', profile_id: profile, destination: 'wallet' },
      } } });
    const auth = { Authorization: `Bearer ${token}` };
    const create = await request(srv.port, 'POST', '/api/wallet/forms', {
      provider: 'tilda', kind: 'login', title: 'Connect Tilda',
    }, auth);
    assert.equal(create.status, 200, JSON.stringify(create.body));
    assert.equal(create.body.connection_id, connectionId);
    assert.equal(create.body.submit_token, undefined);
    assert.equal(create.body.openbao_path, undefined);
    const formId = create.body.form_id;
    const pending = fs.readFileSync(path.join(srv.pendingDir, `${formId}.json`), 'utf8');
    assert.ok(!pending.includes('writer-token'));
    assert.ok(!pending.includes('metadata-token'));
    const form = await request(srv.port, 'GET', `/f/${formId}`);
    assert.equal(form.status, 200);
    assert.match(form.raw, /Wallet owner: <code>owner_a<\/code>/);
    assert.match(form.raw, /Profile: <code>main<\/code>/);
    assert.ok(!form.raw.includes('writer-token'));
    const foreign = await request(srv.port, 'GET', `/api/wallet/forms/${formId}/status`, undefined,
      { Authorization: `Bearer ${otherToken}` });
    assert.equal(foreign.status, 404);
    const first = await request(srv.port, 'POST', `/f/${formId}`,
      { t: formId, fields: { username: 'example', password: 'synthetic-wallet-secret' } });
    assert.equal(first.status, 503);
    assert.equal(savedValue, 'synthetic-wallet-secret');
    const changed = await request(srv.port, 'POST', `/f/${formId}`,
      { t: formId, fields: { username: 'example', password: 'different-value' } });
    assert.equal(changed.status, 409);
    completionFails = false;
    const retry = await request(srv.port, 'POST', `/f/${formId}`,
      { t: formId, fields: { username: 'example', password: 'synthetic-wallet-secret' } });
    assert.equal(retry.status, 200, JSON.stringify(retry.body));
    assert.equal(retry.body.connection_id, connectionId);
    assert.deepEqual(retry.body.receipt.payload.wallet, {
      owner_id: owner, profile_id: profile, connection_id: connectionId, kv_version: 1,
    });
    assert.ok(!JSON.stringify(retry.body).includes('synthetic-wallet-secret'));
    assert.equal(calls.filter(c => c.operation === 'bao' && c.path.endsWith(`/connections/${connectionId}`)).length, 1);
    assert.equal(calls.filter(c => c.operation === 'complete').length, 2);
    const status = await request(srv.port, 'GET', `/api/wallet/forms/${formId}/status`, undefined, auth);
    assert.deepEqual(status.body, { form_id: formId, connection_id: connectionId, status: 'done',
      kv_version: 1, receipt_ref: calls.find(c => c.operation === 'complete').payload.receipt_ref });
    assert.ok(!JSON.stringify(status.body).includes('synthetic-wallet-secret'));
  } finally {
    if (srv) await srv.stop();
    await bao.close();
    await worker.close();
  }
});
