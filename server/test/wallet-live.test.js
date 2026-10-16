'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { startServer, request } = require('./helpers');

const baoUrl = process.env.ZEROCREDS_TEST_OPENBAO_URL;
const rootToken = process.env.ZEROCREDS_TEST_OPENBAO_ROOT_TOKEN;
const workerUrl = process.env.ZEROCREDS_TEST_WALLET_WORKER_URL;
const workerToken = process.env.ZEROCREDS_TEST_WALLET_SERVICE_TOKEN;
const mount = process.env.ZEROCREDS_TEST_WALLET_MOUNT;

test('live wallet: agent API → ZeroCreds form → OpenBao KV v2 → D1 status',
  { skip: !baoUrl || !rootToken || !workerUrl || !workerToken || !mount }, async () => {
    const suffix = crypto.randomBytes(6).toString('hex');
    const owner = `e2e_${suffix}`;
    const profile = 'main';
    const apiToken = `zct_${crypto.randomBytes(32).toString('hex')}`;
    const writerPolicy = `zc_wallet_writer_${suffix}`;
    const metadataPolicy = `zc_wallet_metadata_${suffix}`;
    const readerPolicy = `zc_wallet_reader_${suffix}`;
    const tokens = [];
    let srv;
    async function bao(method, route, token, value) {
      const response = await fetch(`${baoUrl}/v1/${route}`, {
        method, headers: { 'X-Vault-Token': token, ...(value ? { 'Content-Type': 'application/json' } : {}) },
        ...(value ? { body: JSON.stringify(value) } : {}), redirect: 'error',
      });
      let data;
      try { data = await response.json(); } catch { data = {}; }
      assert.ok(response.ok, `${method} ${route}: ${response.status}`);
      return data;
    }
    async function makeToken(policy) {
      const result = await bao('POST', 'auth/token/create', rootToken,
        { policies: [policy], no_default_policy: true });
      tokens.push(result.auth.client_token);
      return result.auth.client_token;
    }
    try {
      await bao('PUT', `sys/policies/acl/${writerPolicy}`, rootToken, { policy: `
path "sys/capabilities-self" { capabilities = ["update"] }
path "${mount}/data/owners/${owner}/connections/*" { capabilities = ["create", "update"] }
path "${mount}/data/owners/${owner}/probes/*" { capabilities = ["create", "update"] }
` });
      await bao('PUT', `sys/policies/acl/${metadataPolicy}`, rootToken, { policy: `
path "${mount}/metadata/owners/${owner}/probes/*" { capabilities = ["read", "delete"] }
` });
      await bao('PUT', `sys/policies/acl/${readerPolicy}`, rootToken, { policy: `
path "${mount}/data/owners/${owner}/connections/*" { capabilities = ["read"] }
` });
      const writer = await makeToken(writerPolicy);
      const metadata = await makeToken(metadataPolicy);
      const reader = await makeToken(readerPolicy);
      srv = await startServer({ namedDestinations: { wallet: {
        type: 'vault', address: baoUrl,
        path: `${mount}/data/owners/placeholder/connections/placeholder`,
        preflight_path_prefix: `${mount}/data/owners/placeholder/probes`,
        token: writer, preflight_metadata_token: metadata,
      } }, app: {
        walletWorkerUrl: workerUrl, walletServiceToken: workerToken,
        walletClients: { [apiToken]: { owner_id: owner, profile_id: profile, destination: 'wallet' } },
      } });
      const auth = { Authorization: `Bearer ${apiToken}` };
      const created = await request(srv.port, 'POST', '/api/wallet/forms', {
        provider: 'github', kind: 'token', idempotency_key: `wallet_${suffix}_create`,
      }, auth);
      assert.equal(created.status, 200, JSON.stringify(created.body));
      const repeated = await request(srv.port, 'POST', '/api/wallet/forms', {
        provider: 'github', kind: 'token', idempotency_key: `wallet_${suffix}_create`,
      }, auth);
      assert.equal(repeated.body.form_id, created.body.form_id);
      const form = await request(srv.port, 'GET', `/f/${created.body.form_id}`);
      assert.equal(form.status, 200);
      assert.match(form.raw, new RegExp(`Wallet owner: <code>${owner}</code>`));
      const value = `synthetic_${suffix}`;
      const submitted = await request(srv.port, 'POST', `/f/${created.body.form_id}`,
        { t: created.body.form_id, fields: { token: value } });
      assert.equal(submitted.status, 200, JSON.stringify(submitted.body));
      const status = await request(srv.port, 'GET', `/api/wallet/forms/${created.body.form_id}/status`, undefined, auth);
      assert.equal(status.body.status, 'done');
      assert.equal(status.body.connection_id, created.body.connection_id);
      assert.equal(status.body.kv_version, 1);
      assert.ok(!JSON.stringify(status.body).includes(value));
      const secretPath = `${mount}/data/owners/${owner}/connections/${created.body.connection_id}`;
      const secret = await bao('GET', secretPath, reader);
      assert.equal(secret.data.data.token, value);
      const scopedMetadata = await fetch(`${workerUrl}/internal/connections/${created.body.connection_id}`, {
        headers: { Authorization: `Bearer ${workerToken}`,
          'X-Wallet-Owner': owner, 'X-Wallet-Profile': profile },
      });
      assert.equal(scopedMetadata.status, 200);
      assert.ok(!(await scopedMetadata.text()).includes(value));
      const foreignMetadata = await fetch(`${workerUrl}/internal/connections/${created.body.connection_id}`, {
        headers: { Authorization: `Bearer ${workerToken}`,
          'X-Wallet-Owner': `other_${suffix}`, 'X-Wallet-Profile': profile },
      });
      assert.equal(foreignMetadata.status, 404);
      const writerRead = await fetch(`${baoUrl}/v1/${secretPath}`, {
        headers: { 'X-Vault-Token': writer },
      });
      assert.equal(writerRead.status, 403);
      const revoked = await request(srv.port, 'POST',
        `/api/wallet/connections/${created.body.connection_id}/revoke`, {}, auth);
      assert.equal(revoked.body.state, 'revoked');
      const afterRevoke = await request(srv.port, 'GET',
        `/api/wallet/connections/${created.body.connection_id}`, undefined, auth);
      assert.equal(afterRevoke.body.state, 'revoked');
    } finally {
      if (srv) await srv.stop();
      for (const token of tokens) {
        try { await bao('POST', 'auth/token/revoke-self', token); } catch {}
      }
      for (const policy of [writerPolicy, metadataPolicy, readerPolicy]) {
        try { await bao('DELETE', `sys/policies/acl/${policy}`, rootToken); } catch {}
      }
    }
  });
