'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { startServer, request } = require('./helpers');

const origin = process.env.ZEROCREDS_TEST_OPENBAO_URL;
const rootToken = process.env.ZEROCREDS_TEST_OPENBAO_ROOT_TOKEN;

test('real OpenBao KV-v2 owner-scoped intake and policy isolation',
  { skip: !origin || !rootToken }, async () => {
    const suffix = crypto.randomBytes(5).toString('hex');
    const mount = `zc_test_${suffix}`;
    const writerPolicy = `zc_writer_${suffix}`;
    const metadataPolicy = `zc_probe_metadata_${suffix}`;
    const readerPolicy = `zc_reader_${suffix}`;
    const owner = `owner_${suffix}`;
    const connectionPath = `${mount}/data/owners/${owner}/connections/example`;
    const probePrefix = `${mount}/data/owners/${owner}/probes`;
    const createdTokens = [];
    let srv;

    async function bao(method, path, token, body) {
      const response = await fetch(`${origin}/v1/${path}`, {
        method,
        headers: { 'X-Vault-Token': token, ...(body ? { 'Content-Type': 'application/json' } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
        redirect: 'error',
      });
      let json;
      try { json = await response.json(); } catch { json = {}; }
      return { status: response.status, body: json };
    }
    async function mustBao(method, path, token, body) {
      const result = await bao(method, path, token, body);
      assert.ok(result.status >= 200 && result.status < 300,
        `${method} ${path} returned ${result.status}`);
      return result.body;
    }
    async function createToken(policy) {
      const response = await mustBao('POST', 'auth/token/create', rootToken,
        { policies: [policy], no_default_policy: true });
      const token = response.auth.client_token;
      createdTokens.push(token);
      return token;
    }

    try {
      await mustBao('POST', `sys/mounts/${mount}`, rootToken,
        { type: 'kv', options: { version: '2' } });
      await mustBao('PUT', `sys/policies/acl/${writerPolicy}`, rootToken, { policy: `
path "sys/capabilities-self" { capabilities = ["update"] }
path "${mount}/data/owners/${owner}/connections/*" { capabilities = ["create", "update"] }
path "${mount}/data/owners/${owner}/probes/*" { capabilities = ["create", "update"] }
` });
      await mustBao('PUT', `sys/policies/acl/${metadataPolicy}`, rootToken, { policy: `
path "${mount}/metadata/owners/${owner}/probes/*" { capabilities = ["read", "delete"] }
` });
      await mustBao('PUT', `sys/policies/acl/${readerPolicy}`, rootToken, { policy: `
path "${mount}/data/owners/${owner}/connections/*" { capabilities = ["read"] }
` });
      const writer = await createToken(writerPolicy);
      const probeMetadata = await createToken(metadataPolicy);
      const reader = await createToken(readerPolicy);

      srv = await startServer({ namedDestinations: { openbao: {
        type: 'vault', address: origin, path: connectionPath, token: writer,
        preflight_path_prefix: probePrefix, preflight_metadata_token: probeMetadata,
      } } });
      const created = await request(srv.port, 'POST', '/api/session/create', {
        title: 'Connect', fields: [{ name: 'api_key', label: 'API key', type: 'password' }],
        destination: 'openbao',
      }, { Authorization: `Bearer ${srv.adminToken}` });
      assert.equal(created.status, 200);
      const form = await request(srv.port, 'GET', `/f/${created.body.token}`);
      assert.equal(form.status, 200);
      assert.match(form.raw, /Storage: OpenBao KV v2/);
      assert.equal((await bao('LIST', `${mount}/metadata/owners/${owner}/probes`, rootToken)).status, 404);
      const submitted = await request(srv.port, 'POST', `/f/${created.body.token}`,
        { t: created.body.token, fields: { api_key: 'synthetic-openbao-e2e-value' } });
      assert.equal(submitted.status, 200);
      const status = await request(srv.port, 'GET', `/api/session/${created.body.token}/status`,
        undefined, { Authorization: `Bearer ${srv.adminToken}` });
      assert.equal(status.body.status, 'done');
      assert.equal(status.body.version, 1);
      assert.equal(status.body.secret_id, connectionPath);
      assert.ok(!JSON.stringify(status.body).includes('synthetic-openbao-e2e-value'));

      const stored = await mustBao('GET', connectionPath, reader);
      assert.equal(stored.data.data.api_key, 'synthetic-openbao-e2e-value');
      assert.equal((await bao('GET', connectionPath, writer)).status, 403);
      assert.equal((await bao('POST', connectionPath, reader,
        { data: { api_key: 'must-not-write' } })).status, 403);
      assert.equal((await bao('GET', `${mount}/data/owners/foreign/connections/example`, reader)).status, 403);
      assert.equal((await bao('GET', connectionPath, probeMetadata)).status, 403);
    } finally {
      if (srv) await srv.stop();
      for (const token of createdTokens) {
        await bao('POST', 'auth/token/revoke-self', token);
      }
      await bao('DELETE', `sys/mounts/${mount}`, rootToken);
      for (const policy of [writerPolicy, metadataPolicy, readerPolicy]) {
        await bao('DELETE', `sys/policies/acl/${policy}`, rootToken);
      }
    }
  });
