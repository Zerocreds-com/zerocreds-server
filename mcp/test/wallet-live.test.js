'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');
const { startServer, request } = require('../../server/test/helpers');

const baoUrl = process.env.ZEROCREDS_TEST_OPENBAO_URL;
const rootToken = process.env.ZEROCREDS_TEST_OPENBAO_ROOT_TOKEN;
const workerUrl = process.env.ZEROCREDS_TEST_WALLET_WORKER_URL;
const workerToken = process.env.ZEROCREDS_TEST_WALLET_SERVICE_TOKEN;
const mount = process.env.ZEROCREDS_TEST_WALLET_MOUNT;

test('live MCP: agent form tool → ZeroCreds → OpenBao → remote D1 → agent status',
  { skip: !baoUrl || !rootToken || !workerUrl || !workerToken || !mount }, async () => {
    const suffix = crypto.randomBytes(6).toString('hex');
    const owner = `mcp_e2e_${suffix}`;
    const apiToken = `zct_${crypto.randomBytes(32).toString('hex')}`;
    const policies = [`mcp_writer_${suffix}`, `mcp_metadata_${suffix}`];
    const tokens = [];
    let app;
    let client;

    async function bao(method, route, token, value) {
      const res = await fetch(`${baoUrl}/v1/${route}`, {
        method, headers: { 'X-Vault-Token': token,
          ...(value ? { 'Content-Type': 'application/json' } : {}) },
        ...(value ? { body: JSON.stringify(value) } : {}),
      });
      assert.ok(res.ok, `${method} ${route}: HTTP ${res.status}`);
      try { return await res.json(); } catch { return {}; }
    }
    async function scopedToken(policy) {
      const result = await bao('POST', 'auth/token/create', rootToken,
        { policies: [policy], no_default_policy: true });
      tokens.push(result.auth.client_token);
      return result.auth.client_token;
    }
    async function tool(name, args) {
      const result = await client.callTool({ name, arguments: args });
      assert.notEqual(result.isError, true, JSON.stringify(result.content));
      return JSON.parse(result.content[0].text);
    }
    try {
      await bao('PUT', `sys/policies/acl/${policies[0]}`, rootToken, { policy: `
path "sys/capabilities-self" { capabilities = ["update"] }
path "${mount}/data/owners/${owner}/connections/*" { capabilities = ["create", "update"] }
path "${mount}/data/owners/${owner}/probes/*" { capabilities = ["create", "update"] }
` });
      await bao('PUT', `sys/policies/acl/${policies[1]}`, rootToken, { policy: `
path "${mount}/metadata/owners/${owner}/probes/*" { capabilities = ["read", "delete"] }
` });
      const writer = await scopedToken(policies[0]);
      const metadata = await scopedToken(policies[1]);
      app = await startServer({ namedDestinations: { wallet: {
        type: 'vault', address: baoUrl,
        path: `${mount}/data/owners/placeholder/connections/placeholder`,
        preflight_path_prefix: `${mount}/data/owners/placeholder/probes`,
        token: writer, preflight_metadata_token: metadata,
      } }, app: {
        walletWorkerUrl: workerUrl, walletServiceToken: workerToken,
        walletClients: { [apiToken]: { owner_id: owner, profile_id: 'main', destination: 'wallet' } },
      } });

      client = new Client({ name: 'wallet-live-test', version: '1.0.0' });
      await client.connect(new StdioClientTransport({
        command: process.execPath, args: [path.join(__dirname, '..', 'index.js')],
        env: { PATH: process.env.PATH || '', HOME: process.env.HOME || '',
          ZEROCREDS_URL: `http://127.0.0.1:${app.port}`, ZEROCREDS_WALLET_API_TOKEN: apiToken },
      }));
      const created = await tool('wallet_form_create',
        { provider: 'github', kind: 'token', idempotency_key: `mcp_${suffix}_wallet_create` });
      assert.match(created.url, new RegExp(`/f/${created.form_id}$`));
      assert.equal(created.owner_id, undefined);
      const before = await tool('wallet_form_status', { form_id: created.form_id });
      assert.equal(before.status, 'pending');
      const value = `synthetic_${suffix}`;
      const submitted = await request(app.port, 'POST', `/f/${created.form_id}`,
        { t: created.form_id, fields: { token: value } });
      assert.equal(submitted.status, 200, JSON.stringify(submitted.body));
      const after = await tool('wallet_form_status', { form_id: created.form_id });
      assert.equal(after.status, 'done');
      assert.equal(after.connection_id, created.connection_id);
      assert.ok(!JSON.stringify(after).includes(value));
      const connection = await tool('wallet_connection_status',
        { connection_id: created.connection_id });
      assert.equal(connection.state, 'active');
      const revoked = await tool('wallet_connection_revoke',
        { connection_id: created.connection_id });
      assert.equal(revoked.state, 'revoked');
    } finally {
      if (client) await client.close();
      if (app) await app.stop();
      for (const token of tokens) {
        try { await bao('POST', 'auth/token/revoke-self', token); } catch {}
      }
      for (const policy of policies) {
        try { await bao('DELETE', `sys/policies/acl/${policy}`, rootToken); } catch {}
      }
    }
  });
