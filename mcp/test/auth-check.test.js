'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

test('local MCP auth_check runs read-only token diagnostics against the local server', async () => {
  const token = 'local-admin-token-12345678901234567890';
  let request;
  const api = http.createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : {};
    request = { method: req.method, url: req.url, authorization: req.headers.authorization, body };
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      connection_id: 'connection-1',
      provider: body.provider,
      account_alias: body.account_alias,
      state: 'active',
      keychain_status: 'present',
      recorded: { verification_status: 'invalid', identity: { id: '999', login: 'someone-else' },
        permissions: ['admin'], permission_evidence: 'provider_verified' },
      live: { status: 'valid', identity: { id: '123', login: 'octocat' },
        permissions: ['repo'], permission_evidence: 'provider_verified' },
      conflicts: [{ kind: 'identity_mismatch', detail: 'the stored credential now resolves elsewhere',
        recorded_identity: { id: '999', login: 'someone-else' },
        live_identity: { id: '123', login: 'octocat' } }],
      catalog_written: false,
      credential_values_read: true,
      checked_at: '2030-01-01T00:00:00.000Z',
    }));
  });
  await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
  const client = new Client({ name: 'auth-check-test-client', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(__dirname, '..', 'index.js')],
    env: {
      ...process.env,
      ZEROCREDS_URL: `http://127.0.0.1:${api.address().port}`,
      ZEROCREDS_LOCAL_MODE: '1',
      ZEROCREDS_ADMIN_TOKEN: token,
      ZEROCREDS_DEFAULT_DESTINATION: 'mac-keychain',
      ZEROCREDS_WALLET_API_TOKEN: '',
    },
  });
  try {
    await client.connect(transport);
    const listed = await client.listTools();
    const authCheck = listed.tools.find(tool => tool.name === 'auth_check');
    assert.ok(authCheck, 'auth_check is registered');
    assert.equal(authCheck.annotations.readOnlyHint, true);
    assert.equal(authCheck.annotations.destructiveHint, false);
    assert.equal(authCheck.inputSchema.properties.provider.type, 'string');
    assert.match(authCheck.inputSchema.properties.provider.pattern, /^\^\[a-z0-9\]/);
    assert.ok(authCheck.inputSchema.properties.account_alias);
    assert.ok(authCheck.inputSchema.properties.token_field);
    assert.deepEqual(authCheck.inputSchema.required, ['provider', 'account_alias'],
      'the connection under inspection must be identified explicitly');

    const result = await client.callTool({ name: 'auth_check', arguments: {
      provider: 'github', account_alias: 'work',
    } });
    assert.equal(request.method, 'POST');
    assert.equal(request.url, '/api/local/auth/check');
    assert.equal(request.authorization, `Bearer ${token}`);
    assert.deepEqual(request.body, { provider: 'github', account_alias: 'work' });

    const data = JSON.parse(result.content[0].text);
    assert.equal(data.live.identity.login, 'octocat');
    assert.equal(data.conflicts[0].kind, 'identity_mismatch');
    assert.equal(data.catalog_written, false);
    assert.equal(data.credential_values_read, true);
    // The response carries metadata only.
    assert.ok(!result.content[0].text.includes('must-never-escape'));

    await client.callTool({ name: 'auth_check', arguments: {
      provider: 'cloudflare', account_alias: 'cf', account_id: 'a'.repeat(32), token_field: 'api_token',
    } });
    assert.deepEqual(request.body, {
      provider: 'cloudflare', account_alias: 'cf', account_id: 'a'.repeat(32), token_field: 'api_token',
    });
  } finally {
    await client.close();
    await new Promise(resolve => api.close(resolve));
  }
});
