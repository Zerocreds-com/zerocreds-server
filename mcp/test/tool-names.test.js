'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

const EXPECTED_LOCAL_TOOLS = [
  'connections_list',
  'connection_resolve',
  'connection_verify',
  'doctor',
  'discovery_sources',
  'discovery_preview',
  'discovery_catalog',
  'credentials_search',
  'form_create',
  'form_status',
  'share_create',
  'share_options',
  'share_direct_setup',
  'share_status',
  'share_cancel',
  'share_claim',
  'playground_scenarios',
  'playground_run',
  'playground_form',
];

test('local MCP tools do not repeat the provider name', async () => {
  const token = 'local-admin-token-12345678901234567890';
  const api = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(req.url === '/api/local/connections?provider=github'
      ? { connections: [{ account_alias: 'first' }, { account_alias: 'second' }] }
      : req.url === '/api/local/shares'
        ? { share_id: 'a'.repeat(32), share_url: `http://8.8.8.8:3457/api/share-relay/invite/${'a'.repeat(32)}#${'b'.repeat(64)}`,
          expires_at: '2030-01-01T00:00:00.000Z', transport: 'direct' }
        : {}));
  });
  await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
  const client = new Client({ name: 'tool-names-test-client', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath, args: [path.join(__dirname, '..', 'index.js')],
    env: { ...process.env, ZEROCREDS_URL: `http://127.0.0.1:${api.address().port}`,
      ZEROCREDS_LOCAL_MODE: '1', ZEROCREDS_ADMIN_TOKEN: token,
      ZEROCREDS_DEFAULT_DESTINATION: 'mac-keychain', ZEROCREDS_WALLET_API_TOKEN: '' },
  });
  try {
    await client.connect(transport);
    const names = (await client.listTools()).tools.map(tool => tool.name);
    for (const name of names) {
      assert.ok(!name.startsWith('zerocreds_'), `${name} must not repeat the provider name`);
    }
    for (const name of EXPECTED_LOCAL_TOOLS) {
      assert.ok(names.includes(name), `${name} is registered`);
    }
    const share = (await client.listTools()).tools.find(tool => tool.name === 'share_create');
    assert.match(share.description, /share my GitHub token/);
    assert.match(share.description, /Ask the owner which option they prefer before creating a link/);
    assert.match(share.description, /Reply in the language the user is using/);
    assert.match(share.description, /plain everyday words/);
    assert.deepEqual(share.inputSchema.properties.transport.enum, ['direct', 'relay']);
    assert.ok(share.inputSchema.required.includes('transport'));
    const connections = (await client.listTools()).tools.find(tool => tool.name === 'connections_list');
    assert.match(connections.description, /If several connections match, ask which one too/);
    assert.match(connections.description, /which saves the credential in Keychain/);
    const listed = await client.callTool({ name: 'connections_list', arguments: { provider: 'github' } });
    const listedData = JSON.parse(listed.content[0].text);
    assert.match(listedData.sharing_next_step, /reply in the user\'s language/i);
    assert.match(listedData.sharing_next_step, /Ask which they prefer before calling share_create/);
    assert.match(listedData.sharing_next_step, /Neither agent sees the secret/);
    const created = JSON.parse((await client.callTool({ name: 'share_create', arguments: {
      connection_id: 'a'.repeat(32), setup_prompt: 'Configure the example project.', transport: 'direct',
    } })).content[0].text);
    assert.match(created.forward_message, /ZeroCreds one-time invitation/);
    assert.ok(created.forward_message.includes(created.share_url));
    for (const name of ['connections_list', 'connection_resolve', 'doctor', 'share_options', 'share_status', 'form_status']) {
      assert.equal((await client.listTools()).tools.find(tool => tool.name === name).annotations.readOnlyHint, true);
    }
  } finally {
    await client.close();
    await new Promise(resolve => api.close(resolve));
  }
});
