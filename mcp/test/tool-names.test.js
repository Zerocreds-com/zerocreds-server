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
    assert.match(share.description, /When asking which, also explain/);
    const connections = (await client.listTools()).tools.find(tool => tool.name === 'connections_list');
    assert.match(connections.description, /If several match, ask which one and explain what happens after the choice/);
    assert.match(connections.description, /share_claim saves the credential in Keychain/);
    const listed = await client.callTool({ name: 'connections_list', arguments: { provider: 'github' } });
    const listedData = JSON.parse(listed.content[0].text);
    assert.match(listedData.sharing_next_step, /after they choose, share_create/);
    assert.match(listedData.sharing_next_step, /share_claim and writes the credential directly/);
    assert.match(listedData.sharing_next_step, /Neither agent receives or displays the raw credential/);
    for (const name of ['connections_list', 'connection_resolve', 'doctor', 'share_status', 'form_status']) {
      assert.equal((await client.listTools()).tools.find(tool => tool.name === name).annotations.readOnlyHint, true);
    }
  } finally {
    await client.close();
    await new Promise(resolve => api.close(resolve));
  }
});
