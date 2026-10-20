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
    res.end(JSON.stringify({}));
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
  } finally {
    await client.close();
    await new Promise(resolve => api.close(resolve));
  }
});
