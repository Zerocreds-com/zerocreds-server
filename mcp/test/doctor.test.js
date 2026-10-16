'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

test('local MCP provisions zerocreds_doctor and returns the sanitized server report', async () => {
  const token = 'local-admin-token-12345678901234567890';
  let request;
  const api = http.createServer(async (req, res) => {
    request = { method: req.method, url: req.url, authorization: req.headers.authorization };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ overall: 'ok', checks: [{ name: 'macos_keychain', status: 'ok' }],
      credential_values_read: false, credential_values_returned: false }));
  });
  await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
  const client = new Client({ name: 'doctor-test-client', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(__dirname, '..', 'index.js')],
    env: { ...process.env, ZEROCREDS_URL: `http://127.0.0.1:${api.address().port}`,
      ZEROCREDS_LOCAL_MODE: '1', ZEROCREDS_ADMIN_TOKEN: token,
      ZEROCREDS_DEFAULT_DESTINATION: 'mac-keychain', ZEROCREDS_WALLET_API_TOKEN: '' },
  });
  try {
    await client.connect(transport);
    const tools = (await client.listTools()).tools;
    assert.ok(tools.some(tool => tool.name === 'zerocreds_doctor'));
    const result = await client.callTool({ name: 'zerocreds_doctor', arguments: {} });
    assert.deepEqual(request, { method: 'GET', url: '/api/local/doctor', authorization: `Bearer ${token}` });
    assert.match(result.content[0].text, /"overall": "ok"/);
    assert.match(result.content[0].text, /"credential_values_returned": false/);
  } finally {
    await client.close();
    await new Promise(resolve => api.close(resolve));
  }
});
