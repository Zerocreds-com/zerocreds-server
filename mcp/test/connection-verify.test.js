'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

test('local MCP verifies Deepgram grant capability and returns only safe diagnostics', async () => {
  const token = 'local-admin-token-12345678901234567890';
  let request;
  const api = http.createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    request = { method: req.method, url: req.url, authorization: req.headers.authorization, body: JSON.parse(raw) };
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      verification: 'valid',
      identity: { grant_capable: true },
      diagnostic: { upstream_status: 200, grant_expires_in: 30 },
    }));
  });
  await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
  const client = new Client({ name: 'connection-verify-test-client', version: '1.0.0' });
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
    const verify = listed.tools.find(tool => tool.name === 'zerocreds_connection_verify');
    assert.ok(verify);
    assert.deepEqual(verify.inputSchema.properties.provider.enum, ['github', 'cloudflare', 'deepgram']);

    const result = await client.callTool({ name: 'zerocreds_connection_verify', arguments: {
      provider: 'deepgram', account_alias: 'chemistry-gpt-deepgram',
    } });
    assert.equal(request.method, 'POST');
    assert.equal(request.url, '/api/local/connections/verify');
    assert.equal(request.authorization, `Bearer ${token}`);
    assert.deepEqual(request.body, { provider: 'deepgram', account_alias: 'chemistry-gpt-deepgram' });
    const text = result.content[0].text;
    assert.match(text, /"grant_capable": true/);
    assert.match(text, /"grant_expires_in": 30/);
    assert.ok(!text.includes('access_token'));
    assert.ok(!text.includes('DEEPGRAM_API_KEY'));
  } finally {
    await client.close();
    await new Promise(resolve => api.close(resolve));
  }
});
