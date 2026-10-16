'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

test('local credential form response gives the agent a friendly user-facing link', async () => {
  const token = 'local-admin-token-12345678901234567890';
  const formUrl = 'http://127.0.0.1:3456/f/' + 'a'.repeat(32);
  const api = http.createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    assert.equal(req.method, 'POST');
    assert.equal(req.url, '/api/session/create');
    const body = JSON.parse(raw);
    assert.equal(body.service, 'deepgram');
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ token: 'a'.repeat(32), url: formUrl, expires_at: '2030-01-01T00:00:00.000Z' }));
  });
  await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
  const client = new Client({ name: 'create-session-test-client', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath, args: [path.join(__dirname, '..', 'index.js')],
    env: { ...process.env, ZEROCREDS_URL: `http://127.0.0.1:${api.address().port}`,
      ZEROCREDS_LOCAL_MODE: '1', ZEROCREDS_ADMIN_TOKEN: token,
      ZEROCREDS_DEFAULT_DESTINATION: 'mac-keychain', ZEROCREDS_WALLET_API_TOKEN: '' },
  });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: 'zerocreds_create_session', arguments: {
      title: 'Connect Deepgram',
      fields: [{ name: 'api_key', label: 'Deepgram API key', type: 'password', level: 'secret' }],
      service: 'deepgram', uid: 'work',
    } });
    const response = JSON.parse(result.content[0].text);
    assert.equal(response.url, formUrl);
    assert.match(response.user_message, /\[Открыть защищённую форму ZeroCreds\]\(http:\/\/127\.0\.0\.1:3456\/f\//);
    assert.equal(response.user_message.match(/\[([^\]]+)\]\(/)[1], 'Открыть защищённую форму ZeroCreds');
  } finally {
    await client.close();
    await new Promise(resolve => api.close(resolve));
  }
});
