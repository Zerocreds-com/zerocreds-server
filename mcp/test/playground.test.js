'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

test('local MCP provisions synthetic playground runner and form tools', async () => {
  const token = 'local-playground-mcp-token-123456789012';
  const requests = [];
  const api = http.createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    requests.push({ method: req.method, url: req.url, body: raw ? JSON.parse(raw) : undefined,
      authorization: req.headers.authorization });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(req.url.endsWith('/forms')
      ? { mode: 'synthetic_only', warning: 'DO NOT ENTER REAL CREDENTIALS', url: 'http://127.0.0.1/f/test' }
      : { mode: 'synthetic_only', results: [{ scenario: 'valid', outcome: 'accepted', value_returned: false }] }));
  });
  await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
  const client = new Client({ name: 'playground-test-client', version: '1.0.0' });
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
    assert.ok(tools.some(tool => tool.name === 'playground_scenarios'));
    assert.ok(tools.some(tool => tool.name === 'playground_run'));
    assert.ok(tools.some(tool => tool.name === 'playground_form'));
    const run = await client.callTool({ name: 'playground_run', arguments: {
      rules: [{ type: 'matches', pattern: '^PLAYGROUND_SYNTHETIC_VALID_' }], scenarios: ['valid'],
    } });
    assert.match(run.content[0].text, /"value_returned": false/);
    const form = await client.callTool({ name: 'playground_form', arguments: {
      rules: [{ type: 'min_length', value: 8 }],
    } });
    assert.match(form.content[0].text, /DO NOT ENTER REAL CREDENTIALS/);
    assert.deepEqual(requests.map(item => item.url), ['/api/local/playground/run', '/api/local/playground/forms']);
    assert.ok(requests.every(item => item.authorization === `Bearer ${token}`));
  } finally {
    await client.close();
    await new Promise(resolve => api.close(resolve));
  }
});
