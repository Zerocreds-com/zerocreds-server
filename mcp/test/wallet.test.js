'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const path = require('path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

test('agent MCP wallet tools create a form and poll value-free status', async () => {
  const token = 'scoped-wallet-api-token-12345678901234567890';
  const formId = 'a'.repeat(32);
  const connectionId = 'connection_123';
  const calls = [];
  const api = http.createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    calls.push({ method: req.method, path: req.url, authorization: req.headers.authorization,
      body: raw ? JSON.parse(raw) : null });
    res.setHeader('content-type', 'application/json');
    if (req.method === 'POST' && req.url === '/api/wallet/forms') {
      return res.end(JSON.stringify({ form_id: formId, connection_id: connectionId,
        url: `http://127.0.0.1:${api.address().port}/f/${formId}`,
        status_url: `http://127.0.0.1:${api.address().port}/api/wallet/forms/${formId}/status`,
        expires_at: '2030-01-01T00:00:00.000Z', state: 'pending' }));
    }
    if (req.method === 'GET' && req.url === `/api/wallet/forms/${formId}/status`) {
      return res.end(JSON.stringify({ form_id: formId, connection_id: connectionId,
        status: 'done', kv_version: 1 }));
    }
    if (req.method === 'GET' && req.url === `/api/wallet/connections/${connectionId}`) {
      return res.end(JSON.stringify({ connection_id: connectionId, provider: 'tilda', state: 'active', kv_version: 1 }));
    }
    if (req.method === 'POST' && req.url === `/api/wallet/connections/${connectionId}/revoke`) {
      return res.end(JSON.stringify({ connection_id: connectionId, state: 'revoked' }));
    }
    res.writeHead(404).end(JSON.stringify({ error: 'not_found' }));
  });
  await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
  const client = new Client({ name: 'wallet-test-client', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath, args: [path.join(__dirname, '..', 'index.js')],
    env: { ...process.env, ZEROCREDS_URL: `http://127.0.0.1:${api.address().port}`,
      ZEROCREDS_WALLET_API_TOKEN: token, ZEROCREDS_ADMIN_TOKEN: '' },
  });
  try {
    await client.connect(transport);
    const tools = await client.listTools();
    assert.ok(tools.tools.some(tool => tool.name === 'wallet_form_create'));
    assert.ok(tools.tools.some(tool => tool.name === 'wallet_form_status'));
    const created = await client.callTool({ name: 'wallet_form_create', arguments: {
      provider: 'tilda', kind: 'login', fields: [
        { name: 'username', label: 'Username' }, { name: 'password', label: 'Password', type: 'password' },
      ],
    } });
    assert.ok(created.content[0].text.startsWith('{'), JSON.stringify(created));
    assert.equal(JSON.parse(created.content[0].text).connection_id, connectionId);
    const status = await client.callTool({ name: 'wallet_form_status', arguments: { form_id: formId } });
    assert.equal(JSON.parse(status.content[0].text).status, 'done');
    const connection = await client.callTool({ name: 'wallet_connection_status', arguments: { connection_id: connectionId } });
    assert.equal(JSON.parse(connection.content[0].text).state, 'active');
    const revoked = await client.callTool({ name: 'wallet_connection_revoke', arguments: { connection_id: connectionId } });
    assert.equal(JSON.parse(revoked.content[0].text).state, 'revoked');
    assert.deepEqual(calls.map(c => c.path), ['/api/wallet/forms', `/api/wallet/forms/${formId}/status`,
      `/api/wallet/connections/${connectionId}`, `/api/wallet/connections/${connectionId}/revoke`]);
    assert.ok(calls.every(c => c.authorization === `Bearer ${token}`));
    assert.equal(calls[0].body.owner_id, undefined);
    assert.equal(calls[0].body.profile_id, undefined);
    assert.equal(calls[0].body.destination, undefined);
  } finally {
    await client.close();
    await new Promise(resolve => api.close(resolve));
  }
});
