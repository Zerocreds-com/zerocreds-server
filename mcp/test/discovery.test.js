'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

test('local discovery MCP exposes staged preview, catalog and search tools', async () => {
  const token = 'local-admin-token-12345678901234567890';
  const previewId = 'a'.repeat(36);
  const calls = [];
  const api = http.createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    calls.push({ method: req.method, url: req.url, body: raw ? JSON.parse(raw) : null });
    res.setHeader('content-type', 'application/json');
    if (req.url === '/api/local/discovery/sources') return res.end(JSON.stringify({ sources: [], catalog_changes: 0 }));
    if (req.url === '/api/local/discovery/preview') return res.end(JSON.stringify({ preview_id: previewId, candidates: [], requires_user_confirmation_to_catalog: true }));
    if (req.url === '/api/local/discovery/catalog') return res.end(JSON.stringify({ catalogued: 1, secret_values_stored: false }));
    if (req.url.startsWith('/api/local/discovery/search?')) return res.end(JSON.stringify({ scope: 'catalog', results: [] }));
    res.writeHead(404).end(JSON.stringify({ error: 'not_found' }));
  });
  await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
  const client = new Client({ name: 'discovery-test-client', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath, args: [path.join(__dirname, '..', 'index.js')],
    env: { ...process.env, ZEROCREDS_URL: `http://127.0.0.1:${api.address().port}`,
      ZEROCREDS_LOCAL_MODE: '1', ZEROCREDS_ADMIN_TOKEN: token,
      ZEROCREDS_DEFAULT_DESTINATION: 'mac-keychain', ZEROCREDS_WALLET_API_TOKEN: '' },
  });
  try {
    await client.connect(transport);
    const names = (await client.listTools()).tools.map(tool => tool.name);
    for (const name of ['zerocreds_discovery_sources', 'zerocreds_discovery_preview', 'zerocreds_discovery_catalog', 'zerocreds_credentials_search']) {
      assert.ok(names.includes(name), `${name} is registered`);
    }
    const sources = await client.callTool({ name: 'zerocreds_discovery_sources', arguments: {} });
    assert.equal(JSON.parse(sources.content[0].text).catalog_changes, 0);
    const preview = await client.callTool({ name: 'zerocreds_discovery_preview', arguments: { source_ids: ['github_cli'] } });
    assert.equal(JSON.parse(preview.content[0].text).preview_id, previewId);
    await client.callTool({ name: 'zerocreds_discovery_catalog', arguments: { preview_id: previewId, refs: ['disc_0123456789abcdef01234567'] } });
    await client.callTool({ name: 'zerocreds_credentials_search', arguments: { q: 'github' } });
    assert.deepEqual(calls.map(call => call.url.split('?')[0]), [
      '/api/local/discovery/sources', '/api/local/discovery/preview', '/api/local/discovery/catalog', '/api/local/discovery/search',
    ]);
    assert.equal(calls[2].body.preview_id, previewId);
  } finally {
    await client.close();
    await new Promise(resolve => api.close(resolve));
  }
});
