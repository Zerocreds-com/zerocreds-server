'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const http = require('node:http');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

const MCP_ENTRY = path.join(__dirname, '..', 'index.js');

function mcpEnv(extra) {
  return { ...process.env, ZEROCREDS_LOCAL_MODE: '1', ZEROCREDS_ADMIN_TOKEN: 'local-admin-token-12345678901234567890',
    ZEROCREDS_DEFAULT_DESTINATION: 'mac-keychain', ZEROCREDS_WALLET_API_TOKEN: '', ...extra };
}

function runMcp(env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [MCP_ENTRY], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => resolve({ code, stderr }));
  });
}

test('the local MCP accepts a base URL with a mount prefix', async () => {
  const calls = [];
  const api = http.createServer((req, res) => {
    calls.push(req.url);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({}));
  });
  await new Promise((resolve) => api.listen(0, '127.0.0.1', resolve));
  const port = api.address().port;
  const client = new Client({ name: 'base-url-test-client', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath, args: [MCP_ENTRY],
    env: mcpEnv({ ZEROCREDS_URL: `http://127.0.0.1:${port}/zerocreds` }),
  });
  try {
    await client.connect(transport);
    const names = (await client.listTools()).tools.map((tool) => tool.name);
    assert.ok(names.includes('discovery_sources'), 'the tools are registered');
    await client.callTool({ name: 'discovery_sources', arguments: {} });
    assert.ok(calls.length > 0, 'the server was called');
    assert.ok(calls.every((url) => url.startsWith('/zerocreds/')), `the mount prefix reaches the server: ${calls.join(', ')}`);
  } finally {
    await client.close();
    await new Promise((resolve) => api.close(resolve));
  }
});

test('the local MCP rejects a base URL that is not loopback', async () => {
  const result = await runMcp(mcpEnv({ ZEROCREDS_URL: 'https://zerocreds.ru' }));
  assert.notEqual(result.code, 0, 'the server refuses to start');
  assert.match(result.stderr, /loopback/);
});

test('the local MCP rejects a base URL with credentials in it', async () => {
  const result = await runMcp(mcpEnv({ ZEROCREDS_URL: 'http://user:pass@127.0.0.1:3456/zerocreds' }));
  assert.notEqual(result.code, 0, 'the server refuses to start');
  assert.match(result.stderr, /loopback/);
});

test('the local MCP rejects a base URL without a destination', async () => {
  const result = await runMcp({ ...process.env, ZEROCREDS_LOCAL_MODE: '1', ZEROCREDS_URL: 'http://localhost/zerocreds',
    ZEROCREDS_ADMIN_TOKEN: 'local-admin-token-12345678901234567890', ZEROCREDS_DEFAULT_DESTINATION: '', ZEROCREDS_WALLET_API_TOKEN: '' });
  assert.notEqual(result.code, 0, 'the server refuses to start');
  assert.match(result.stderr, /destination/);
});
