'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const plugin = require('../../opencode-plugin/zerocreds-events');

test('OpenCode plugin resumes the originating session on a value-free done event', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-plugin-'));
  const tokenFile = path.join(dir, 'admin-token');
  const adminToken = `test-${'x'.repeat(40)}`;
  fs.writeFileSync(tokenFile, adminToken, { mode: 0o600 });
  let requestAuth;
  let requestPath;
  const server = http.createServer((req, res) => {
    requestAuth = req.headers.authorization;
    requestPath = req.url;
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.end('event: done\ndata: {"status":"done"}\n\n');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const resumed = [];
  try {
    const hooks = await plugin({ client: { session: { promptAsync: async (input) => resumed.push(input) } } }, {
      baseUrl: `http://127.0.0.1:${server.address().port}`, adminTokenFile: tokenFile,
    });
    const formToken = 'a'.repeat(32);
    await hooks['tool.execute.after']({ tool: 'form_create', sessionID: 'session-123' }, {
      title: 'Created', output: JSON.stringify({ token: formToken }), metadata: {},
    });
    for (let i = 0; i < 50 && resumed.length === 0; i++) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(requestAuth, `Bearer ${adminToken}`);
    assert.equal(requestPath, `/api/session/${formToken}/events`);
    assert.equal(resumed.length, 1);
    assert.equal(resumed[0].path.id, 'session-123');
    assert.match(resumed[0].body.parts[0].text, /form_status/);
    assert.doesNotMatch(resumed[0].body.parts[0].text, new RegExp(formToken));
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('OpenCode listener reconnects after an interrupted stream and resumes once', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-plugin-reconnect-'));
  const tokenFile = path.join(dir, 'admin-token');
  fs.writeFileSync(tokenFile, `test-${'x'.repeat(40)}`, { mode: 0o600 });
  let requests = 0;
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.end(++requests === 1 ? 'event: pending\ndata: {"status":"pending"}\n\n'
      : 'event: done\ndata: {"status":"done"}\n\n');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const resumed = [];
  try {
    const hooks = await plugin({ client: { session: { promptAsync: async value => resumed.push(value) } } }, {
      baseUrl: `http://127.0.0.1:${server.address().port}`, adminTokenFile: tokenFile,
    });
    await hooks['tool.execute.after']({ tool: 'form_create', sessionID: 'original-session' }, {
      output: JSON.stringify({ token: 'b'.repeat(32) }),
    });
    for (let i = 0; i < 100 && resumed.length === 0; i++) await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(requests, 2);
    assert.equal(resumed.length, 1);
    assert.equal(resumed[0].path.id, 'original-session');
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
