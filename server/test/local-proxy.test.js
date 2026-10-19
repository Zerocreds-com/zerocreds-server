'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const PROXY_SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'local-proxy.js');
const { hostHeaderFor } = require('../../scripts/local-proxy.js');;

async function freePort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

function get(port, route, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: route, method: 'GET', headers }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, raw, headers: res.headers }));
    });
    req.once('error', reject);
    req.end();
  });
}

async function waitForPort(port, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { await get(port, '/health'); return true; } catch { await new Promise((r) => setTimeout(r, 50)); }
  }
  return false;
}

test('the local proxy forwards the path unchanged and rewrites the host header', async () => {
  const upstreamPort = await freePort();
  const proxyPort = await freePort();
  const seen = [];
  const upstream = http.createServer((req, res) => {
    seen.push({ url: req.url, host: req.headers.host });
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: true, path: req.url }));
  });
  await new Promise((resolve) => upstream.listen(upstreamPort, '127.0.0.1', resolve));

  const child = spawn(process.execPath, [PROXY_SCRIPT], {
    env: {
      ...process.env,
      ZEROCREDS_PROXY_PORT: String(proxyPort),
      ZEROCREDS_PROXY_TARGET: `http://127.0.0.1:${upstreamPort}`,
      ZEROCREDS_PROXY_HOST: 'localhost',
      ZEROCREDS_PROXY_HOSTS: '127.0.0.1',
    },
    stdio: 'ignore',
  });

  try {
    assert.ok(await waitForPort(proxyPort), 'the proxy starts listening');
    seen.length = 0;
    const response = await get(proxyPort, '/zerocreds/api/local/connections', { Host: 'localhost' });
    assert.equal(response.status, 200);
    assert.deepEqual(JSON.parse(response.raw), { ok: true, path: '/zerocreds/api/local/connections' });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].url, '/zerocreds/api/local/connections', 'the mount prefix reaches the server untouched');
    assert.equal(seen[0].host, `localhost:${proxyPort}`, 'the host header carries the port the proxy serves on');
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test('the proxy sends the host header a browser would send', () => {
  // The server compares the Host header with the host of its configured base URL,
  // so a proxy on a non-default port has to include that port.
  assert.equal(hostHeaderFor(80, 'localhost'), 'localhost');
  assert.equal(hostHeaderFor(443, 'localhost'), 'localhost');
  assert.equal(hostHeaderFor(8080, 'localhost'), 'localhost:8080');
  assert.equal(hostHeaderFor(8080, 'localhost:3456'), 'localhost:3456');
  assert.equal(hostHeaderFor(80, undefined), 'localhost');
});

test('the local proxy answers with a clear error when the server is unreachable', async () => {
  const proxyPort = await freePort();
  const deadPort = await freePort();
  const child = spawn(process.execPath, [PROXY_SCRIPT], {
    env: {
      ...process.env,
      ZEROCREDS_PROXY_PORT: String(proxyPort),
      ZEROCREDS_PROXY_TARGET: `http://127.0.0.1:${deadPort}`,
      ZEROCREDS_PROXY_HOST: 'localhost',
      ZEROCREDS_PROXY_HOSTS: '127.0.0.1',
    },
    stdio: 'ignore',
  });

  try {
    assert.ok(await waitForPort(proxyPort), 'the proxy starts listening');
    const response = await get(proxyPort, '/health', { Host: 'localhost' });
    assert.equal(response.status, 502);
    assert.equal(JSON.parse(response.raw).error, 'zerocreds local server is unreachable');
  } finally {
    child.kill('SIGTERM');
  }
});
