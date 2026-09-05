'use strict';
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

async function startServer(opts = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-test-'));
  const pendingDir = path.join(tmpDir, 'pending');
  const tokensDir = path.join(tmpDir, 'tokens');
  const savedDir = path.join(tmpDir, 'saved');
  fs.mkdirSync(pendingDir);
  fs.mkdirSync(tokensDir);
  fs.mkdirSync(savedDir);

  const adminToken = opts.adminToken ?? ('test-' + crypto.randomBytes(8).toString('hex'));
  const destinationsFile = path.join(tmpDir, 'destinations.json');
  const integratorsFile = path.join(tmpDir, 'integrators.json');
  fs.writeFileSync(destinationsFile, JSON.stringify(opts.namedDestinations || {}));
  fs.writeFileSync(integratorsFile, JSON.stringify(opts.integrators || {}));

  const { createApp } = require('../src/server');
  const server = createApp({ adminToken, pendingDir, tokensDir, savedDir, destinationsFile, integratorsFile, baseUrl: 'http://test.local' });

  await new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', resolve);
    server.once('error', reject);
  });

  const port = server.address().port;

  return {
    port, adminToken, tmpDir, pendingDir, tokensDir, savedDir, integratorsFile, destinationsFile, server,
    async stop() {
      await new Promise(r => server.close(r));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    },
  };
}

function request(port, method, urlPath, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const bodyStr = body !== undefined ? JSON.stringify(body) : undefined;
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path: urlPath,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(bodyStr ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {}),
        ...headers,
      },
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed, raw: data });
      });
    });
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

module.exports = { startServer, request };
