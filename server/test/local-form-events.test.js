'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createApp } = require('../src/server');

function request(port, method, pathname, body, token) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request({ hostname: '127.0.0.1', port, method, path: pathname,
      headers: { Host: '127.0.0.1', ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}) } }, (res) => {
      let text = '';
      res.on('data', chunk => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, text, headers: res.headers }));
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function openEventStream(port, pathname, token) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: pathname,
      headers: { Host: '127.0.0.1', Authorization: `Bearer ${token}` } }, (res) => {
      let text = '';
      res.on('data', chunk => { text += chunk; });
      resolve({ res, get text() { return text; }, close: () => req.destroy() });
    });
    req.on('error', reject);
    req.end();
  });
}

test('local form event stream reports completion only after successful save', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-local-events-'));
  const adminToken = `test-${'x'.repeat(40)}`;
  const destinationsFile = path.join(dir, 'destinations.json');
  fs.writeFileSync(destinationsFile, JSON.stringify({ local: { type: 'local_file', uid: 'events', filename: 'credential' } }));
  const server = createApp({
    localMode: true, adminToken, baseUrl: 'http://127.0.0.1',
    pendingDir: path.join(dir, 'pending'), tokensDir: path.join(dir, 'tokens'),
    signingKeyFile: path.join(dir, 'signing.pem'),
    destinationsFile,
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const created = await request(port, 'POST', '/api/session/create', {
      title: 'event test', fields: [{ name: 'token', label: 'Token', type: 'password' }],
      destination: 'local', ttl_minutes: 5,
    }, adminToken);
    assert.equal(created.status, 200, created.text);
    const formToken = JSON.parse(created.text).token;

    const unauthorized = await request(port, 'GET', `/api/session/${formToken}/events`);
    assert.equal(unauthorized.status, 401);

    const event = await openEventStream(port, `/api/session/${formToken}/events`, adminToken);
    assert.equal(event.res.statusCode, 200);
    assert.match(event.res.headers['content-type'], /text\/event-stream/);
    await new Promise(resolve => setImmediate(resolve));
    assert.match(event.text, /event: pending/);

    // A listener arriving after Submit claimed the form must stay subscribed.
    const pendingFile = path.join(dir, 'pending', `${formToken}.json`);
    const claimedFile = path.join(dir, 'pending', `${formToken}.claimed`);
    fs.renameSync(pendingFile, claimedFile);
    const duringSubmit = await openEventStream(port, `/api/session/${formToken}/events`, adminToken);
    await new Promise(resolve => setImmediate(resolve));
    assert.match(duringSubmit.text, /event: pending/);
    assert.doesNotMatch(duringSubmit.text, /event: expired/);
    fs.renameSync(claimedFile, pendingFile);

    const submitted = await request(port, 'POST', `/f/${formToken}`, { t: formToken, fields: { token: 'never-echo-this' } });
    assert.equal(submitted.status, 200, submitted.text);
    await new Promise(resolve => setImmediate(resolve));
    assert.match(event.text, /event: done/);
    assert.match(duringSubmit.text, /event: done/);
    assert.doesNotMatch(event.text, /never-echo-this/);
    event.close();
    duringSubmit.close();
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
