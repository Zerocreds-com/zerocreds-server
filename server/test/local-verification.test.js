'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { verifyLocalCredential } = require('../src/local-verification');

test('GitHub verification returns provider identity and observed scopes, never the token', async () => {
  const token = 'synthetic-github-secret';
  let request;
  const result = await verifyLocalCredential('github', { token }, async (url, options) => {
    request = { url, options };
    return new Response(JSON.stringify({ id: 42, login: 'test-user' }), {
      status: 200,
      headers: { 'x-oauth-scopes': 'repo, read:org' },
    });
  });
  assert.equal(request.url, 'https://api.github.com/user');
  assert.equal(request.options.redirect, 'error');
  assert.equal(request.options.headers.Authorization, `Bearer ${token}`);
  assert.deepEqual(result, {
    status: 'valid',
    identity: { id: '42', login: 'test-user' },
    permissions: ['repo', 'read:org'],
    permission_evidence: 'provider_verified',
  });
  assert.ok(!JSON.stringify(result).includes(token));
});

test('Cloudflare verification reports expiry but does not infer permissions', async () => {
  const result = await verifyLocalCredential('cloudflare', { api_token: 'synthetic-cf-secret' }, async () =>
    new Response(JSON.stringify({ success: true, result: {
      id: 'token-id', status: 'active', expires_on: '2030-01-02T00:00:00Z',
    } }), { status: 200 }));
  assert.deepEqual(result, {
    status: 'valid',
    identity: { token_id: 'token-id' },
    permissions: [],
    permission_evidence: 'unknown',
    provider_expires_at: '2030-01-02T00:00:00Z',
  });
  assert.ok(!JSON.stringify(result).includes('synthetic-cf-secret'));
});

test('unsupported providers and provider/network failures fail closed', async () => {
  assert.deepEqual(await verifyLocalCredential('unknown', { token: 'x' }), { status: 'unsupported_provider' });
  assert.deepEqual(await verifyLocalCredential('github', { token: 'x' }, async () => {
    throw new Error('network detail must not escape');
  }), { status: 'unavailable' });
  assert.deepEqual(await verifyLocalCredential('github', { token: 'x' }, async () =>
    new Response('{}', { status: 401 })), { status: 'invalid' });
});
