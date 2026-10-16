'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { verifyLocalCredential, credentialHint } = require('../src/local-verification');

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

test('Deepgram verification checks grant capability and discards the temporary token', async () => {
  const key = 'synthetic-deepgram-key';
  const accessToken = 'temporary-grant-must-not-escape';
  let request;
  const result = await verifyLocalCredential('deepgram', { DEEPGRAM_API_KEY: key }, async (url, options) => {
    request = { url, options };
    return new Response(JSON.stringify({ access_token: accessToken, expires_in: 30 }), { status: 200 });
  });
  assert.equal(request.url, 'https://api.deepgram.com/v1/auth/grant');
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.headers.Authorization, `Token ${key}`);
  assert.equal(request.options.redirect, 'error');
  assert.deepEqual(result, {
    status: 'valid',
    identity: { grant_capable: true },
    permissions: [],
    permission_evidence: 'provider_verified',
    diagnostic: { upstream_status: 200, grant_expires_in: 30 },
  });
  assert.ok(!JSON.stringify(result).includes(key));
  assert.ok(!JSON.stringify(result).includes(accessToken));
  assert.deepEqual(credentialHint('deepgram', { DEEPGRAM_API_KEY: key }), {
    character_count: key.length, masked: 'syn…-key',
  });
  assert.equal(credentialHint('deepgram', { DEEPGRAM_API_KEY: 'short' }).masked, '[too short to mask safely]');
  assert.equal(credentialHint('github', { token: key }), null);
});

test('Deepgram verification distinguishes invalid keys and insufficient grant permissions', async () => {
  const invalid = await verifyLocalCredential('deepgram', { token: 'synthetic-key' }, async () =>
    new Response('{"err_code":"INVALID_AUTH","err_msg":"do not persist provider text"}', { status: 401 }));
  assert.deepEqual(invalid, { status: 'invalid', diagnostic: { upstream_status: 401, upstream_code: 'invalid_credentials' } });

  const badRequest = await verifyLocalCredential('deepgram', { DEEPGRAM_API_KEY: 'synthetic-key' }, async () =>
    new Response('{"err_code":"BAD_REQUEST","err_msg":"Invalid credentials."}', { status: 400 }));
  assert.deepEqual(badRequest, {
    status: 'invalid',
    diagnostic: { upstream_status: 400, upstream_code: 'BAD_REQUEST' },
  });
  assert.ok(!JSON.stringify(badRequest).includes('Invalid credentials'));

  const forbidden = await verifyLocalCredential('deepgram', { api_key: 'synthetic-key' }, async () =>
    new Response('{"err_code":"FORBIDDEN","err_msg":"Insufficient permissions."}', { status: 403 }));
  assert.deepEqual(forbidden, {
    status: 'insufficient_permissions',
    diagnostic: { upstream_status: 403, upstream_code: 'FORBIDDEN' },
  });
  assert.ok(!JSON.stringify(forbidden).includes('Insufficient permissions'));
});

test('unsupported providers and provider/network failures fail closed', async () => {
  assert.deepEqual(await verifyLocalCredential('unknown', { token: 'x' }), { status: 'unsupported_provider' });
  assert.deepEqual(await verifyLocalCredential('github', { token: 'x' }, async () => {
    throw new Error('network detail must not escape');
  }), { status: 'unavailable' });
  assert.deepEqual(await verifyLocalCredential('github', { token: 'x' }, async () =>
    new Response('{}', { status: 401 })), { status: 'invalid' });
});
