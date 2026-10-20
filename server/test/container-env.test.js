'use strict';
const { test, before } = require('node:test');
const assert = require('node:assert/strict');

let containerEnv;
let settingsFingerprint;

before(async () => {
  ({ containerEnv, settingsFingerprint } = await import('../cloudflare-sandbox/env.mjs'));
});

test('only the settings that are set reach the container', () => {
  const env = containerEnv({
    ZEROCREDS_VAULT_DATA_KEY: 'a-key',
    ZEROCREDS_ADMIN_TOKEN: 'an-admin-token',
    OPENBAO_ROOT_TOKEN: undefined,
    ZEROCREDS_VAULT_KEY_REF: '',
  });
  assert.deepEqual(Object.keys(env).sort(), ['ZEROCREDS_ADMIN_TOKEN', 'ZEROCREDS_VAULT_DATA_KEY']);
  assert.equal('OPENBAO_ROOT_TOKEN' in env, false);
});

test('a container never sees both custody modes at once', () => {
  const durable = containerEnv({ ZEROCREDS_VAULT_DATA_KEY: 'a-key' });
  const legacy = containerEnv({ OPENBAO_ROOT_TOKEN: 'a-token' });
  assert.equal('OPENBAO_ROOT_TOKEN' in durable, false);
  assert.equal('ZEROCREDS_VAULT_DATA_KEY' in legacy, false);
});

test('the settings fingerprint changes with the settings and hides them', async () => {
  const first = await settingsFingerprint({ ZEROCREDS_VAULT_DATA_KEY: 'a-key', OPENBAO_ROOT_TOKEN: undefined });
  const same = await settingsFingerprint({ ZEROCREDS_VAULT_DATA_KEY: 'a-key', OPENBAO_ROOT_TOKEN: undefined });
  const other = await settingsFingerprint({ ZEROCREDS_VAULT_DATA_KEY: 'another-key' });
  assert.equal(first, same);
  assert.notEqual(first, other);
  assert.equal(first.includes('a-key'), false);
  assert.match(first, /^[0-9a-f]{64}$/);
});
