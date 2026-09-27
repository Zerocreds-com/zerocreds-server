'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { canonicalJson, signPayload, verifySigned } = require('../src/receipts');

test('canonicalJson — sorted keys, no whitespace, undefined dropped', () => {
  assert.equal(canonicalJson({ b: 1, a: [true, null, 'x'], c: { z: 'é', y: undefined } }), '{"a":[true,null,"x"],"b":1,"c":{"z":"é"}}');
  assert.equal(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 2, a: 1 }));
  assert.throws(() => canonicalJson({ a: NaN }));
  assert.throws(() => canonicalJson({ a: () => 1 }));
});

test('signPayload / verifySigned — Ed25519 round trip, key order independent, tamper and wrong key fail', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const key = { privateKey, keyId: 'k1' };
  const signed = signPayload(key, { handle: 'cred:x', n: 1 });
  assert.equal(signed.alg, 'Ed25519');
  assert.equal(signed.key_id, 'k1');
  assert.ok(verifySigned(publicKey, signed));
  assert.ok(verifySigned(publicKey.export({ type: 'spki', format: 'pem' }), { ...signed, payload: { n: 1, handle: 'cred:x' } }));
  assert.equal(verifySigned(publicKey, { ...signed, payload: { handle: 'cred:y', n: 1 } }), false);
  assert.equal(verifySigned(crypto.generateKeyPairSync('ed25519').publicKey, signed), false);
  assert.equal(verifySigned(publicKey, { ...signed, signature: 'garbage' }), false);
});
