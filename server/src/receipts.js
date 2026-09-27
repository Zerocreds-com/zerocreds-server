'use strict';
// Signed form manifests and submission receipts (Ed25519 over canonical JSON).
// Nothing signed here ever contains submitted values — only names, destinations and ids.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Canonical JSON: object keys sorted, no whitespace (JCS for the value types we sign:
// strings, finite numbers, booleans, null, arrays and plain objects).
function canonicalJson(v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('canonicalJson: non-finite number');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (typeof v === 'object') {
    const keys = Object.keys(v).filter(k => v[k] !== undefined).sort();
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
  }
  throw new Error(`canonicalJson: unsupported type ${typeof v}`);
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

// Loads the Ed25519 signing key from keyFile (PKCS#8 PEM), creating it (0600) on first run.
function loadSigningKey(keyFile) {
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(fs.readFileSync(keyFile, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') throw new Error(`signing key ${keyFile}: ${e.message}`);
    privateKey = crypto.generateKeyPairSync('ed25519').privateKey;
    fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
    fs.writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error(`signing key ${keyFile}: must be Ed25519`);
  const publicKey = crypto.createPublicKey(privateKey);
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return {
    privateKey,
    publicKey,
    keyId: sha256Hex(spki).slice(0, 16),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

// Wraps payload as { payload, alg, key_id, signature }; signature is base64url over canonicalJson(payload).
function signPayload(key, payload) {
  const signature = crypto.sign(null, Buffer.from(canonicalJson(payload)), key.privateKey).toString('base64url');
  return { payload, alg: 'Ed25519', key_id: key.keyId, signature };
}

function verifySigned(publicKey, signed) {
  try {
    const pub = typeof publicKey === 'string' ? crypto.createPublicKey(publicKey) : publicKey;
    return crypto.verify(null, Buffer.from(canonicalJson(signed.payload)), pub, Buffer.from(signed.signature, 'base64url'));
  } catch { return false; }
}

module.exports = { canonicalJson, sha256Hex, loadSigningKey, signPayload, verifySigned };
