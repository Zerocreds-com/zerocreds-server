'use strict';

// Synthetic-only CI fixture. No local credential store, user secret or network call.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { encrypt, decrypt } = require('../server/src/local-share');

const [stage, directory] = process.argv.slice(2);
if (!['prepare', 'send', 'receive'].includes(stage) || !directory) {
  throw new Error('usage: node scripts/share-cross-platform.cjs prepare|send|receive DIRECTORY');
}
const file = name => path.join(directory, name);
const sample = 'synthetic-ci-credential-only';

if (stage === 'prepare') {
  fs.mkdirSync(directory, { recursive: true });
  const keys = crypto.generateKeyPairSync('x25519');
  fs.writeFileSync(file('fixture.json'), JSON.stringify({
    id: crypto.randomBytes(16).toString('hex'),
    secret: crypto.randomBytes(32).toString('hex'),
    public_key: keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    private_key: keys.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
  }));
} else if (stage === 'send') {
  const fixture = JSON.parse(fs.readFileSync(file('fixture.json'), 'utf8'));
  const envelope = encrypt(Buffer.from(fixture.secret, 'hex'), fixture.id, fixture.public_key, {
    metadata: { provider: 'ci_fixture', account_alias: 'cross_os', setup_prompt: 'Configure only the synthetic CI fixture.' },
    fields: { token: sample },
  });
  assert.ok(!JSON.stringify(envelope).includes(sample));
  fs.writeFileSync(file('envelope.json'), JSON.stringify(envelope));
} else {
  const fixture = JSON.parse(fs.readFileSync(file('fixture.json'), 'utf8'));
  const envelope = JSON.parse(fs.readFileSync(file('envelope.json'), 'utf8'));
  const privateKey = crypto.createPrivateKey({ key: Buffer.from(fixture.private_key, 'base64'),
    format: 'der', type: 'pkcs8' });
  const payload = decrypt(Buffer.from(fixture.secret, 'hex'), fixture.id, privateKey, envelope);
  assert.deepEqual(payload.fields, { token: sample });
  assert.equal(payload.metadata.setup_prompt, 'Configure only the synthetic CI fixture.');
  process.stdout.write('cross-platform encrypted handoff verified\n');
}
