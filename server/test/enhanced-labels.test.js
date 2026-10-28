'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { discoverCredentialSources } = require('../src/credential-discovery');

async function discovery(overrides = {}) {
  return discoverCredentialSources({
    platform: 'darwin', home: '/nonexistent', chromeExists: () => false,
    runCommand: async () => ({ ok: false, stdout: '' }),
    listKeychain: async () => ({ available: true, items: [] }),
    ...overrides,
  });
}

test('keychain candidates get contextual display_labels', async () => {
  const result = await discovery({
    listKeychain: async () => ({ available: true, items: [
      { account: 'kobzevvv', label: 'Trained Agent GitHub Token', service: 'trained-agent-github-token' },
      { account: 'kobzevvv', label: 'Trained Agent GitHub Token', service: 'github.com' },
      { account: 'gha-compute-cluster', label: 'Trained Agent GitHub PAT', service: 'github.com' },
      { account: 'unknown', label: 'Other', service: 'github.com' },
      { account: 'Irina-5GHz', label: 'Irina-5GHz', service: 'AirPort' },
    ] }),
  });
  const keychain = result.candidates.filter((c) => c.provider === 'keychain');
  const byKey = Object.fromEntries(keychain.map((c) => [`${c.account}|${c.service}`, c]));
  
  assert.equal(byKey['kobzevvv|trained-agent-github-token'].display_label, 'GitHub Token (Main: kobzevvv)');
  assert.equal(byKey['kobzevvv|github.com'].display_label, 'GitHub Token (Project: kobzevvv)');
  assert.equal(byKey['gha-compute-cluster|github.com'].display_label, 'GitHub Token (Zen-Rings CI/CD)');
  assert.equal(byKey['unknown|github.com'].display_label, 'GitHub Token (Unknown: flexi-leads-bot)');
  assert.equal(byKey['Irina-5GHz|AirPort'].display_label, 'Irina-5GHz @ AirPort');
});
