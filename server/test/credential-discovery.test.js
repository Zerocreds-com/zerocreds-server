'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { discoverCredentialSources, searchCredentialMetadata, run } = require('../src/credential-discovery');

test('discovery subprocesses time out and discard partial output', async () => {
  const started = Date.now();
  const result = await run(process.execPath, ['-e', "process.stdout.write('partial'); setInterval(() => {}, 1000)"], {}, 50);
  assert.equal(result.ok, false);
  assert.equal(result.stdout, '');
  assert.ok(Date.now() - started < 2000, 'hung provider CLI should not stall discovery');
});

test('discovery parses provider metadata without ever returning credential values', async () => {
  const responses = {
    gh: { ok: true, stdout: JSON.stringify({ hosts: { 'github.com': [
      { login: 'work-user', active: true, state: { name: 'success' }, scopes: ['repo', 'read:org'], token: 'SECRET_GH_TOKEN' },
      { login: 'personal-user', active: false, state: { name: 'success' }, scopes: ['read:user'], token: 'ANOTHER_TOKEN' },
    ] } }) },
    wrangler: { ok: true, stdout: JSON.stringify({ user: { email: 'cf@example.test' }, accounts: [{ name: 'edge-account' }], token: 'CF_SECRET' }) },
    gcloud: { ok: true, stdout: JSON.stringify([{ account: 'gcp@example.test', status: 'ACTIVE', access_token: 'GCP_SECRET' }]) },
  };
  const result = await discoverCredentialSources({
    platform: 'darwin', home: '/nonexistent', chromeExists: () => true,
    runCommand: async (command) => command === 'gh' ? responses.gh : command === 'wrangler' ? responses.wrangler : responses.gcloud,
    listKeychain: async () => ({ available: true, items: [{ account: 'keychain-user', service: 'github', label: 'GitHub item', password: 'KEYCHAIN_SECRET' }] }),
  });
  assert.equal(result.sources.find((x) => x.source_id === 'github_cli').candidate_count, 2);
  assert.equal(result.sources.find((x) => x.source_id === 'chrome').status, 'detected_unsupported');
  assert.ok(result.candidates.some((x) => x.account === 'work-user' && x.scopes.includes('repo')));
  const serialized = JSON.stringify(result);
  for (const secret of ['SECRET_GH_TOKEN', 'ANOTHER_TOKEN', 'CF_SECRET', 'GCP_SECRET', 'KEYCHAIN_SECRET']) {
    assert.ok(!serialized.includes(secret));
  }
  assert.ok(result.candidates.every((x) => !Object.keys(x).some((key) => /token|password|secret/i.test(key))));
});

test('metadata search ranks provider and matches labels and scopes', () => {
  const results = searchCredentialMetadata([
    { provider: 'github', source_id: 'github_cli', account: 'work', label: 'github.com', scopes: ['repo'] },
    { provider: 'cloudflare', source_id: 'cloudflare_cli', account: 'edge', label: 'Cloudflare account', scopes: [] },
  ], 'github repo');
  assert.equal(results[0].provider, 'github');
  assert.equal(results.length, 1);
});
