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

test('a candidate without a discriminator keeps the reference it already had', async () => {
  // github_cli has no service ambiguity, so its ref must stay byte-identical to
  // the one already written into existing local catalogs. A changed ref would
  // orphan every catalogued GitHub entry and duplicate it on the next catalog.
  const result = await discoverCredentialSources({
    platform: 'darwin', home: '/nonexistent', chromeExists: () => false,
    runCommand: async (command) => command === 'gh'
      ? { ok: true, stdout: JSON.stringify({ hosts: { 'github.com': [
        { login: 'kobzevvv', active: true, state: { name: 'success' }, scopes: ['repo'], token: 'SECRET' }] } }) }
      : { ok: false, stdout: '' },
    listKeychain: async () => ({ available: false, items: [] }),
  });
  const github = result.candidates.find((candidate) => candidate.provider === 'github');
  assert.equal(github.ref, 'disc_efd277ac77bc32859321ee88');
});

test('github candidates have friendly display labels', async () => {
  const result = await discoverCredentialSources({
    platform: 'darwin', home: '/nonexistent', chromeExists: () => false,
    runCommand: async (command) => command === 'gh'
      ? { ok: true, stdout: JSON.stringify({ hosts: { 'github.com': [
        { login: 'kobzevvv', active: true, state: { name: 'success' }, scopes: ['repo'], token: 'SECRET' }] } }) }
      : { ok: false, stdout: '' },
    listKeychain: async () => ({ available: false, items: [] }),
  });
  const github = result.candidates.find((candidate) => candidate.provider === 'github');
  assert.equal(github.display_label, 'GitHub Token (Main: kobzevvv)');
});

test('keychain candidates with identical account and label stay distinct by service', async () => {
  const result = await discoverCredentialSources({
    platform: 'darwin', home: '/nonexistent', chromeExists: () => false,
    runCommand: async () => ({ ok: false, stdout: '' }),
    listKeychain: async () => ({ available: true, items: [
      { account: 'kobzevvv', label: 'Trained Agent GitHub Token', service: 'trained-agent-github-token' },
      { account: 'kobzevvv', label: 'Trained Agent GitHub Token', service: 'github.com' },
    ] }),
  });
  const keychain = result.candidates.filter((candidate) => candidate.provider === 'keychain');
  assert.equal(keychain.length, 2, 'both Keychain items survive');
  assert.notEqual(keychain[0].ref, keychain[1].ref, 'service disambiguates the reference');
  assert.equal(new Set(result.candidates.map((candidate) => candidate.ref)).size, result.candidates.length,
    'every candidate has a unique ref');
  assert.deepEqual(keychain.map((candidate) => candidate.service).sort(), ['github.com', 'trained-agent-github-token']);
});

test('a genuinely duplicated identity collapses to one candidate instead of colliding', async () => {
  const result = await discoverCredentialSources({
    platform: 'darwin', home: '/nonexistent', chromeExists: () => false,
    runCommand: async () => ({ ok: false, stdout: '' }),
    listKeychain: async () => ({ available: true, items: [
      { account: 'dup', label: 'Same Item', service: 'same-service' },
      { account: 'dup', label: 'Same Item', service: 'same-service' },
    ] }),
  });
  assert.equal(result.candidates.filter((candidate) => candidate.provider === 'keychain').length, 1);
  assert.equal(new Set(result.candidates.map((candidate) => candidate.ref)).size, result.candidates.length);
});

test('keychain candidates are classified so OS noise is separable from credentials', async () => {
  const result = await discoverCredentialSources({
    platform: 'darwin', home: '/nonexistent', chromeExists: () => false,
    runCommand: async () => ({ ok: false, stdout: '' }),
    listKeychain: async () => ({ available: true, items: [
      { account: 'kobzevvv', label: 'Trained Agent GitHub Token', service: 'github.com' },
      { account: 'Irina-5GHz', label: 'Irina-5GHz', service: 'AirPort' },
      { account: 'Local Device Identifier', label: 'BluetoothGlobal', service: 'BluetoothGlobal' },
      { account: 'Chrome', label: 'Chrome Safe Storage', service: 'Chrome Safe Storage' },
      { account: 'com.apple.wifi.analytics.tokenStore.airportd', label: 'WiFiAnalytics', service: 'WiFiAnalytics' },
      { account: 'ProtonVPN WG', label: 'ProtonVPN WireGuard config', service: 'ch.protonvpn.mac' },
      { account: 'someone', label: 'Some random item', service: 'misc' },
    ] }),
  });
  const category = Object.fromEntries(result.candidates
    .filter((candidate) => candidate.provider === 'keychain')
    .map((candidate) => [candidate.label, candidate.category]));
  assert.equal(category['Trained Agent GitHub Token'], 'credential');
  assert.equal(category['Irina-5GHz'], 'wifi');
  assert.equal(category['BluetoothGlobal'], 'bluetooth');
  assert.equal(category['Chrome Safe Storage'], 'browser');
  assert.equal(category['WiFiAnalytics'], 'wifi');
  assert.equal(category['ProtonVPN WireGuard config'], 'vpn');
  assert.equal(category['Some random item'], 'other');
});
