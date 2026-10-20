'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const { createApp } = require('../src/server');

async function freePort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

function call(port, method, route, body, token) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? '' : JSON.stringify(body);
    const req = http.request({ hostname: '127.0.0.1', port, path: route, method, headers: {
      ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    } }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(raw) }));
    });
    req.once('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function withLocalServer(run, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-local-catalog-'));
  const port = await freePort();
  const token = 'local-test-token-' + 'x'.repeat(40);
  const catalogFile = path.join(root, 'connections.json');
  const discoveryCatalogFile = path.join(root, 'discovery-catalog.json');
  const provider = options.provider || 'github';
  const accountAlias = options.accountAlias || 'work';
  fs.writeFileSync(catalogFile, JSON.stringify([{
    connection_id: 'connection-1', provider, account_alias: accountAlias,
    storage: 'keychain:github-work', state: 'active', credential_expires_at: null,
    verification_status: 'unknown', created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
  }]));
  const app = createApp({
    adminToken: token,
    localMode: true,
    baseUrl: `http://127.0.0.1:${port}`,
    localCatalogFile: catalogFile,
    localDiscoveryCatalogFile: discoveryCatalogFile,
    localCredentialDiscovery: options.discovery || (async () => ({ sources: [{ source_id: 'github_cli', status: 'found', candidate_count: 1 }], candidates: [{
      ref: 'disc_0123456789abcdef01234567', provider: 'github', source_id: 'github_cli', account: 'work-user',
      label: 'github.com', scopes: ['repo'],
    }] })),
    localProviderPolicies: { github: {
      login_url: 'https://github.com/login', auth_url: 'https://github.com/settings/profile',
      username_selector: '#login_field', password_selector: '#password',
      submit_selector: 'button[type=submit]', success_selector: '#signed-in',
      username_field: 'username', password_field: 'password',
    } },
    pendingDir: path.join(root, 'pending'),
    tokensDir: path.join(root, 'tokens'),
    destinationsFile: path.join(root, 'destinations.json'),
    integratorsFile: path.join(root, 'integrators.json'),
    signingKeyFile: path.join(root, 'signing-key.pem'),
    localCredentialReader: async () => ({ token: 'must-never-escape-test-secret', username: 'test-user',
      password: 'synthetic-login-password', api_token: 'must-not-be-included' }),
    localCredentialVerifier: options.verifier || (async () => ({ status: 'valid', identity: { id: '123', login: 'octocat' },
      permissions: ['repo'], permission_evidence: 'provider_verified' })),
  });
  await new Promise((resolve, reject) => { app.once('error', reject); app.listen(port, '127.0.0.1', resolve); });
  try { await run({ port, token, catalogFile, discoveryCatalogFile }); }
  finally {
    await new Promise((resolve) => app.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('local Deepgram verification returns and persists grant diagnostics without the grant token', async () => {
  const accessToken = 'temporary-grant-must-not-escape';
  await withLocalServer(async ({ port, token }) => {
    const input = { provider: 'deepgram', account_alias: 'chemistry-gpt-deepgram' };
    const denied = await call(port, 'POST', '/api/local/connections/verify', input);
    assert.equal(denied.status, 401);
    const verified = await call(port, 'POST', '/api/local/connections/verify', input, token);
    assert.equal(verified.status, 200);
    assert.equal(verified.body.verification, 'valid');
    assert.deepEqual(verified.body.identity, { grant_capable: true });
    assert.deepEqual(verified.body.diagnostic, { upstream_status: 200, grant_expires_in: 30 });
    assert.deepEqual(verified.body.credential_hint, {
      character_count: 'must-never-escape-test-secret'.length,
      masked: 'mus…cret',
    });
    assert.ok(!JSON.stringify(verified.body).includes(accessToken));
    assert.ok(!JSON.stringify(verified.body).includes('must-never-escape-test-secret'));

    const list = await call(port, 'GET', '/api/local/connections', undefined, token);
    assert.equal(list.status, 200);
    assert.equal(list.body.connections[0].verification_status, 'valid');
    assert.deepEqual(list.body.connections[0].verification_diagnostic, { upstream_status: 200, grant_expires_in: 30 });
    assert.ok(!JSON.stringify(list.body.connections[0]).includes('credential_hint'), 'masked fragments are never persisted');
    assert.ok(list.body.connections[0].last_verified_at);
  }, {
    provider: 'deepgram',
    accountAlias: 'chemistry-gpt-deepgram',
    verifier: async () => ({ status: 'valid', identity: { grant_capable: true }, permissions: [], access_token: accessToken,
      permission_evidence: 'provider_verified', diagnostic: { upstream_status: 200, grant_expires_in: 30 } }),
  });
});

test('local broker grants are connection-bound, short-lived, one-use and return only approved fields', async () => {
  await withLocalServer(async ({ port, token, catalogFile }) => {
    const denied = await call(port, 'POST', '/api/local/broker/grants', {
      provider: 'github', account_alias: 'work', run_id: '12345678-1234-1234-1234-123456789abc',
    });
    assert.equal(denied.status, 401);
    const issued = await call(port, 'POST', '/api/local/broker/grants', {
      provider: 'github', account_alias: 'work', run_id: '12345678-1234-1234-1234-123456789abc',
    }, token);
    assert.equal(issued.status, 200);
    assert.equal(issued.body.approved_origin, 'https://github.com');
    assert.equal(issued.body.login_url, 'https://github.com/login');
    assert.equal(issued.body.success_selector, '#signed-in');
    assert.ok(!JSON.stringify(issued.body).includes('must-never-escape-test-secret'));

    const redeemed = await call(port, 'POST', '/api/local/broker/redeem', { grant: issued.body.grant });
    assert.equal(redeemed.status, 200);
    assert.deepEqual(redeemed.body, { username: 'test-user', password: 'synthetic-login-password' });
    assert.ok(!JSON.stringify(redeemed.body).includes('must-not-be-included'));
    const replay = await call(port, 'POST', '/api/local/broker/redeem', { grant: issued.body.grant });
    assert.equal(replay.status, 401);
    const catalog = JSON.parse(fs.readFileSync(catalogFile, 'utf8'));
    assert.equal(catalog[0].last_use.operation, 'browser_login');
    assert.equal(catalog[0].last_use.run_id, '12345678-1234-1234-1234-123456789abc');
    assert.equal(catalog[0].last_use.outcome, 'delivered');
  });
});


test('discovery is previewed before explicit selection and persists metadata only', async () => {
  await withLocalServer(async ({ port, token, discoveryCatalogFile }) => {
    const unauthenticated = await call(port, 'GET', '/api/local/discovery/sources');
    assert.equal(unauthenticated.status, 401);
    const sources = await call(port, 'GET', '/api/local/discovery/sources', undefined, token);
    assert.equal(sources.body.catalog_changes, 0);
    const preview = await call(port, 'POST', '/api/local/discovery/preview', {}, token);
    assert.equal(preview.status, 200);
    assert.equal(preview.body.requires_user_confirmation_to_catalog, true);
    assert.equal(preview.body.candidates.length, 1);
    const previewLifetime = Date.parse(preview.body.expires_at) - Date.now();
    assert.ok(previewLifetime > 5 * 60 * 60 * 1000 && previewLifetime <= 6 * 60 * 60 * 1000);
    assert.equal(fs.existsSync(discoveryCatalogFile), false);
    const searchedPreview = await call(port, 'GET', `/api/local/discovery/search?q=github&preview_id=${preview.body.preview_id}`, undefined, token);
    assert.equal(searchedPreview.body.scope, 'preview');
    const catalogued = await call(port, 'POST', '/api/local/discovery/catalog', {
      preview_id: preview.body.preview_id, refs: ['disc_0123456789abcdef01234567'],
    }, token);
    assert.equal(catalogued.status, 200);
    assert.equal(catalogued.body.catalogued, 1);
    const search = await call(port, 'GET', '/api/local/discovery/search?q=github', undefined, token);
    assert.equal(search.body.results[0].account, 'work-user');
    assert.equal(fs.statSync(discoveryCatalogFile).mode & 0o777, 0o600);
    assert.ok(!fs.readFileSync(discoveryCatalogFile, 'utf8').includes('secret_value_collected'));
  });
});

test('discovery catalog endpoint accepts only references from its unexpired preview', async () => {
  await withLocalServer(async ({ port, token }) => {
    const invalid = await call(port, 'POST', '/api/local/discovery/catalog', {
      preview_id: 'f'.repeat(36), refs: ['disc_0123456789abcdef01234567'],
    }, token);
    assert.equal(invalid.status, 410);
  });
});

test('catalog accepts a ref that two candidates share and reports only unknown refs', async () => {
  const shared = {
    ref: 'disc_aaaaaaaaaaaaaaaaaaaaaaaa', provider: 'keychain', source_id: 'macos_keychain',
    account: 'kobzevvv', label: 'Trained Agent GitHub Token', scopes: [],
    category: 'credential', service: 'github.com',
  };
  await withLocalServer(async ({ port, token }) => {
    const preview = await call(port, 'POST', '/api/local/discovery/preview', {}, token);
    assert.equal(preview.status, 200);
    // The exact call that used to 400 forever: two candidates, one ref.
    const catalogued = await call(port, 'POST', '/api/local/discovery/catalog', {
      preview_id: preview.body.preview_id, refs: [shared.ref, shared.ref],
    }, token);
    assert.equal(catalogued.status, 200);
    assert.equal(catalogued.body.catalogued, 1);
    assert.equal(catalogued.body.already_present, 0);

    const secondPreview = await call(port, 'POST', '/api/local/discovery/preview', {}, token);
    const unknown = await call(port, 'POST', '/api/local/discovery/catalog', {
      preview_id: secondPreview.body.preview_id, refs: ['disc_bbbbbbbbbbbbbbbbbbbbbbbb'],
    }, token);
    assert.equal(unknown.status, 400);
    assert.match(unknown.body.error, /not in this preview/);
  }, { discovery: async () => ({ sources: [{ source_id: 'macos_keychain', status: 'found', candidate_count: 2 }], candidates: [shared, { ...shared }] }) });
});

test('preview reports category counts and narrows without hiding anything by default', async () => {
  const candidates = [
    { ref: 'disc_111111111111111111111111', provider: 'keychain', source_id: 'macos_keychain', account: 'a', label: 'Token A', scopes: [], category: 'credential' },
    { ref: 'disc_222222222222222222222222', provider: 'keychain', source_id: 'macos_keychain', account: 'b', label: 'AirPort', scopes: [], category: 'wifi' },
    { ref: 'disc_333333333333333333333333', provider: 'keychain', source_id: 'macos_keychain', account: 'c', label: 'BluetoothGlobal', scopes: [], category: 'bluetooth' },
  ];
  await withLocalServer(async ({ port, token }) => {
    const all = await call(port, 'POST', '/api/local/discovery/preview', {}, token);
    assert.equal(all.body.candidate_count, 3);
    assert.deepEqual(all.body.category_counts, { credential: 1, wifi: 1, bluetooth: 1 });

    const narrowed = await call(port, 'POST', '/api/local/discovery/preview', { categories: ['credential'] }, token);
    assert.equal(narrowed.status, 200);
    assert.equal(narrowed.body.candidate_count, 1);
    assert.equal(narrowed.body.filtered_out, 2);
    assert.deepEqual(narrowed.body.category_counts, { credential: 1, wifi: 1, bluetooth: 1 },
      'counts still describe the full inventory the filter was applied to');

    const invalid = await call(port, 'POST', '/api/local/discovery/preview', { categories: ['nope'] }, token);
    assert.equal(invalid.status, 400);
  }, { discovery: async () => ({ sources: [{ source_id: 'macos_keychain', status: 'found', candidate_count: 3 }], candidates }) });
});

test('cataloguing drops legacy keychain entries that predate service-qualified refs', async () => {
  const candidate = {
    ref: 'disc_444444444444444444444444', provider: 'keychain', source_id: 'macos_keychain',
    account: 'kobzevvv', label: 'Trained Agent GitHub Token', scopes: [], category: 'credential', service: 'github.com',
  };
  await withLocalServer(async ({ port, token, discoveryCatalogFile }) => {
    fs.writeFileSync(discoveryCatalogFile, JSON.stringify([{
      ref: 'disc_legacy', provider: 'keychain', source_id: 'macos_keychain',
      account: 'kobzevvv', label: 'Trained Agent GitHub Token', scopes: [],
    }]), { mode: 0o600 });
    const preview = await call(port, 'POST', '/api/local/discovery/preview', {}, token);
    const catalogued = await call(port, 'POST', '/api/local/discovery/catalog', {
      preview_id: preview.body.preview_id, refs: [candidate.ref],
    }, token);
    assert.equal(catalogued.status, 200);
    assert.equal(catalogued.body.migrated_legacy_entries, 1);
    const stored = JSON.parse(fs.readFileSync(discoveryCatalogFile, 'utf8'));
    assert.deepEqual(stored.map((record) => record.ref), [candidate.ref]);
    assert.equal(stored[0].service, 'github.com');
    assert.equal(stored[0].category, 'credential');
  }, { discovery: async () => ({ sources: [{ source_id: 'macos_keychain', status: 'found', candidate_count: 1 }], candidates: [candidate] }) });
});

test('verification forwards explicit field selection, validates it and explains recovery', async () => {
  let calls = 0;
  await withLocalServer(async ({ port, token }) => {
    const input = { provider: 'github', account_alias: 'work', token_field: 'github_pat_admin' };
    const result = await call(port, 'POST', '/api/local/connections/verify', input, token);
    assert.equal(result.status, 200);
    assert.equal(result.body.verification, 'credential_field_missing');
    assert.match(result.body.next_step, /token_field/);
    assert.ok(!JSON.stringify(result.body).includes('must-never-escape-test-secret'));
    for (const field of ['', '../token', 42, null, 'x'.repeat(65)]) {
      const invalid = await call(port, 'POST', '/api/local/connections/verify', { ...input, token_field: field }, token);
      assert.equal(invalid.status, 400);
    }
    assert.equal(calls, 1);
  }, { verifier: async (provider, fields, fetchImpl, options) => {
    calls++;
    assert.equal(provider, 'github');
    assert.deepEqual(options, { tokenField: 'github_pat_admin', account_id: undefined });
    return { status: 'credential_field_missing' };
  } });
});

test('Cloudflare verification accepts only a Cloudflare account ID and forwards it', async () => {
  const accountId = 'a'.repeat(32);
  await withLocalServer(async ({ port, token }) => {
    const input = { provider: 'cloudflare', account_alias: 'work', account_id: accountId };
    const result = await call(port, 'POST', '/api/local/connections/verify', input, token);
    assert.equal(result.status, 200);
    assert.equal(result.body.verification, 'unknown');
    assert.equal((await call(port, 'POST', '/api/local/connections/verify',
      { ...input, account_id: 'not-an-account' }, token)).status, 400);
    assert.equal((await call(port, 'POST', '/api/local/connections/verify',
      { ...input, provider: 'github' }, token)).status, 400);
  }, { provider: 'cloudflare', verifier: async (provider, fields, fetchImpl, options) => {
    assert.equal(provider, 'cloudflare');
    assert.equal(options.account_id, accountId);
    return { status: 'unknown' };
  } });
});

test('saved token alias survives later checks; temporary overrides and failed saves preserve it', async () => {
  const selected = [];
  await withLocalServer(async ({ port, token, catalogFile }) => {
    const input = { provider: 'github', account_alias: 'work' };
    const verify = (extra) => call(port, 'POST', '/api/local/connections/verify', { ...input, ...extra }, token);
    assert.equal((await verify({ save_token_field: true })).status, 400);
    assert.equal((await verify({ save_token_field: 'yes', token_field: 'token' })).status, 400);
    const saved = await verify({ token_field: 'custom_pat', save_token_field: true });
    assert.equal(saved.body.token_field_saved, true);
    assert.equal(JSON.parse(fs.readFileSync(catalogFile))[0].token_field, 'custom_pat');
    await verify({});
    await verify({ token_field: 'temporary' });
    await verify({});
    const failed = await verify({ token_field: 'invalid', save_token_field: true });
    assert.equal(failed.body.token_field_saved, false);
    await verify({});
    const replaced = await verify({ token_field: 'replacement', save_token_field: true });
    assert.equal(replaced.body.token_field_saved, true);
    await verify({});
    assert.deepEqual(selected, ['custom_pat', 'custom_pat', 'temporary', 'custom_pat', 'invalid', 'custom_pat', 'replacement', 'replacement']);
    const persisted = fs.readFileSync(catalogFile, 'utf8');
    assert.ok(!persisted.includes('must-never-escape-test-secret'));
    assert.equal(JSON.parse(persisted)[0].token_field, 'replacement');
  }, { verifier: async (provider, fields, fetchImpl, { tokenField }) => {
    selected.push(tokenField);
    return { status: tokenField === 'invalid' ? 'invalid' : 'valid' };
  } });
});

test('a slow verification cannot overwrite a newer saved field alias', async () => {
  let releaseSlow;
  let enteredSlow;
  const slowEntered = new Promise(resolve => { enteredSlow = resolve; });
  const slowMayFinish = new Promise(resolve => { releaseSlow = resolve; });
  let calls = 0;
  await withLocalServer(async ({ port, token, catalogFile }) => {
    const input = { provider: 'github', account_alias: 'work' };
    const slow = call(port, 'POST', '/api/local/connections/verify', input, token);
    await slowEntered;
    const saved = await call(port, 'POST', '/api/local/connections/verify', {
      ...input, token_field: 'replacement', save_token_field: true,
    }, token);
    assert.equal(saved.body.token_field_saved, true);
    releaseSlow();
    const stale = await slow;
    assert.equal(stale.status, 409);
    assert.equal(stale.body.verification, 'stale');
    assert.equal(JSON.parse(fs.readFileSync(catalogFile, 'utf8'))[0].token_field, 'replacement');
  }, { verifier: async () => {
    if (++calls === 1) { enteredSlow(); await slowMayFinish; }
    return { status: 'valid' };
  } });
});
