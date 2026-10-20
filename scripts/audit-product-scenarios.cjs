'use strict';
// Read-only product audit against isolated temporary servers. Invented values only.
// Prints observed behavior; this is an audit probe, not a regression-test oracle.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { startServer, request } = require('../server/test/helpers');

(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-product-audit-'));
  const catalog = path.join(root, 'catalog.json');
  let unblock, entered;
  const started = new Promise(resolve => { entered = resolve; });
  const blocked = new Promise(resolve => { unblock = resolve; });
  let blockNext = false;
  const ctx = await startServer({ namedDestinations: {
    'audit-sink': { type: 'http_post', url: 'http://127.0.0.1:1/not-contacted' },
  }, app: {
    localCredentialDiscovery: async () => ({ sources: [], candidates: Array.from({ length: 201 }, (_, i) => ({
      ref: `disc_${i.toString(16).padStart(24, '0')}`, source_id: 'macos_keychain', category: 'credential',
      provider: 'keychain', account: `synthetic-${i}`, label: `Synthetic ${i}`,
    })) }),
    localMode: true, baseUrl: 'http://localhost', localCatalogFile: catalog,
    localCredentialReader: async () => ({ custom_pat: 'invented-audit-value' }),
    localCredentialVerifier: async () => {
      if (blockNext) { blockNext = false; entered(); await blocked; }
      return { status: 'valid' };
    },
  } });
  const headers = { Host: 'localhost', Authorization: `Bearer ${ctx.adminToken}` };
  const call = (method, route, body) => request(ctx.port, method, route, body, headers);
  const firstEvent = route => new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: ctx.port, path: route,
      headers }, res => res.once('data', chunk => {
        resolve(String(chunk).match(/^event: (\w+)/m)?.[1]);
        req.destroy();
      }));
    req.once('error', reject);
    req.end();
  });
  const read = () => JSON.parse(fs.readFileSync(catalog, 'utf8'));
  const seed = () => fs.writeFileSync(catalog, JSON.stringify([{
    connection_id: 'audit-connection', provider: 'github', account_alias: 'work',
    state: 'active', storage: 'synthetic:unread', token_field: 'custom_pat',
    verification_status: 'unknown', created_at: new Date().toISOString(),
  }]));
  const report = (id, observed) => console.log(JSON.stringify({ id, ...observed }));
  const create = extra => call('POST', '/api/session/create', {
    title: 'Synthetic audit', service: 'github', uid: 'work',
    fields: [{ name: 'custom_pat', label: 'Invented value' }],
    destination: { type: 'local_file', uid: 'audit', filename: 'invented' }, ...extra,
  });
  const submit = token => call('POST', `/f/${token}`, { t: token, fields: { custom_pat: 'invented-audit-value' } });
  try {
    // A required field has no route; creation should reject it.
    const missing = await create({ destination: undefined, destinations_by_level: {
      secret: { type: 'local_file', uid: 'unrouted', filename: 'unused' },
    } });
    const discarded = missing.body.token ? await submit(missing.body.token) : null;
    const discardedStatus = missing.body.token ? await call('GET', `/api/session/${missing.body.token}/status`) : null;
    report('F01', { create_status: missing.status, submit_status: discarded?.status,
      form_status: discardedStatus?.body.status, destination_written: fs.existsSync(path.join(ctx.tokensDir, 'unrouted', 'unused')) });

    seed();
    const rotation = await create({});
    await submit(rotation.body.token);
    report('F02', { connection_id_preserved: read()[0].connection_id === 'audit-connection',
      token_alias_preserved: read()[0].token_field === 'custom_pat' });

    seed();
    const casing = await create({ service: 'GitHub', uid: 'Work' });
    await submit(casing.body.token);
    report('F03', { catalog_entries: read().length, aliases: read().map(e => `${e.provider}/${e.account_alias}`) });

    seed();
    // A slow verification captures the old whole catalog, then overwrites a newer save.
    blockNext = true;
    const slow = call('POST', '/api/local/connections/verify', { provider: 'github', account_alias: 'work' });
    await started;
    await call('POST', '/api/local/connections/verify', { provider: 'github', account_alias: 'work', token_field: 'replacement', save_token_field: true });
    const before = read()[0].token_field;
    unblock();
    const slowResult = await slow;
    report('F04', { slow_status: slowResult.status, alias_after_save: before,
      alias_after_older_check_completes: read()[0].token_field });

    const interrupted = await create({});
    const token = interrupted.body.token;
    const claimed = path.join(ctx.pendingDir, `${token}.claimed`);
    fs.renameSync(path.join(ctx.pendingDir, `${token}.json`), claimed);
    const inFlightStatus = await call('GET', `/api/session/${token}/status`);
    const inFlightEvent = await firstEvent(`/api/session/${token}/events`);
    report('F09', { status_during_submit: inFlightStatus.body.status,
      event_during_submit: inFlightEvent });
    const old = new Date(Date.now() - 2 * 86400000);
    fs.utimesSync(claimed, old, old);
    ctx.server.sweepPending();
    const status = await call('GET', `/api/session/${token}/status`);
    report('F05', { form_status_after_stale_claim: status.body.status,
      resumable_pending_exists: fs.existsSync(path.join(ctx.pendingDir, `${token}.json`)) });

    seed();
    const listed = await call('GET', '/api/local/connections?provider=github');
    report('F06', { saved_alias_visible_in_connection_list: Object.hasOwn(listed.body.connections[0], 'token_field') });

    const integrator = await call('POST', '/admin/integrators/create', { id: 'audit-agent', name: 'Synthetic audit agent' });
    const integratorHeaders = { ...headers, Authorization: `Bearer ${integrator.body.token}` };
    const spec = { title: 'First schema', uid: 'idempotency-probe', service: 'github',
      fields: [{ name: 'old_field', label: 'Old field' }], destination: 'audit-sink', test_destination: false };
    const first = await request(ctx.port, 'POST', '/api/session/create', spec, integratorHeaders);
    const second = await request(ctx.port, 'POST', '/api/session/create', {
      ...spec, title: 'Corrected schema', fields: [{ name: 'token', label: 'Corrected field' }],
    }, integratorHeaders);
    report('F07', { first_status: first.status, second_status: second.status,
      same_form: first.body.token === second.body.token, reused: second.body.reused,
      actual_field: JSON.parse(fs.readFileSync(path.join(ctx.pendingDir, `${second.body.token}.json`))).fields[0].name });

    const preview = await call('POST', '/api/local/discovery/preview', {});
    report('F08', { candidate_count: 201, preview_status: preview.status,
      preview_id_available: Boolean(preview.body.preview_id), error: preview.body.error });
  } finally {
    unblock();
    await ctx.stop();
    fs.rmSync(root, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
