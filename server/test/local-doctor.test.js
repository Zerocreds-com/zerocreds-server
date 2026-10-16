'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { diagnoseLocalSetup, inspectCatalog, inspectHelper, runHelperHealth } = require('../src/local-doctor');

function executable(file, body) {
  fs.writeFileSync(file, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
}

test('doctor reports local Keychain and catalog readiness without exposing catalog values', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-doctor-'));
  const helper = path.join(dir, 'keychain-helper');
  const catalogFile = path.join(dir, 'connections.json');
  const rawSecret = 'doctor-test-secret-must-never-escape';
  executable(helper, `printf '{"status":"accessible"}'`);
  fs.writeFileSync(catalogFile, JSON.stringify([{ provider: 'deepgram', account_alias: 'work', state: 'active', token: rawSecret }]), { mode: 0o600 });
  try {
    assert.equal(inspectHelper(helper), 'ready');
    assert.deepEqual(await runHelperHealth(helper), 'accessible');
    assert.deepEqual(inspectCatalog(catalogFile), { status: 'ready', connection_count: 1, active_count: 1 });
    const report = await diagnoseLocalSetup({
      helperPath: helper,
      catalogFile,
      destinations: { 'mac-keychain': { type: 'macos_keychain' } },
      defaultDestination: 'mac-keychain',
      version: 'test', commit: 'abcdef123456',
    });
    assert.equal(report.overall, 'ok');
    assert.equal(report.credential_values_read, false);
    assert.equal(report.credential_values_returned, false);
    assert.ok(!JSON.stringify(report).includes(rawSecret));
    assert.ok(!JSON.stringify(report).includes(catalogFile));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('doctor gives a repair action for a locked Keychain and malformed catalog', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-doctor-locked-'));
  const helper = path.join(dir, 'keychain-helper');
  const catalogFile = path.join(dir, 'connections.json');
  executable(helper, `printf '{"status":"locked"}'\nexit 4`);
  fs.writeFileSync(catalogFile, '{broken', { mode: 0o600 });
  try {
    const report = await diagnoseLocalSetup({ helperPath: helper, catalogFile,
      destinations: { 'mac-keychain': { type: 'macos_keychain' } }, defaultDestination: 'mac-keychain',
      version: 'test', commit: 'abcdef123456' });
    assert.equal(report.overall, 'needs_attention');
    assert.equal(report.checks.find(check => check.name === 'macos_keychain').status, 'warning');
    assert.match(report.checks.find(check => check.name === 'macos_keychain').action, /Unlock/);
    assert.equal(report.checks.find(check => check.name === 'local_catalog').status, 'error');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
