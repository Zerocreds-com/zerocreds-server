'use strict';

const fs = require('node:fs');
const { spawn } = require('node:child_process');

function runHelperHealth(helper, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let stdout = '';
    let settled = false;
    let timer;
    const finish = (status) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(status);
    };
    let child;
    try { child = spawn(helper, ['health'], { stdio: ['ignore', 'pipe', 'ignore'] }); }
    catch { return finish('unavailable'); }
    timer = setTimeout(() => { child.kill('SIGKILL'); finish('timeout'); }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      if (stdout.length + chunk.length > 2048) { child.kill('SIGKILL'); finish('invalid_response'); return; }
      stdout += chunk.toString('utf8');
    });
    child.once('error', () => finish('unavailable'));
    child.once('close', (code) => {
      let body;
      try { body = JSON.parse(stdout); } catch { return finish(code === 4 ? 'locked' : 'unavailable'); }
      if (body.status === 'accessible' && code === 0) return finish('accessible');
      if (body.status === 'locked' || code === 4) return finish('locked');
      finish('unavailable');
    });
  });
}

function inspectHelper(helperPath) {
  try {
    const fd = fs.openSync(helperPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || !(stat.mode & 0o111)
          || (process.getuid && stat.uid !== process.getuid()) || (stat.mode & 0o077)) return 'unsafe';
      return 'ready';
    } finally { fs.closeSync(fd); }
  } catch (error) { return error.code === 'ENOENT' ? 'missing' : 'unavailable'; }
}

function inspectCatalog(catalogFile) {
  try {
    const fd = fs.openSync(catalogFile, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid()) || stat.size > 5 * 1024 * 1024) {
        return { status: 'unsafe', connection_count: null };
      }
      const entries = JSON.parse(fs.readFileSync(fd, 'utf8'));
      if (!Array.isArray(entries) || entries.some((item) => !item || typeof item !== 'object' || Array.isArray(item))) {
        return { status: 'invalid', connection_count: null };
      }
      return { status: 'ready', connection_count: entries.length,
        active_count: entries.filter((item) => item.state === 'active').length };
    } finally { fs.closeSync(fd); }
  } catch (error) {
    return error.code === 'ENOENT' ? { status: 'empty', connection_count: 0, active_count: 0 }
      : { status: 'unavailable', connection_count: null };
  }
}

async function diagnoseLocalSetup(options) {
  const platform = options.platform || process.platform;
  const checks = [];
  const add = (name, status, detail, action = undefined) => checks.push({ name, status, detail, ...(action ? { action } : {}) });
  add('mcp_to_local_server', 'ok', 'This authenticated MCP request reached the local ZeroCreds server.');
  add('server', 'ok', `ZeroCreds ${options.version} (${options.commit}).`);

  const helperStatus = inspectHelper(options.helperPath);
  add('keychain_helper', helperStatus === 'ready' ? 'ok' : 'error',
    helperStatus === 'ready' ? 'Private Keychain helper is installed.' : `Keychain helper status: ${helperStatus}.`,
    helperStatus === 'ready' ? undefined : 'Run scripts/setup-local-mac.sh to compile and install the helper.');
  const keychainStatus = helperStatus === 'ready' && platform === 'darwin'
    ? await runHelperHealth(options.helperPath) : platform === 'darwin' ? 'unavailable' : 'unsupported_platform';
  add('macos_keychain', keychainStatus === 'accessible' ? 'ok' : keychainStatus === 'locked' ? 'warning' : 'error',
    keychainStatus === 'accessible' ? 'Login Keychain answered a metadata-only health query.'
      : keychainStatus === 'locked' ? 'Login Keychain is locked or requires user interaction.'
        : `Keychain health status: ${keychainStatus}.`,
    keychainStatus === 'locked' ? 'Unlock the macOS login Keychain, then rerun zerocreds_doctor.'
      : keychainStatus === 'accessible' ? undefined : 'Check macOS Keychain access and rerun scripts/setup-local-mac.sh.');

  const destination = options.destinations?.[options.defaultDestination];
  const destinationReady = destination && ['macos_keychain', 'os_keychain'].includes(destination.type);
  add('default_destination', destinationReady ? 'ok' : 'error', destinationReady
    ? 'Configured default destination is an OS Keychain; this check does not read any credential.'
    : 'Configured default destination is missing or is not an OS Keychain.',
  destinationReady ? undefined : 'Check ZEROCREDS_DEFAULT_DESTINATION and the local destinations configuration.');

  const catalog = inspectCatalog(options.catalogFile);
  add('local_catalog', ['ready', 'empty'].includes(catalog.status) ? 'ok' : 'error',
    catalog.status === 'empty' ? 'Catalog is not created yet; this is normal before the first saved credential.'
      : catalog.status === 'ready' ? `Private catalog is readable (${catalog.connection_count} connection(s), ${catalog.active_count} active).`
        : `Catalog status: ${catalog.status}.`,
    ['ready', 'empty'].includes(catalog.status) ? undefined : 'Check permissions and JSON integrity of the local connections catalog.');

  const overall = checks.some((check) => check.status === 'error') ? 'needs_attention'
    : checks.some((check) => check.status === 'warning') ? 'warning' : 'ok';
  return {
    diagnostic_id: `zcdiag_${require('node:crypto').randomBytes(8).toString('hex')}`,
    checked_at: new Date().toISOString(),
    overall,
    checks,
    catalog: { connection_count: catalog.connection_count, active_count: catalog.active_count },
    next: overall === 'ok' ? 'Run zerocreds_connection_verify for the specific provider/account to test credential validity and permissions.'
      : 'Fix the checks marked warning/error, then rerun zerocreds_doctor.',
    credential_values_read: false,
    credential_values_returned: false,
  };
}

module.exports = { diagnoseLocalSetup, inspectCatalog, inspectHelper, runHelperHealth };
