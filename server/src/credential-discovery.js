'use strict';

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

const MAX_OUTPUT = 1024 * 1024;
const MAX_ITEMS = 2000;
const COMMAND_TIMEOUT_MS = 5000;

function run(command, args, options = {}, timeoutMs = COMMAND_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'ignore'], ...options });
    let stdout = '';
    let size = 0;
    let settled = false;
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish({ ok: false, stdout: '' });
    }, timeoutMs);
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    child.stdout.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > MAX_OUTPUT) { child.kill('SIGKILL'); finish({ ok: false, stdout: '' }); return; }
      stdout += chunk.toString('utf8');
    });
    child.on('error', () => finish({ ok: false, stdout: '' }));
    child.on('close', (code) => finish({ ok: code === 0 && size <= MAX_OUTPUT, stdout }));
  });
}

function source(id, status, count = 0, reason = undefined) {
  return { source_id: id, status, candidate_count: count, ...(reason ? { reason } : {}) };
}

function makeCandidate(provider, sourceId, account, label, scopes = []) {
  const safeAccount = String(account || 'default').slice(0, 128);
  const ref = crypto.createHash('sha256').update(`${sourceId}\0${provider}\0${safeAccount}\0${label || ''}`).digest('hex').slice(0, 24);
  return {
    ref: `disc_${ref}`, provider, source_id: sourceId,
    account: safeAccount, label: String(label || provider).slice(0, 128),
    scopes: [...new Set(scopes.filter((x) => typeof x === 'string').map((x) => x.slice(0, 80)))].slice(0, 100),
  };
}

async function scanGithub(runCommand = run) {
  const result = await runCommand('gh', ['auth', 'status', '--json', 'hosts']);
  if (!result.ok) return { source: source('github_cli', 'unavailable', 0, 'not_installed_or_not_authenticated'), candidates: [] };
  let parsed;
  try { parsed = JSON.parse(result.stdout); } catch { return { source: source('github_cli', 'unavailable', 0, 'status_unrecognized'), candidates: [] }; }
  const candidates = [];
  for (const [host, accounts] of Object.entries(parsed.hosts || {})) {
    if (!Array.isArray(accounts)) continue;
    for (const entry of accounts) {
      if (!entry || typeof entry.login !== 'string') continue;
      const state = typeof entry.state === 'string' ? entry.state : entry.state?.name;
      const scopes = Array.isArray(entry.scopes) ? entry.scopes
        : typeof entry.scopes === 'string' ? entry.scopes.split(/,\s*/) : [];
      candidates.push(makeCandidate('github', 'github_cli', entry.login, host, scopes));
      candidates.at(-1).active = entry.active === true;
      candidates.at(-1).authentication_status = state === 'success' ? 'authenticated' : 'unknown';
    }
  }
  return { source: source('github_cli', candidates.length ? 'found' : 'empty', candidates.length), candidates: candidates.slice(0, MAX_ITEMS) };
}

async function scanCloudflare(runCommand = run) {
  const result = await runCommand('wrangler', ['whoami', '--json']);
  if (!result.ok) return { source: source('cloudflare_cli', 'unavailable', 0, 'not_installed_or_not_authenticated'), candidates: [] };
  let parsed;
  try { parsed = JSON.parse(result.stdout); } catch { return { source: source('cloudflare_cli', 'unavailable', 0, 'status_unrecognized'), candidates: [] }; }
  const entries = [parsed.user, ...(Array.isArray(parsed.accounts) ? parsed.accounts : [])].filter((x) => x && typeof x === 'object');
  const candidates = entries.map((entry, i) => makeCandidate('cloudflare', 'cloudflare_cli',
    entry.email || entry.name || entry.id || `account-${i + 1}`, entry.name || 'Cloudflare account'));
  return { source: source('cloudflare_cli', candidates.length ? 'found' : 'empty', candidates.length), candidates: candidates.slice(0, MAX_ITEMS) };
}

async function scanGcloud(runCommand = run) {
  const result = await runCommand('gcloud', ['auth', 'list', '--format=json']);
  if (!result.ok) return { source: source('gcloud_cli', 'unavailable', 0, 'not_installed_or_not_authenticated'), candidates: [] };
  let parsed;
  try { parsed = JSON.parse(result.stdout); } catch { return { source: source('gcloud_cli', 'unavailable', 0, 'status_unrecognized'), candidates: [] }; }
  const candidates = (Array.isArray(parsed) ? parsed : []).filter((x) => typeof x.account === 'string')
    .map((x) => makeCandidate('google_cloud', 'gcloud_cli', x.account, x.status === 'ACTIVE' ? 'Active Google Cloud account' : 'Google Cloud account'));
  return { source: source('gcloud_cli', candidates.length ? 'found' : 'empty', candidates.length), candidates: candidates.slice(0, MAX_ITEMS) };
}

async function listKeychain(helperPath) {
  const result = await run(helperPath, ['list']);
  if (!result.ok) return { available: false, reason: 'keychain_metadata_unavailable', items: [] };
  try {
    const parsed = JSON.parse(result.stdout);
    return { available: true, items: Array.isArray(parsed) ? parsed.slice(0, MAX_ITEMS) : [] };
  } catch { return { available: false, reason: 'status_unrecognized', items: [] }; }
}

function discoverCredentialSources(options = {}) {
  const runCommand = options.runCommand || run;
  const platform = options.platform || process.platform;
  const home = options.home || os.homedir();
  const helperPath = options.keychainHelper || path.join(home, '.config/zerocreds/local/zerocreds-keychain');
  const keychainLister = options.listKeychain || listKeychain;
  const sources = [];
  const candidates = [];
  const tasks = [scanGithub(runCommand), scanCloudflare(runCommand), scanGcloud(runCommand)];
  return Promise.all(tasks).then(async (results) => {
    results.forEach((result) => { sources.push(result.source); candidates.push(...result.candidates); });
    if (platform === 'darwin') {
      let result;
      try { result = await keychainLister(helperPath); }
      catch { result = { available: false, reason: 'keychain_metadata_unavailable', items: [] }; }
      const found = (result.items || []).slice(0, MAX_ITEMS).filter((entry) => entry && (entry.account || entry.service || entry.label));
      for (const entry of found) candidates.push(makeCandidate('keychain', 'macos_keychain',
        entry.account || entry.server || 'unknown', entry.label || entry.service || 'Keychain item'));
      sources.push(source('macos_keychain', result.available ? (found.length ? 'found' : 'empty') : 'unavailable', found.length,
        result.available ? undefined : result.reason || 'keychain_metadata_unavailable'));
      const chrome = path.join(home, 'Library/Application Support/Google/Chrome');
      const exists = options.chromeExists ? options.chromeExists(chrome) : fs.existsSync(chrome);
      sources.push(source('chrome', exists ? 'detected_unsupported' : 'not_detected', 0,
        exists ? 'browser_credentials_are_not_read' : undefined));
    } else {
      sources.push(source('macos_keychain', 'unsupported_platform'));
      sources.push(source('chrome', 'unsupported_platform'));
    }
    return { sources, candidates: candidates.slice(0, MAX_ITEMS) };
  });
}

function searchCredentialMetadata(items, query, limit = 50) {
  const terms = String(query || '').toLowerCase().split(/[^a-z0-9@._-]+/).filter(Boolean);
  if (!terms.length) return [];
  return items.map((item) => {
    const haystack = [item.provider, item.source_id, item.account, item.label, ...(item.scopes || [])].join(' ').toLowerCase();
    const score = terms.reduce((sum, term) => sum + (haystack.includes(term) ? (String(item.provider).toLowerCase() === term ? 5 : 1) : 0), 0);
    return { ...item, search_score: score };
  }).filter((item) => item.search_score > 0).sort((a, b) => b.search_score - a.search_score).slice(0, Math.max(1, Math.min(100, limit)));
}

module.exports = { discoverCredentialSources, searchCredentialMetadata, makeCandidate, run };
