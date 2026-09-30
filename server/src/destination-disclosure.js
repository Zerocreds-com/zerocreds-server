'use strict';

// Collapsible destination disclosure ("where will your secrets go") for the
// /f/:token form.
//
// SECURITY INVARIANT — never render destination credential values into HTML:
//   - Addresses ARE shown, so the user can see where their data goes:
//     file path, http method + host/path, secret resource name, vault
//     address/path, keychain service/account.
//   - Credentials are ALWAYS masked. Header values (Authorization, x-api-key,
//     access tokens, SA keys, encryption keys) render as •••••• in the detail
//     rows and as <TOKEN> in the curl example. Known credential config fields
//     (gcp `credentials`, aws `access_key_id`/`secret_access_key`, vault
//     `token`/`secret_id`) are masked the same way. Unknown config keys of a
//     known destination type are masked too; for an unknown destination type
//     only the type name is shown and every config value is masked.
//   - {placeholders} stay visible as placeholders (they are slot names, not
//     values); literal values are masked when the key/parameter name looks
//     secret-ish OR the literal itself looks like an opaque credential
//     (long, random-ish charset). Header values are masked unconditionally.
//   - Caveat by design: the http path is part of the address the user must
//     see, so it is rendered as-is — tokens belong in headers/query, where
//     they are always masked.
//
// Pure function of the pending session: no I/O, no network calls — it cannot
// disturb the http_post preflight probe (X-ZeroCreds-Preflight), and probe
// values never reach the HTML because probes are built at request time from
// the destination config, never stored in it.

const { resolveTemplate } = require('./destinations');

const MASK = '••••••';        // shown in detail rows
const CURL_MASK = '<TOKEN>';   // shown in the curl example

// Config keys / header names / {placeholder} names / query param names that
// carry credentials.
const SECRET_NAME_RE = /token|secret|key|auth|passw|cred|bearer|sign|encrypt|private|fields_json/i;

// Destination config keys each type actually consumes (destinations.js).
// Anything else present on the destination object is shown masked.
const KNOWN_KEYS = {
  local_file: ['type', 'uid', 'filename'],
  http_post: ['type', 'url', 'headers', 'body'],
  gcp_secret_manager: ['type', 'secret', 'credentials'],
  aws_secrets_manager: ['type', 'secret_id', 'region', 'access_key_id', 'secret_access_key'],
  vault: ['type', 'address', 'path', 'token', 'role_id', 'secret_id'],
  macos_keychain: ['type', 'service', 'account'],
  windows_credential_manager: ['type', 'service', 'account'],
  os_keychain: ['type', 'service', 'account'],
};

// Same tags the form uses for per-field level chips.
const LEVEL_TAGS = { secret: 'SECRET', pii: 'PII DATA', attribute: 'CONFIG', credential: 'SESSION' };

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function isSecretName(name) {
  return SECRET_NAME_RE.test(String(name ?? ''));
}

// Opaque-credential heuristic: long, single-token, random-looking literals are
// masked even when their key name looks innocent ("note": "sk_live_…").
function looksLikeSecret(v) {
  return v.length >= 12 && /^[A-Za-z0-9_\-.+/=%]+$/.test(v);
}

// What to show for one value given the name it sits under.
function maskString(name, raw, maskStr) {
  if (isSecretName(name)) return maskStr;
  return raw.replace(/(\{[a-zA-Z0-9_]+\}|[^{}]+|\{)/g, (seg) => {
    if (/^\{[a-zA-Z0-9_]+\}$/.test(seg)) {
      return isSecretName(seg.slice(1, -1)) ? maskStr : seg;
    }
    if (seg === '{') return seg; // stray brace, keep as-is
    return looksLikeSecret(seg) ? maskStr : seg;
  });
}

// Mask every query-parameter value; names and the host/path stay visible.
function maskQueryValues(url, maskStr) {
  const q = url.indexOf('?');
  if (q === -1) return url;
  const hash = url.indexOf('#', q);
  const head = url.slice(0, q + 1);
  const query = url.slice(q + 1, hash === -1 ? url.length : hash);
  const tail = hash === -1 ? '' : url.slice(hash);
  const masked = query.split('&').map((pair) => {
    const eq = pair.indexOf('=');
    if (eq === -1) return isSecretName(pair) ? `${pair}=${maskStr}` : pair;
    const name = pair.slice(0, eq);
    let value = pair.slice(eq + 1);
    try { value = decodeURIComponent(value); } catch {}
    return `${name}=${maskString(name, value, maskStr)}`;
  }).join('&');
  return head + masked + tail;
}

function renderUrl(urlTemplate, maskStr) {
  // Placeholders (path and query) follow the same rule as everywhere else:
  // secret-ish slot names are masked, the rest stay visible as slots. Query
  // literal values are then masked by maskQueryValues.
  const raw = String(urlTemplate || '').replace(/\{([a-zA-Z0-9_]+)\}/g, (m, name) =>
    isSecretName(name) ? maskStr : m);
  return maskQueryValues(raw, maskStr);
}

// Render the request body template the same way applyTemplate walks it, but
// with values masked. Without a body template the real request posts the
// submitted fields, so every field is shown as a masked placeholder.
function renderBody(body, maskStr, fieldNames) {
  if (body === undefined || body === null) {
    if (!fieldNames.length) return null;
    return '{' + fieldNames.map((n) => `"${n}":"${maskStr}"`).join(',') + '}';
  }
  return renderAny(body, maskStr);
}

function renderAny(v, maskStr, name = '') {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'string') return JSON.stringify(maskString(name, v, maskStr));
  if (typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map((x) => renderAny(x, maskStr, name)).join(',') + ']';
  if (typeof v === 'object') {
    return '{' + Object.entries(v).map(([k, val]) => `${JSON.stringify(k)}:${renderAny(val, maskStr, k)}`).join(',') + '}';
  }
  return JSON.stringify(maskStr);
}

// Single-quote shell quoting for the curl example.
function shq(s) {
  return String(s).replace(/'/g, `'\\''`);
}

function headerNames(headers) {
  if (!headers) return [];
  if (typeof headers === 'object' && !Array.isArray(headers)) return Object.keys(headers);
  return null; // string/array form — rendered as one opaque masked entry
}

function curlHttpPost(dest, pending, names) {
  const lines = [`curl -X POST '${shq(renderUrl(dest.url, CURL_MASK))}'`];
  if (names === null) {
    lines.push(`  -H '${CURL_MASK}'`);
  } else {
    let hasContentType = false;
    for (const name of names) {
      if (/^content-type$/i.test(name)) hasContentType = true;
      lines.push(`  -H '${shq(`${name}: ${CURL_MASK}`)}'`);
    }
    if (!hasContentType) lines.push(`  -H 'Content-Type: application/json'`);
  }
  const fieldNames = (pending.fields || []).map((f) => f.name);
  const body = renderBody(dest.body, CURL_MASK, fieldNames);
  if (body !== null) lines.push(`  -d '${shq(body)}'`);
  return lines.join(' \\\n');
}

function curlGcp(secret) {
  return [
    `curl -X POST '${shq(`https://secretmanager.googleapis.com/v1/${secret}:addVersion`)}'`,
    `  -H 'Authorization: Bearer ${CURL_MASK}'`,
    `  -H 'Content-Type: application/json'`,
    `  -d '{"data":"${CURL_MASK}"}'`,
  ].join(' \\\n');
}

function curlAws(dest) {
  const host = `secretsmanager.${dest.region}.amazonaws.com`;
  return [
    `curl -X POST 'https://${host}/'`,
    `  -H 'Content-Type: application/json'`,
    `  -H 'X-Amz-Target: secretsmanager.PutSecretValue'`,
    `  -H 'X-Amz-Date: ${CURL_MASK}'`,
    `  -H 'Authorization: ${CURL_MASK}'`,
    `  -d '${shq(`{"SecretId":"${dest.secret_id}","SecretString":"${CURL_MASK}"}`)}'`,
  ].join(' \\\n');
}

function curlVault(dest, pending) {
  const url = `${dest.address}/v1/${String(dest.path).replace(/^\//, '')}`;
  const fieldNames = (pending.fields || []).map((f) => f.name);
  const fields = renderBody(null, CURL_MASK, fieldNames) || '{}';
  return [
    `curl -X POST '${shq(url)}'`,
    `  -H 'X-Vault-Token: ${CURL_MASK}'`,
    `  -H 'Content-Type: application/json'`,
    `  -d '${shq(`{"data":${fields}}`)}'`,
  ].join(' \\\n');
}

// Build display rows + curl example for one destination. Returns raw strings;
// the caller HTML-escapes everything.
function describeDestination(dest, pending) {
  const rows = [];
  let curl = null;
  const type = String(dest.type || '');

  switch (type) {
    case 'local_file': {
      const ctx = { uid: pending.uid, service: pending.service_slug };
      const uid = resolveTemplate(dest.uid, ctx) || '…';
      const name = resolveTemplate(dest.filename, ctx) || '…';
      rows.push({ k: 'File', v: `~/agent-tokens/${uid}/${name}` });
      break;
    }
    case 'http_post': {
      rows.push({
        k: 'Request',
        v: dest.url ? `POST ${renderUrl(dest.url, MASK)}` : '…',
      });
      const names = headerNames(dest.headers);
      if (names === null) {
        rows.push({ k: 'Headers', v: MASK });
      } else {
        for (const name of names) rows.push({ k: `Header ${name}`, v: MASK });
      }
      if (dest.url) curl = curlHttpPost(dest, pending, names);
      break;
    }
    case 'gcp_secret_manager':
      rows.push({ k: 'Resource', v: dest.secret ? String(dest.secret) : '…' });
      if (dest.credentials !== undefined) rows.push({ k: 'Service-account key', v: MASK });
      if (dest.secret) curl = curlGcp(String(dest.secret));
      break;
    case 'aws_secrets_manager':
      rows.push({ k: 'Secret', v: dest.secret_id ? String(dest.secret_id) : '…' });
      rows.push({ k: 'Region', v: dest.region ? String(dest.region) : '…' });
      if (dest.access_key_id !== undefined) rows.push({ k: 'Access key ID', v: MASK });
      if (dest.secret_access_key !== undefined) rows.push({ k: 'Secret access key', v: MASK });
      if (dest.secret_id && dest.region) curl = curlAws(dest);
      break;
    case 'vault':
      rows.push({ k: 'Address', v: dest.address ? String(dest.address) : '…' });
      rows.push({ k: 'Path', v: dest.path ? String(dest.path) : '…' });
      if (dest.token !== undefined) rows.push({ k: 'Token', v: MASK });
      if (dest.role_id !== undefined) rows.push({ k: 'Role ID', v: String(dest.role_id) });
      if (dest.secret_id !== undefined) rows.push({ k: 'Secret ID', v: MASK });
      if (dest.address && dest.path) curl = curlVault(dest, pending);
      break;
    case 'macos_keychain':
      rows.push({ k: 'Store', v: 'macOS Keychain' });
      rows.push({ k: 'Service', v: String(dest.service || 'zerocreds') });
      rows.push({ k: 'Account', v: String(dest.account || 'default') });
      break;
    case 'windows_credential_manager':
      rows.push({ k: 'Store', v: 'Windows Credential Manager' });
      rows.push({ k: 'Service', v: String(dest.service || 'zerocreds') });
      rows.push({ k: 'Account', v: String(dest.account || 'default') });
      break;
    case 'os_keychain':
      rows.push({ k: 'Store', v: 'OS credential store (Keychain / Credential Manager / local file)' });
      rows.push({ k: 'Service', v: String(dest.service || 'zerocreds') });
      rows.push({ k: 'Account', v: String(dest.account || 'default') });
      break;
    default:
      rows.push({ k: 'Type', v: type || '…' });
  }

  // Config keys the type does not consume: shown masked (never rendered raw).
  const known = KNOWN_KEYS[type] || ['type'];
  for (const key of Object.keys(dest)) {
    if (!known.includes(key)) rows.push({ k: key, v: MASK });
  }

  return { type, rows, curl };
}

// One entry per distinct destination of the session, mirroring how submit
// resolves them: destinations_by_level[level] → [default] → destination.
function collectEntries(pending) {
  if (!pending || typeof pending !== 'object') return [];
  const byLevel = pending.destinations_by_level && typeof pending.destinations_by_level === 'object'
    && !Array.isArray(pending.destinations_by_level)
    ? pending.destinations_by_level
    : null;

  if (!byLevel) {
    const dest = pending.destination;
    return dest && dest.type ? [{ labels: [], dest }] : [];
  }

  const entries = new Map(); // serialized dest → { labels, dest }
  const push = (dest, label) => {
    if (!dest || !dest.type) return;
    const key = JSON.stringify(dest);
    const found = entries.get(key);
    if (found) { if (label && !found.labels.includes(label)) found.labels.push(label); return; }
    entries.set(key, { labels: label ? [label] : [], dest });
  };

  for (const [level, dest] of Object.entries(byLevel)) push(dest, level);
  // Submit falls back to the session destination only when no default level
  // is configured — mirror that, dedup via the serialized key.
  if (pending.destination && !byLevel.default) push(pending.destination, null);
  return [...entries.values()];
}

function levelChip(label) {
  const tag = LEVEL_TAGS[label];
  if (!tag) return `<span class="dest-ent-lvl">${esc(label)}</span>`;
  return `<span class="wl-chip lvl-${esc(label)}">${tag}</span>`;
}

function destinationDisclosureHtml(pending) {
  const entries = collectEntries(pending);
  if (!entries.length) return '';

  const blocks = entries.map(({ labels, dest }) => {
    const d = describeDestination(dest, pending);
    let html = '<div class="dest-ent"><div class="dest-ent-hd">'
      + `<span class="dest-ent-t">${esc(d.type)}</span>`
      + labels.map(levelChip).join('')
      + '</div>';
    for (const r of d.rows) {
      html += `<div class="dest-row"><span class="dest-k">${esc(r.k)}</span><code class="dest-v">${esc(r.v)}</code></div>`;
    }
    if (d.curl) html += `<pre class="dest-curl">${esc(d.curl)}</pre>`;
    return html + '</div>';
  });

  return `<details class="dest-dd">
<summary class="dest-dd-sum"><span>Where will your secrets go?</span><span class="dest-dd-chev" aria-hidden="true">▾</span></summary>
<div class="dest-dd-body">
${blocks.join('\n')}
<div class="dest-note">Secret values are never shown on this page — ${MASK} and ${esc(CURL_MASK)} stand for the real values carried by the actual request.</div>
</div>
</details>`;
}

module.exports = { destinationDisclosureHtml, describeDestination, MASK, CURL_MASK };
