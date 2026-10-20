const ID = /^[a-zA-Z0-9_-]{1,100}$/;
const FORM_ID = /^[a-f0-9]{32}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const PROVIDER = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const KEY = /^[a-zA-Z0-9_-]{16,128}$/;
const ASSERTION_JTI = /^[a-f0-9]{64}$/;
const RUN_REF = /^[A-Za-z0-9_.:-]{1,200}$/;

function response(status, body) {
  return new Response(JSON.stringify(body), { status, headers: {
    'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  } });
}
function validObject(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).every(key => keys.includes(key));
}
function validText(value, pattern) { return typeof value === 'string' && pattern.test(value); }
async function readBody(request, keys, limit = 4096) {
  if (Number(request.headers.get('content-length') || 0) > limit) return null;
  const reader = request.body?.getReader();
  if (!reader) return null;
  let size = 0;
  const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) { await reader.cancel(); return null; }
      chunks.push(value);
    }
  } catch { return null; }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const raw = new TextDecoder().decode(bytes);
  try { const body = JSON.parse(raw); return validObject(body, keys) ? body : null; }
  catch { return null; }
}
async function hash(input) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}
async function authorized(request, token) {
  if (!token || token.length < 32) return false;
  const bearer = request.headers.get('authorization');
  if (!bearer?.startsWith('Bearer ')) return false;
  const supplied = bearer.slice(7);
  if (supplied.length < 32 || supplied.length > 256) return false;
  const [a, b] = await Promise.all([hash(supplied), hash(token)]);
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}
function identity(ownerId, profileId) { return validText(ownerId, ID) && validText(profileId, ID); }
function publicConnection(row) {
  return { connection_id: row.connection_id, owner_id: row.owner_id, profile_id: row.profile_id,
    provider: row.provider, openbao_path: row.openbao_path, state: row.state,
    kv_version: row.kv_version, updated_at: row.updated_at };
}
async function allocate(env, request) {
  const body = await readBody(request, ['owner_id', 'profile_id', 'provider', 'idempotency_key']);
  if (!body || !identity(body.owner_id, body.profile_id) || !validText(body.provider, PROVIDER)
      || !validText(body.idempotency_key, KEY)) return response(400, { error: 'invalid_allocation' });
  const requestKeyHash = await hash(body.idempotency_key);
  const connectionId = crypto.randomUUID();
  const mount = env.OPENBAO_MOUNT;
  if (!validText(mount, /^[a-zA-Z0-9_-]{1,64}$/)) return response(503, { error: 'wallet_not_configured' });
  const path = `${mount}/data/owners/${body.owner_id}/connections/${connectionId}`;
  const now = Date.now();
  await env.DB.prepare(`INSERT OR IGNORE INTO wallet_connections
    (connection_id, owner_id, profile_id, provider, request_key_hash, openbao_path, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(connectionId, body.owner_id, body.profile_id,
    body.provider, requestKeyHash, path, now, now).run();
  const row = await env.DB.prepare('SELECT * FROM wallet_connections WHERE owner_id = ? AND request_key_hash = ?')
    .bind(body.owner_id, requestKeyHash).first();
  if (!row || row.profile_id !== body.profile_id || row.provider !== body.provider) {
    return response(409, { error: 'allocation_conflict' });
  }
  return response(200, publicConnection(row));
}
async function registerForm(env, request) {
  const body = await readBody(request, ['form_id', 'connection_id', 'owner_id', 'profile_id', 'manifest_id', 'expires_at']);
  if (!body || !validText(body.form_id, FORM_ID) || !validText(body.connection_id, ID)
      || !identity(body.owner_id, body.profile_id) || !validText(body.manifest_id, SHA256)
      || !Number.isSafeInteger(body.expires_at) || body.expires_at <= Date.now()
      || body.expires_at > Date.now() + 86_400_000) return response(400, { error: 'invalid_form' });
  const connection = await env.DB.prepare('SELECT * FROM wallet_connections WHERE connection_id = ? AND owner_id = ? AND profile_id = ?')
    .bind(body.connection_id, body.owner_id, body.profile_id).first();
  if (!connection || connection.state === 'revoked') return response(404, { error: 'connection_unavailable' });
  await env.DB.prepare(`INSERT OR IGNORE INTO wallet_forms
    (form_id, connection_id, owner_id, profile_id, manifest_id, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(body.form_id, body.connection_id, body.owner_id,
    body.profile_id, body.manifest_id, body.expires_at, Date.now()).run();
  const row = await env.DB.prepare('SELECT * FROM wallet_forms WHERE form_id = ?').bind(body.form_id).first();
  if (row.connection_id !== body.connection_id || row.owner_id !== body.owner_id
      || row.profile_id !== body.profile_id || row.manifest_id !== body.manifest_id
      || row.expires_at !== body.expires_at) return response(409, { error: 'form_conflict' });
  return response(200, { form_id: row.form_id, connection_id: row.connection_id,
    state: row.state, expires_at: row.expires_at });
}
async function completeForm(env, request, formId) {
  const body = await readBody(request, ['owner_id', 'profile_id', 'manifest_id', 'kv_version', 'receipt_ref']);
  if (!body || !identity(body.owner_id, body.profile_id) || !validText(body.manifest_id, SHA256)
      || !Number.isSafeInteger(body.kv_version) || body.kv_version < 1
      || !validText(body.receipt_ref, SHA256)) return response(400, { error: 'invalid_completion' });
  const row = await env.DB.prepare(`SELECT f.*, c.state AS connection_state FROM wallet_forms f
    JOIN wallet_connections c ON c.connection_id = f.connection_id
    WHERE f.form_id = ? AND f.owner_id = ? AND f.profile_id = ?`).bind(formId, body.owner_id, body.profile_id).first();
  if (!row) return response(404, { error: 'form_unavailable' });
  if (row.manifest_id !== body.manifest_id) return response(409, { error: 'manifest_mismatch' });
  if (row.state === 'written') return row.kv_version === body.kv_version && row.receipt_ref === body.receipt_ref
    ? response(200, { form_id: formId, connection_id: row.connection_id, state: 'written', kv_version: row.kv_version })
    : response(409, { error: 'completion_conflict' });
  if (row.expires_at <= Date.now() || row.connection_state === 'revoked') return response(409, { error: 'form_unavailable' });
  const now = Date.now();
  let results;
  try { results = await env.DB.batch([
    env.DB.prepare(`UPDATE wallet_forms SET state = 'written', kv_version = ?, receipt_ref = ?, completed_at = ?
      WHERE form_id = ? AND owner_id = ? AND profile_id = ? AND manifest_id = ? AND state = 'pending'
      AND expires_at > ? AND EXISTS (SELECT 1 FROM wallet_connections c WHERE c.connection_id = wallet_forms.connection_id AND c.state != 'revoked')`)
      .bind(body.kv_version, body.receipt_ref, now, formId, body.owner_id, body.profile_id, body.manifest_id, now),
    env.DB.prepare(`UPDATE wallet_connections SET state = 'active', kv_version = ?, updated_at = ?
      WHERE connection_id = ? AND owner_id = ? AND profile_id = ? AND state != 'revoked'
      AND EXISTS (SELECT 1 FROM wallet_forms f WHERE f.form_id = ? AND f.state = 'written' AND f.kv_version = ? AND f.receipt_ref = ?)`)
      .bind(body.kv_version, now, row.connection_id, body.owner_id, body.profile_id,
        formId, body.kv_version, body.receipt_ref),
  ]); } catch (error) {
    if (String(error?.message || '').includes('wallet_version_not_newer')) {
      return response(409, { error: 'stale_kv_version' });
    }
    throw error;
  }
  if (results[0].meta.changes !== 1 || results[1].meta.changes !== 1) {
    return response(409, { error: 'completion_conflict' });
  }
  return response(200, { form_id: formId, connection_id: row.connection_id, state: 'written', kv_version: body.kv_version });
}
async function connectionStatus(env, request, connectionId) {
  const owner = request.headers.get('x-wallet-owner');
  const profile = request.headers.get('x-wallet-profile');
  if (!identity(owner, profile)) return response(400, { error: 'invalid_scope' });
  const row = await env.DB.prepare('SELECT * FROM wallet_connections WHERE connection_id = ? AND owner_id = ? AND profile_id = ?')
    .bind(connectionId, owner, profile).first();
  return row ? response(200, publicConnection(row)) : response(404, { error: 'connection_unavailable' });
}
async function revoke(env, request, connectionId) {
  const body = await readBody(request, ['owner_id', 'profile_id']);
  if (!body || !identity(body.owner_id, body.profile_id)) return response(400, { error: 'invalid_scope' });
  const result = await env.DB.prepare(`UPDATE wallet_connections SET state = 'revoked', updated_at = ?
    WHERE connection_id = ? AND owner_id = ? AND profile_id = ?`).bind(Date.now(), connectionId,
    body.owner_id, body.profile_id).run();
  return result.meta.changes === 1 ? response(200, { connection_id: connectionId, state: 'revoked' })
    : response(404, { error: 'connection_unavailable' });
}
const BASE64 = /^[A-Za-z0-9+/]{1,20000}={0,2}$/;
const VAULT_BODY_LIMIT = 65536;

// Custody routes. The wallet encrypts the value before it leaves the wallet, so
// this store only ever holds ciphertext; the metadata read never returns it.
// A lease is a promise that the value is only hand-out-able while it is valid.
// It is opt-in: a long-lived integration sends nothing and keeps working.
// The lease is recorded on the value, so the grant path can refuse an expired
// lease and the journal can answer "the value was handed out under a lease
// that ended" after the fact.
const LEASE_AT = /^[A-Za-z0-9_.:-]{1,64}$/;

// A lease instant is either absent (no lease), a millisecond timestamp, or an
// ISO-8601 instant. An unparsable one is refused rather than silently read as
// "no lease": a lease that is meant and cannot be read must not widen the
// window in which the value can leave the store.
function leaseField(value) {
  if (value === undefined || value === null || value === '') return { present: false, at: null };
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value > 0
      ? { present: true, at: value } : { present: true, invalid: true, at: null };
  }
  if (typeof value === 'string' && LEASE_AT.test(value)) {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return { present: true, at: parsed };
  }
  return { present: true, invalid: true, at: null };
}

async function vaultPut(env, request, connectionId) {
  if (!env.VAULT_DB) return response(503, { error: 'vault_not_configured' });
  const body = await readBody(request, ['owner_id', 'profile_id', 'provider', 'ciphertext', 'iv', 'tag', 'alg', 'key_ref',
    'lease_started_at', 'lease_expires_at'], VAULT_BODY_LIMIT);
  if (!body || !identity(body.owner_id, body.profile_id) || !validText(body.provider, PROVIDER)
      || !validText(body.ciphertext, BASE64) || !validText(body.iv, BASE64) || !validText(body.tag, BASE64)
      || body.alg !== 'A256GCM' || !validText(body.key_ref, ID)) return response(400, { error: 'invalid_value' });
  const started = leaseField(body.lease_started_at);
  const expires = leaseField(body.lease_expires_at);
  if (started.invalid || expires.invalid) {
    return response(400, { error: 'invalid_lease', message: 'the lease instants are not readable' });
  }
  const leaseStartedAt = started.at;
  const leaseExpiresAt = expires.at;
  if (leaseStartedAt !== null && leaseExpiresAt !== null && leaseExpiresAt <= leaseStartedAt) {
    return response(400, { error: 'invalid_lease', message: 'the lease must end after it starts' });
  }
  const connection = await env.DB.prepare('SELECT * FROM wallet_connections WHERE connection_id = ? AND owner_id = ? AND profile_id = ?')
    .bind(connectionId, body.owner_id, body.profile_id).first();
  if (!connection) return response(404, { error: 'connection_unavailable' });
  if (connection.state === 'revoked') return response(409, { error: 'connection_revoked' });
  const now = Date.now();
  await env.VAULT_DB.prepare(`INSERT INTO credential_values
    (connection_id, owner_id, profile_id, version, ciphertext, iv, tag, alg, key_ref, provider, created_at,
     lease_started_at, lease_expires_at)
    SELECT ?, ?, ?, COALESCE(MAX(version), 0) + 1, ?, ?, ?, ?, ?, ?, ?, ?, ?
    FROM credential_values WHERE connection_id = ?`)
    .bind(connectionId, body.owner_id, body.profile_id, body.ciphertext, body.iv, body.tag,
      body.alg, body.key_ref, body.provider, now, leaseStartedAt, leaseExpiresAt, connectionId).run();
  const stored = await env.VAULT_DB.prepare('SELECT MAX(version) AS version FROM credential_values WHERE connection_id = ?')
    .bind(connectionId).first();
  const version = Number(stored?.version || 0);
  if (!Number.isSafeInteger(version) || version < 1) return response(503, { error: 'vault_unavailable' });
  await env.VAULT_DB.prepare(`INSERT INTO credential_events
    (connection_id, owner_id, profile_id, action, version, actor, created_at)
    VALUES (?, ?, ?, 'created', ?, 'wallet', ?)`)
    .bind(connectionId, body.owner_id, body.profile_id, version, now).run();
  return response(200, { connection_id: connectionId, version, key_ref: body.key_ref,
    lease_started_at: leaseStartedAt, lease_expires_at: leaseExpiresAt });
}
async function vaultStatus(env, request, connectionId) {
  if (!env.VAULT_DB) return response(503, { error: 'vault_not_configured' });
  const owner = request.headers.get('x-wallet-owner');
  const profile = request.headers.get('x-wallet-profile');
  if (!identity(owner, profile)) return response(400, { error: 'invalid_scope' });
  const live = await env.VAULT_DB.prepare('SELECT version, created_at FROM credential_values WHERE connection_id = ? AND owner_id = ? AND profile_id = ? AND revoked_at IS NULL ORDER BY version DESC LIMIT 1')
    .bind(connectionId, owner, profile).first();
  if (live) return response(200, { connection_id: connectionId, state: 'active', version: live.version, updated_at: live.created_at });
  const last = await env.VAULT_DB.prepare('SELECT created_at FROM credential_values WHERE connection_id = ? AND owner_id = ? AND profile_id = ? ORDER BY version DESC LIMIT 1')
    .bind(connectionId, owner, profile).first();
  return response(200, { connection_id: connectionId, state: 'missing', version: null, updated_at: last?.created_at ?? null });
}
async function vaultRevoke(env, request, connectionId) {
  if (!env.VAULT_DB) return response(503, { error: 'vault_not_configured' });
  const body = await readBody(request, ['owner_id', 'profile_id']);
  if (!body || !identity(body.owner_id, body.profile_id)) return response(400, { error: 'invalid_scope' });
  const known = await env.VAULT_DB.prepare('SELECT COUNT(*) AS n FROM credential_values WHERE connection_id = ? AND owner_id = ? AND profile_id = ?')
    .bind(connectionId, body.owner_id, body.profile_id).first();
  if (!known?.n) return response(404, { error: 'connection_unavailable' });
  const now = Date.now();
  // The value is destroyed, not only flagged: a revoked credential leaves no
  // ciphertext behind.
  const result = await env.VAULT_DB.prepare('DELETE FROM credential_values WHERE connection_id = ? AND owner_id = ? AND profile_id = ?')
    .bind(connectionId, body.owner_id, body.profile_id).run();
  const versions = result.meta.changes || 0;
  await env.VAULT_DB.prepare(`INSERT INTO credential_events
    (connection_id, owner_id, profile_id, action, version, actor, created_at)
    VALUES (?, ?, ?, 'revoked', ?, 'wallet', ?)`)
    .bind(connectionId, body.owner_id, body.profile_id, versions, now).run();
  return response(200, { connection_id: connectionId, state: 'revoked', versions_revoked: versions });
}
// The wallet is the only component that holds the data key, so it is the only
// caller that may read a stored ciphertext back. A read is bound to the run that
// asked for it and is recorded before the ciphertext leaves the store, so a use
// is attributable even though the store never sees the plaintext.
async function vaultRead(env, request, connectionId) {
  if (!env.VAULT_DB) return response(503, { error: 'vault_not_configured' });
  const body = await readBody(request, ['owner_id', 'profile_id', 'run_id'], VAULT_BODY_LIMIT);
  if (!body || !identity(body.owner_id, body.profile_id) || !validText(body.run_id, RUN_REF)) {
    return response(400, { error: 'invalid_scope' });
  }
  const live = await env.VAULT_DB.prepare(`SELECT version, ciphertext, iv, tag, alg, key_ref,
    lease_started_at, lease_expires_at FROM credential_values
    WHERE connection_id = ? AND owner_id = ? AND profile_id = ? AND revoked_at IS NULL
    ORDER BY version DESC LIMIT 1`).bind(connectionId, body.owner_id, body.profile_id).first();
  if (!live) return response(404, { error: 'value_unavailable' });
  // A lease that has ended closes the store for this value. The refusal names
  // the lease and never the value: the caller learns that the credential aged
  // out, and nothing about what it was.
  const now = Date.now();
  if (live.lease_expires_at !== null && live.lease_expires_at !== undefined
      && Number(live.lease_expires_at) <= now) {
    return response(409, { error: 'lease_expired',
      lease_expires_at: new Date(Number(live.lease_expires_at)).toISOString() });
  }
  // One grant per run. The host asks again on every dispatch attempt — a retry,
  // a cut-over to another worker, a replacement host after the previous one
  // died — and those are the same grant, so the journal keeps one `granted`
  // event for it. Every bound value is validated above and the version comes
  // from the row itself, so the only constraint the ignore can hit is the
  // grant-once index.
  const grant = await env.VAULT_DB.prepare(`INSERT OR IGNORE INTO credential_events
    (connection_id, owner_id, profile_id, action, version, actor, created_at, lease_expires_at)
    VALUES (?, ?, ?, 'granted', ?, ?, ?, ?)`)
    .bind(connectionId, body.owner_id, body.profile_id, live.version, body.run_id, now,
      live.lease_expires_at ?? null).run();
  // `replay` tells the host that the run already held this grant: the value is
  // still answered (the run needs it to work), but the journal did not grow.
  // The lease end rides along with the grant, so "the value was handed out
  // under a lease that ended" stays answerable after the fact.
  return response(200, { connection_id: connectionId, version: live.version, ciphertext: live.ciphertext,
    iv: live.iv, tag: live.tag, alg: live.alg, key_ref: live.key_ref, replay: grant.meta?.changes === 0,
    lease_started_at: live.lease_started_at ?? null, lease_expires_at: live.lease_expires_at ?? null });
}
async function claimAssertion(env, request) {
  const body = await readBody(request, ['jti_hash', 'expires_at']);
  const now = Date.now();
  if (!body || !validText(body.jti_hash, ASSERTION_JTI) || !Number.isSafeInteger(body.expires_at)
      || body.expires_at <= now || body.expires_at > now + 300_000) {
    return response(400, { error: 'invalid_assertion_claim' });
  }
  await env.DB.prepare('DELETE FROM wallet_assertions WHERE expires_at <= ?').bind(now).run();
  const inserted = await env.DB.prepare(`INSERT OR IGNORE INTO wallet_assertions
    (jti_hash, expires_at, created_at) VALUES (?, ?, ?)`).bind(body.jti_hash, body.expires_at, now).run();
  return inserted.meta.changes === 1 ? response(200, { claimed: true })
    : response(409, { error: 'assertion_replayed' });
}
export default {
  async fetch(request, env) {
    if (!env.DB || !env.WALLET_SERVICE_TOKEN || !env.OPENBAO_MOUNT) return response(503, { error: 'wallet_not_configured' });
    if (!(await authorized(request, env.WALLET_SERVICE_TOKEN))) return response(401, { error: 'unauthorized' });
    const url = new URL(request.url);
    try {
      if (url.pathname === '/internal/connections/allocate' && request.method === 'POST') return allocate(env, request);
      if (url.pathname === '/internal/forms' && request.method === 'POST') return registerForm(env, request);
      if (url.pathname === '/internal/assertions/claim' && request.method === 'POST') return claimAssertion(env, request);
      const completed = /^\/internal\/forms\/([a-f0-9]{32})\/complete$/.exec(url.pathname);
      if (completed && request.method === 'POST') return completeForm(env, request, completed[1]);
      const connection = /^\/internal\/connections\/([a-zA-Z0-9_-]{1,100})$/.exec(url.pathname);
      if (connection && request.method === 'GET') return connectionStatus(env, request, connection[1]);
      const revoked = /^\/internal\/connections\/([a-zA-Z0-9_-]{1,100})\/revoke$/.exec(url.pathname);
      if (revoked && request.method === 'POST') return revoke(env, request, revoked[1]);
      const vaultValue = /^\/internal\/vault\/values\/([a-zA-Z0-9_-]{1,100})$/.exec(url.pathname);
      if (vaultValue && request.method === 'PUT') return vaultPut(env, request, vaultValue[1]);
      if (vaultValue && request.method === 'GET') return vaultStatus(env, request, vaultValue[1]);
      const vaultRevoked = /^\/internal\/vault\/values\/([a-zA-Z0-9_-]{1,100})\/revoke$/.exec(url.pathname);
      if (vaultRevoked && request.method === 'POST') return vaultRevoke(env, request, vaultRevoked[1]);
      const vaultReadBack = /^\/internal\/vault\/values\/([a-zA-Z0-9_-]{1,100})\/read$/.exec(url.pathname);
      if (vaultReadBack && request.method === 'POST') return vaultRead(env, request, vaultReadBack[1]);
      return response(404, { error: 'not_found' });
    } catch (error) {
      console.error('wallet metadata operation failed', error?.name || 'unknown');
      return response(503, { error: 'wallet_unavailable' });
    }
  },
};
