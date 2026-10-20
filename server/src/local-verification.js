'use strict';

const PROVIDERS = Object.freeze({
  github: {
    url: 'https://api.github.com/user',
    tokenFields: ['token', 'github_token', 'personal_access_token'],
  },
  cloudflare: {
    url: 'https://api.cloudflare.com/client/v4/user/tokens/verify',
    tokenFields: ['api_token', 'token', 'cloudflare_token'],
  },
  deepgram: {
    url: 'https://api.deepgram.com/v1/auth/grant',
    method: 'POST',
    authScheme: 'Token',
    tokenFields: ['DEEPGRAM_API_KEY', 'api_key', 'deepgram_api_key', 'token'],
  },
});

async function boundedJson(response) {
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > 16_384) throw new Error('verification response too large');
  const text = await response.text();
  if (Buffer.byteLength(text) > 16_384) throw new Error('verification response too large');
  try { return JSON.parse(text); } catch { throw new Error('invalid verification response'); }
}

function selectToken(fields, names) {
  for (const name of names) {
    if (Object.hasOwn(fields || {}, name) && typeof fields[name] === 'string' && fields[name].length > 0 && fields[name].length <= 8192) {
      return fields[name];
    }
  }
  return null;
}

function credentialHint(provider, fields, { tokenField } = {}) {
  if (String(provider).toLowerCase() !== 'deepgram') return null;
  const token = selectToken(fields, tokenField === undefined ? PROVIDERS.deepgram.tokenFields : [tokenField]);
  if (!token) return null;
  return {
    character_count: token.length,
    masked: token.length >= 12 ? `${token.slice(0, 3)}…${token.slice(-4)}` : '[too short to mask safely]',
  };
}

async function verifyLocalCredential(provider, fields, fetchImpl = fetch, { tokenField, account_id: accountIdOverride } = {}) {
  const normalizedProvider = String(provider).toLowerCase();
  const config = PROVIDERS[normalizedProvider];
  if (!config) return { status: 'unsupported_provider' };
  const token = selectToken(fields, tokenField === undefined ? config.tokenFields : [tokenField]);
  if (!token) return { status: 'credential_field_missing' };

  let response;
  try {
    response = await fetchImpl(config.url, {
      method: config.method || 'GET',
      headers: {
        Authorization: `${config.authScheme || 'Bearer'} ${token}`,
        Accept: 'application/json',
        'User-Agent': 'ZeroCreds-local-verifier',
        ...(normalizedProvider === 'github' ? { 'X-GitHub-Api-Version': '2022-11-28' } : {}),
      },
      redirect: 'error',
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    return { status: 'unavailable' };
  }

  if (normalizedProvider === 'deepgram') {
    if (response.status === 401) return { status: 'invalid', diagnostic: { upstream_status: 401, upstream_code: 'invalid_credentials' } };
    if (!response.ok) {
      let body = {};
      try { body = await boundedJson(response); } catch {}
      const code = typeof body.err_code === 'string' && /^[A-Z0-9_-]{1,64}$/.test(body.err_code)
        ? body.err_code : undefined;
      const message = typeof body.err_msg === 'string' ? body.err_msg : typeof body.error === 'string' ? body.error : '';
      const invalid = response.status === 400 && /invalid credentials/i.test(message);
      const status = response.status === 403 ? 'insufficient_permissions' : invalid ? 'invalid' : 'unavailable';
      return { status, diagnostic: { upstream_status: response.status, upstream_code: code || (invalid ? 'invalid_credentials' : undefined) } };
    }
    try {
      const grant = await boundedJson(response);
      if (typeof grant.access_token !== 'string' || !grant.access_token) {
        return { status: 'unavailable', diagnostic: { upstream_status: response.status, upstream_code: 'grant_token_missing' } };
      }
      return {
        status: 'valid',
        identity: { grant_capable: true },
        permissions: [],
        permission_evidence: 'provider_verified',
        diagnostic: {
          upstream_status: response.status,
          grant_expires_in: Number.isSafeInteger(grant.expires_in) ? grant.expires_in : null,
        },
      };
    } catch {
      return { status: 'unavailable', diagnostic: { upstream_status: response.status, upstream_code: 'invalid_response' } };
    }
  }

  if (normalizedProvider === 'github') {
    if (response.status === 401) return { status: 'invalid' };
    if (!response.ok) return { status: 'unavailable' };
    try {
      const user = await boundedJson(response);
      if (!Number.isSafeInteger(user.id) || typeof user.login !== 'string') return { status: 'unavailable' };
      const scopes = (response.headers.get('x-oauth-scopes') || '').split(',').map((s) => s.trim()).filter(Boolean).slice(0, 64);
      return {
        status: 'valid',
        identity: { id: String(user.id), login: user.login.slice(0, 100) },
        permissions: scopes,
        permission_evidence: scopes.length ? 'provider_verified' : 'unknown',
      };
    } catch {
      return { status: 'unavailable' };
    }
  }

  // A Cloudflare account-owned token can be rejected by the user-token
  // endpoint while still accessing its account's Workers. That response alone
  // is not evidence that the stored token is invalid.
  if (!response.ok) {
    const accountId = accountIdOverride || fields?.account_id;
    if (!/^[a-f0-9]{32}$/.test(accountId || '')) {
      return { status: 'unknown', diagnostic: { upstream_status: response.status,
        reason: 'cloudflare_token_context_unconfirmed', account_id_required: true,
        next_step: 'Check the existing token against the target account or resource. Do not request a replacement token from this result.' } };
    }
    try {
      response = await fetchImpl(`https://api.cloudflare.com/client/v4/accounts/${accountId}/tokens/verify`, {
        method: 'GET', headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        redirect: 'error', signal: AbortSignal.timeout(8000),
      });
    } catch {
      return { status: 'unknown', diagnostic: { reason: 'cloudflare_account_verification_unavailable',
        next_step: 'Check the existing token against the target resource. Do not request a replacement token from this result.' } };
    }
  }
  if (!response.ok) return { status: 'unknown', diagnostic: { upstream_status: response.status,
    reason: 'cloudflare_verification_rejected',
    next_step: 'Check the token type, account and intended resource before requesting a replacement.' } };
  try {
    const result = await boundedJson(response);
    const verification = result?.result;
    if (!result?.success || verification?.status !== 'active') return { status: 'invalid' };
    return {
      status: 'valid',
      identity: { token_id: String(verification.id || '').slice(0, 100) || null },
      permissions: [],
      permission_evidence: 'unknown',
      provider_expires_at: typeof verification.expires_on === 'string' ? verification.expires_on : null,
    };
  } catch {
    return { status: 'unavailable' };
  }
}

module.exports = { verifyLocalCredential, credentialHint };
