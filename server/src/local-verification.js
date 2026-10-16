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
    if (typeof fields?.[name] === 'string' && fields[name].length > 0 && fields[name].length <= 8192) {
      return fields[name];
    }
  }
  return null;
}

async function verifyLocalCredential(provider, fields, fetchImpl = fetch) {
  const config = PROVIDERS[String(provider).toLowerCase()];
  if (!config) return { status: 'unsupported_provider' };
  const token = selectToken(fields, config.tokenFields);
  if (!token) return { status: 'credential_field_missing' };

  let response;
  try {
    response = await fetchImpl(config.url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        'User-Agent': 'ZeroCreds-local-verifier',
        ...(provider === 'github' ? { 'X-GitHub-Api-Version': '2022-11-28' } : {}),
      },
      redirect: 'error',
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    return { status: 'unavailable' };
  }

  if (provider === 'github') {
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

  if (!response.ok) return response.status === 401
    ? { status: 'invalid' } : { status: 'unavailable' };
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

module.exports = { verifyLocalCredential };
