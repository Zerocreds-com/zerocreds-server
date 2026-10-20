// The environment a container is started with. Kept apart from the Durable
// Object so it can be tested without a Cloudflare runtime.

const SETTINGS = ['OPENBAO_ROOT_TOKEN', 'ZEROCREDS_VAULT_DATA_KEY', 'ZEROCREDS_VAULT_KEY_REF',
  'ZEROCREDS_ADMIN_TOKEN', 'ZEROCREDS_WALLET_SERVICE_TOKEN', 'ZEROCREDS_WALLET_WORKER_URL',
  'ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON', 'ZEROCREDS_BASE_URL'];

// Only the settings that are actually set are passed on: an unset secret must
// not reach the container as the text "undefined", and a container that reads
// two custody modes at once refuses to start.
export function containerEnv(env) {
  const result = {};
  for (const key of SETTINGS) {
    const value = env?.[key];
    if (typeof value === 'string' && value !== '') result[key] = value;
  }
  return result;
}

// The container keeps the environment it was started with, so the settings are
// fingerprinted to tell whether a running instance still matches them.
export async function settingsFingerprint(env) {
  const material = SETTINGS.map((key) => `${key}=${env?.[key] ?? ''}`).join('\n');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}
