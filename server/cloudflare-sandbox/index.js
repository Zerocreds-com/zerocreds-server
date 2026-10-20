import { DurableObject } from 'cloudflare:workers';

const PORT = 3456;
const INACTIVITY_TIMEOUT_MS = 30 * 60 * 1000;

// The container keeps the environment it was started with, so a changed setting
// only reaches it once the instance is replaced. The fingerprint of the
// settings says whether the running instance still matches them.
async function settingsFingerprint(env) {
  const keys = ['OPENBAO_ROOT_TOKEN', 'ZEROCREDS_VAULT_DATA_KEY', 'ZEROCREDS_VAULT_KEY_REF',
    'ZEROCREDS_ADMIN_TOKEN', 'ZEROCREDS_WALLET_SERVICE_TOKEN', 'ZEROCREDS_WALLET_WORKER_URL',
    'ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON', 'ZEROCREDS_BASE_URL'];
  const material = keys.map((key) => `${key}=${env[key] ?? ''}`).join('\n');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export class WalletApiContainer extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    if (ctx.container?.running) {
      void ctx.blockConcurrencyWhile(() => ctx.container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS));
    }
  }

  async fetch(request) {
    const container = this.ctx.container;
    if (!container) return new Response('Container unavailable', { status: 503 });
    const fingerprint = await settingsFingerprint(this.env);
    if (container.running) {
      const started = await this.ctx.storage.get('settings_fingerprint');
      if (started !== fingerprint) {
        // The running instance still carries the previous settings, so it is
        // replaced before the request is served with the current ones.
        try {
          await container.destroy('settings changed');
        } catch {}
        return new Response('Container restarting', { status: 503, headers: { 'retry-after': '2' } });
      }
    }
    if (!container.running) {
      await container.start({
        image: container.images.api,
        enableInternet: true,
        env: {
          OPENBAO_ROOT_TOKEN: this.env.OPENBAO_ROOT_TOKEN,
          ZEROCREDS_VAULT_DATA_KEY: this.env.ZEROCREDS_VAULT_DATA_KEY,
          ZEROCREDS_VAULT_KEY_REF: this.env.ZEROCREDS_VAULT_KEY_REF,
          ZEROCREDS_ADMIN_TOKEN: this.env.ZEROCREDS_ADMIN_TOKEN,
          ZEROCREDS_WALLET_SERVICE_TOKEN: this.env.ZEROCREDS_WALLET_SERVICE_TOKEN,
          ZEROCREDS_WALLET_WORKER_URL: this.env.ZEROCREDS_WALLET_WORKER_URL,
          ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON: this.env.ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON,
          ZEROCREDS_BASE_URL: this.env.ZEROCREDS_BASE_URL,
        },
      });
      await container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
      await this.ctx.storage.put('settings_fingerprint', fingerprint);
    }

    const port = container.getTcpPort(PORT);
    let lastError;
    for (let i = 0; i < 120; i++) {
      try {
        const health = await port.fetch('http://container/health', {
          signal: AbortSignal.timeout(1000),
        });
        await health.body?.cancel();
        if (health.ok) {
          const url = new URL(request.url);
          url.protocol = 'http:';
          url.host = 'container';
          const forwarded = new Request(url, request);
          forwarded.headers.delete('host');
          return port.fetch(forwarded);
        }
        lastError = new Error(`health returned ${health.status}`);
      } catch (error) {
        lastError = error;
      }
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    throw new Error('ZeroCreds sandbox container did not become ready', { cause: lastError });
  }
}

export default {
  fetch(request, env) {
    if (new URL(request.url).pathname === '/_sandbox-health') {
      // The custody mode decides where a credential value lives, so it is worth
      // being able to see which one a lane runs.
      const custody = env.ZEROCREDS_VAULT_DATA_KEY ? 'd1' : (env.OPENBAO_ROOT_TOKEN ? 'openbao' : 'none');
      return new Response('ok', { headers: { 'cache-control': 'no-store', 'x-custody-mode': custody } });
    }
    return env.WALLET_API.getByName('wallet-api').fetch(request);
  },
};
