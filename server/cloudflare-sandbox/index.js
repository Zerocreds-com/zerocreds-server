import { DurableObject } from 'cloudflare:workers';

const PORT = 3456;
export class WalletApiContainer extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    if (ctx.container?.running) {
      void ctx.blockConcurrencyWhile(() => ctx.container.setInactivityTimeout(30 * 60 * 1000));
    }
  }

  async fetch(request) {
    const container = this.ctx.container;
    if (!container) return new Response('Container unavailable', { status: 503 });
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
      await container.setInactivityTimeout(30 * 60 * 1000);
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
