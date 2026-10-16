# Cloudflare wallet API sandbox

This deployment runs the existing Node wallet API and an OpenBao dev server in one Cloudflare Container, behind a Durable Object. OpenBao is reachable only on the container loopback interface. The container uses a synthetic sandbox mount and a write-only credential policy plus a separate probe-metadata policy.

This is a disposable test environment. Its filesystem and OpenBao data are temporary; pending forms and sandbox connections can disappear when Cloudflare stops or replaces the container. Do not submit real credentials to it.

## Deploy

From `server/`, use a Workers Paid account, a Docker-compatible engine, and Wrangler 4.136 or newer:

```sh
npx wrangler deploy --config wrangler.sandbox.jsonc
```

Set these Worker secrets before sending requests:

- `OPENBAO_ROOT_TOKEN` — random bootstrap token for the private dev server.
- `ZEROCREDS_ADMIN_TOKEN` — random API admin token.
- `ZEROCREDS_WALLET_SERVICE_TOKEN` — same value as `WALLET_SERVICE_TOKEN` on the sandbox metadata Worker.
- `ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON` — public issuer key and sandbox profile mapping; never put a private signing key here.

The Host URL and metadata Worker URL are non-secret values in `wrangler.sandbox.jsonc`. The host signing key belongs only in the Trained Assist Host Worker secret `ZEROCREDS_WALLET_SIGNING_KEY`. Keep the Host's profile KV mapping and the API issuer profile mapping identical.

Cloudflare Containers build and upload the image during `wrangler deploy`. Initial image preparation can take several minutes. The service token is sent only between the Node API and the internal metadata Worker; it does not go to the MCP client.
