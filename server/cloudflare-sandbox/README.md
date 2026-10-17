# Cloudflare wallet API sandbox

This deployment runs the existing Node wallet API and an OpenBao dev server in one Cloudflare Container, behind a Durable Object. OpenBao is reachable only on the container loopback interface. The container uses a synthetic sandbox mount and a write-only credential policy plus a separate probe-metadata policy.

This is a disposable test environment. Its filesystem and OpenBao data are temporary; pending forms and sandbox connections can disappear when Cloudflare stops or replaces the container. Do not submit real credentials to it.

## Deploy

From `server/`, use a Workers Paid account, a Docker-compatible engine, and Wrangler 4.136 or newer:

```sh
npx wrangler deploy --config wrangler.sandbox.jsonc
```

The repository workflow **Deploy ZeroCreds wallet sandbox** provides the trusted
GitHub Actions path. It targets the `sandbox` Environment only, validates the
metadata Worker/API container and, when `dry_run=false`, applies the existing
remote D1 migrations, deploys both sandbox Workers, and installs their secrets.
It never targets production. Provision the exact sandbox-only secrets listed
below in the `sandbox` GitHub Environment before dispatching the workflow.

Set these Worker secrets before sending requests:

- `OPENBAO_ROOT_TOKEN` — random bootstrap token for the private dev server.
- `ZEROCREDS_ADMIN_TOKEN` — random API admin token.
- `ZEROCREDS_WALLET_SERVICE_TOKEN` — same value as `WALLET_SERVICE_TOKEN` on the sandbox metadata Worker.
- `ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON` — public issuer key and sandbox profile mapping; never put a private signing key here.

The test host's public key must match the key ID and issuer above. Each profile
entry must map only a disposable owner/profile to `wallet_sandbox`; include only
the caller classes that have actually been provisioned. Do not reuse production
owner IDs, credentials or destinations. The MCP Host private signing key belongs
only in that repository's sandbox Worker secret store.

The Host URL and metadata Worker URL are non-secret values in `wrangler.sandbox.jsonc`. The host signing key belongs only in the Trained Assist Host Worker secret `ZEROCREDS_WALLET_SIGNING_KEY`. Keep the Host's profile KV mapping and the API issuer profile mapping identical.

Cloudflare Containers build and upload the image during `wrangler deploy`. Initial image preparation can take several minutes. The service token is sent only between the Node API and the internal metadata Worker; it does not go to the MCP client.
