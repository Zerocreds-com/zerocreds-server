# Runner wallet sandbox

This lane is a second, disposable instance of the Cloudflare wallet API for the
Trained Assist Runner lane. It exists because the shared wallet sandbox trusts
the MCP Host issuer only, and its trust configuration cannot be extended from
outside: the issuer blob is a write-only secret and the deploy workflow reads a
host signing key file that no step creates. The Runner lane therefore runs its
own container with its own issuer, its own D1 metadata database and its own
OpenBao dev server, so no existing trust decision has to be rewritten.

It is a test environment. Its filesystem and OpenBao data are temporary; pending
forms and connections can disappear when Cloudflare stops or replaces the
container. Do not submit real credentials to it.

## Resources

| Resource | Name |
| --- | --- |
| Container Worker | `zerocreds-wallet-api-runner-sandbox` |
| Metadata Worker | `zerocreds-wallet-metadata-runner-sandbox` |
| D1 database | `zerocreds-wallet-runner-sandbox` |
| Issuer | `ai-agent-runner-sandbox` |

## Deploy

From `server/`, with a Workers Paid account, a Docker-compatible engine and
Wrangler 4.136 or newer:

```sh
npx wrangler d1 migrations apply zerocreds-wallet-runner-sandbox --remote \
  --config ../wallet-worker/wrangler.runner-sandbox.jsonc
npx wrangler deploy --config ../wallet-worker/wrangler.runner-sandbox.jsonc
npx wrangler deploy --config wrangler.runner-sandbox.jsonc
```

Set the same secrets as on the shared wallet sandbox, with values of its own:

- `OPENBAO_ROOT_TOKEN` — random bootstrap token for the private dev server.
- `ZEROCREDS_ADMIN_TOKEN` — random API admin token.
- `ZEROCREDS_WALLET_SERVICE_TOKEN` — same value as `WALLET_SERVICE_TOKEN` on the Runner metadata Worker.
- `ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON` — the Runner host issuer only: one
  Ed25519 public key, the disposable owner/profile mapping to `wallet_sandbox`
  and the caller classes that are actually provisioned. Never put a private
  signing key here; the Runner keeps the private half in its own Worker secret
  store.

The Runner host signs a short-lived Ed25519 assertion per call
(`caller_class: human`, at most five minutes, a fresh `jti`), so the wallet API
needs the Runner issuer public key and nothing else.

The caller must reach this lane through the public path: a Cloudflare Worker
that fetches another Worker of the same account needs the
`global_fetch_strictly_public` compatibility flag, otherwise Cloudflare answers
with error 1042. The Runner API lane carries that flag.
