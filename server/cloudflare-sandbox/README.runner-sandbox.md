# Runner wallet sandbox

This lane is a second, disposable instance of the Cloudflare wallet API for the
Trained Assist Runner lane. It exists because the shared wallet sandbox trusts
the MCP Host issuer only, and its trust configuration cannot be extended from
outside: the issuer blob is a write-only secret and the deploy workflow reads a
host signing key file that no step creates. The Runner lane therefore runs its
own container with its own issuer, its own D1 metadata database and its own
custody store, so no existing trust decision has to be rewritten.

It is a test environment. Its filesystem is temporary: pending forms and
connections can disappear when Cloudflare stops or replaces the container. The
credential values themselves are durable — they live in the custody database —
but do not submit real credentials to this lane.

## Resources

| Resource | Name |
| --- | --- |
| Container Worker | `zerocreds-wallet-api-runner-sandbox` |
| Metadata Worker | `zerocreds-wallet-metadata-runner-sandbox` |
| D1 metadata database | `zerocreds-wallet-runner-sandbox` |
| D1 custody database | `ta-credential-vault` |
| Issuer | `ai-agent-runner-sandbox` |

## Custody

The wallet encrypts a credential value (AES-256-GCM) before it leaves the
wallet and writes the ciphertext into the custody database. The metadata Worker
and the database therefore only ever hold ciphertext; the metadata read answers
existence and version, never a value. A revocation destroys the stored value
instead of only closing the connection.

A run gets a value through a **run-scoped grant**:
`POST /api/wallet/connections/{connection_id}/grants`. Only a machine assertion
(`caller_class: "machine"` with a `run_id`) may call it, the connection has to be
owned by the assertion's owner and profile, and the custody store has to hold a
live value — a revoked connection fails closed with `404`. The wallet decrypts
with the data key and the store records a `granted` event whose actor is the
`run_id`, so a use is attributable even though the store only ever sees
ciphertext. Nothing else answers a value.

The lane selects the custody mode by environment:

- `ZEROCREDS_VAULT_DATA_KEY` set — durable custody in `ta-credential-vault`,
  no OpenBao in the container at all;
- `OPENBAO_ROOT_TOKEN` set — the legacy in-container OpenBao dev server, whose
  data is temporary.

Exactly one of the two must be present. The same image serves both modes, which
is why the shared wallet sandbox keeps working unchanged.

A container keeps the environment it was started with, so a changed setting
only reaches it once the instance is replaced. The lane compares the settings
with the ones the running instance was started with and replaces the instance
when they differ, so the first request after a settings change comes back with
`503` and the next one is served by a container with the current settings. When
deploying by hand, set the secrets first and deploy the code last.

## Deploy

From `server/`, with a Workers Paid account, a Docker-compatible engine and
Wrangler 4.136 or newer:

```sh
npx wrangler d1 migrations apply zerocreds-wallet-runner-sandbox --remote \
  --config ../wallet-worker/wrangler.runner-sandbox.jsonc
npx wrangler d1 execute ta-credential-vault --remote \
  --file ../wallet-worker/vault-migrations/0001_credential_vault.sql \
  --config ../wallet-worker/wrangler.runner-sandbox.jsonc
npx wrangler deploy --config ../wallet-worker/wrangler.runner-sandbox.jsonc
npx wrangler deploy --config wrangler.runner-sandbox.jsonc
```

Set the same secrets as on the shared wallet sandbox, with values of its own:

- `ZEROCREDS_VAULT_DATA_KEY` — 32 random bytes in base64; the key the wallet
  encrypts credential values with. Losing it makes every stored value
  unreadable.
- `ZEROCREDS_VAULT_KEY_REF` — optional label for that key (`k1` by default),
  recorded with every stored version so the key can be rotated later.
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
