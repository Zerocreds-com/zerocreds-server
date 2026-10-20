# ZeroCreds wallet metadata Worker

This is the D1 side of the planned ServerlessAgence wallet. It stores **only metadata**. Secret values stay in OpenBao KV v2. The sandbox Worker is deployed; the ZeroCreds Node form service and Runner credential-use broker are not connected to it in a deployed environment yet.

ZeroCreds operates the wallet infrastructure and its OpenBao administrative lifecycle; the customer owns the credential. ServerlessAgence receives a separate broker identity for authorized use, never OpenBao administration. The OpenCode agent receives no direct OpenBao identity. A write-only application policy does not prevent an OpenBao infrastructure administrator from accessing values, so production disclosure must state that boundary.

The default `wrangler.jsonc` is **local only**: its database UUID is a dummy identifier and `workers_dev` is off. `wrangler.sandbox.jsonc` and `wrangler.production.jsonc` bind separate EU-jurisdiction D1 databases in the confirmed Cloudflare account. The sandbox Worker is available at `https://zerocreds-wallet-metadata-sandbox.skillset-apply.workers.dev`; migration `0002_assertion_replay.sql` is applied and Worker version `177a2843-b0cc-4aec-8187-a805deba0696` is deployed. This URL is the internal metadata API, **not** the ZeroCreds Node form API expected at `/api/wallet/*`. No deployed sandbox Node API base URL is configured or documented yet; issue [#91](https://github.com/Zerocreds-com/zerocreds-server/issues/91) tracks that rollout. The production Worker has not been deployed or routed. Keep `WALLET_SERVICE_TOKEN` in a Worker secret; its sandbox copy is in the operator's macOS Keychain under service `zerocreds-wallet-metadata-sandbox`, account `service-token`, for the trusted ZeroCreds Node service only. Never provide it, the Worker URL, or D1 bindings to MCP Host or an agent. The trusted host must derive owner/profile IDs from its authenticated session before requesting a scoped API assertion. A caller-provided owner/profile value is not proof of identity.

Run `npm ci && npm test` to exercise the Worker against local D1 with the real migration. For manual local development, run `npm run migrate:local` and `npm run dev` with a local `.dev.vars`. The migration is additive; do not reuse the Control Plane task-store database.

For a new remote migration, review the SQL and run `npx wrangler d1 migrations apply DB --remote --config wrangler.sandbox.jsonc` before the production config. Deploy the sandbox with `npx wrangler deploy --config wrangler.sandbox.jsonc`; set its `WALLET_SERVICE_TOKEN` with `npx wrangler secret put WALLET_SERVICE_TOKEN --config wrangler.sandbox.jsonc`. Supply `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` from an operator secret store, never from a committed file. The production Worker remains intentionally unpublished until its host identity, OpenBao and service-token distribution are ready.

All endpoints are internal, require `Authorization: Bearer <WALLET_SERVICE_TOKEN>`, return JSON with `Cache-Control: no-store`, and accept at most 4 KiB of JSON. Only listed body keys are accepted, preventing accidental provider-value storage.

| Operation | Request | Effect |
| --- | --- | --- |
| `POST /internal/connections/allocate` | `owner_id`, `profile_id`, `provider`, `idempotency_key` | Returns stable `connection_id` and a server-derived `<mount>/data/owners/<owner>/connections/<connection>` path. Repeating the key returns the same allocation. |
| `POST /internal/forms` | `form_id`, `connection_id`, `owner_id`, `profile_id`, `manifest_id`, `expires_at` | Records an immutable form-to-connection binding. Same request may be retried; a conflicting binding returns 409. |
| `POST /internal/assertions/claim` | `jti_hash`, `expires_at` | Atomically claims a one-time host assertion ID digest; reuse returns 409. Expired digests are pruned on claim. |
| `POST /internal/forms/<form_id>/complete` | `owner_id`, `profile_id`, `manifest_id`, `kv_version`, `receipt_ref` | Confirms the already completed OpenBao write. Same version/receipt may be retried. A stale version or changed receipt returns 409. |
| `GET /internal/connections/<connection_id>` | `X-Wallet-Owner`, `X-Wallet-Profile` headers | Returns a scoped, value-free connection status or 404. |
| `POST /internal/connections/<connection_id>/revoke` | `owner_id`, `profile_id` | Prevents later form completion or new use. |

## The custody vault

The durable custody lives in a second D1 database (`VAULT_DB`), separate from the metadata database above. The wallet encrypts a value with a key only it holds (AES-256-GCM) before it reaches the store, so the store only ever holds ciphertext, and the metadata read never answers it. The vault routes are the same internal ones — service token, JSON, no-store:

| Operation | Request | Effect |
| --- | --- | --- |
| `PUT /internal/vault/values/<connection_id>` | `owner_id`, `profile_id`, `provider`, `ciphertext`, `iv`, `tag`, `alg`, `key_ref`, optional `lease_started_at`, `lease_expires_at` | Stores a new version of the value. The version is derived from the store, never from the request. |
| `GET /internal/vault/values/<connection_id>` | `X-Wallet-Owner`, `X-Wallet-Profile` headers | Returns the scoped, value-free status and version, or 404. |
| `POST /internal/vault/values/<connection_id>/read` | `owner_id`, `profile_id`, `run_id` | The only route that answers ciphertext. It records a `granted` event whose actor is the `run_id`. |
| `POST /internal/vault/values/<connection_id>/revoke` | `owner_id`, `profile_id` | Destroys the stored values, not only the connection flag. The event log survives. |

**One run, one grant.** The read route records the grant idempotently, per connection, run and value version: the same run asking again — a retry, a cut-over to another worker, a replacement host after the previous one died — is the same grant, so the journal keeps a single `granted` event. The answer carries `replay: true` when the run already held that grant, so the host can count its own deliveries. A rotated value is a different version and therefore a different grant.

**A lease on the value.** A value may carry a lease: `lease_started_at` and `lease_expires_at`, in milliseconds or as an ISO-8601 instant. The lease is the custody's own bound on how long the value may leave the store, and it is **opt-in**: without it the value lives in the custody until it is revoked, which is the right default for a credential a user minted for a long-lived integration. Once the lease has ended the read route refuses with `409 lease_expired` and the lease end — never the value. A refused grant is not a grant: the journal records no `granted` event for it. The grant that *did* happen keeps the lease end in the journal, so "the value was handed out under a lease that ended" is answerable after the fact. The lease is host policy: it travels with the value when the wallet stores it and the submitted form values cannot shorten or widen it.

The vault migrations are applied with `npx wrangler d1 migrations apply VAULT_DB --remote --config <config>`; the first one creates the tables, the second the grant-once index and the third the lease columns.

The current Worker cannot prove an OpenBao write by itself: the trusted ZeroCreds service must verify the KV-v2 version receipt before calling `complete`. The `receipt_ref` is a SHA-256 reference, not a signed receipt or secret. If OpenBao succeeds and D1 completion fails, retry `complete` with the same form/version/receipt; the Worker does not mint a second version. Runtime use must separately check that the connection is active and belongs to the run's owner/profile. No secret read endpoint exists here.

Before production: connect a trusted identity source, bind the signed form manifest to this D1 record, provision scoped OpenBao and D1 environments, establish service-token rotation and audit, and prove end-to-end retry/revocation against a real sandbox. See [the integration contract](../docs/serverlessagence-runner-credential-intake.md).

The local form-to-wallet flow and operator checklist are documented in [wallet-agent-e2e.md](../docs/wallet-agent-e2e.md).
