# ZeroCreds wallet metadata Worker

This is the D1 side of the planned ServerlessAgence wallet. It stores **only metadata**. Secret values stay in OpenBao KV v2. The sandbox Worker is deployed and the wallet integration branch connects it to ZeroCreds forms locally, but the Node service and Runner credential-use broker are not connected to the deployed Worker yet.

ZeroCreds operates the wallet infrastructure and its OpenBao administrative lifecycle; the customer owns the credential. ServerlessAgence receives a separate broker identity for authorized use, never OpenBao administration. The OpenCode agent receives no direct OpenBao identity. A write-only application policy does not prevent an OpenBao infrastructure administrator from accessing values, so production disclosure must state that boundary.

The default `wrangler.jsonc` is **local only**: its database UUID is a dummy identifier and `workers_dev` is off. `wrangler.sandbox.jsonc` and `wrangler.production.jsonc` bind separate D1 databases in the confirmed Cloudflare account; both databases have the initial migration applied and EU jurisdiction. The sandbox Worker is available at `https://zerocreds-wallet-metadata-sandbox.skillset-apply.workers.dev`. The production Worker has not been deployed or routed. Keep `WALLET_SERVICE_TOKEN` in a Worker secret; the sandbox copy is also in the operator's macOS Keychain under service `zerocreds-wallet-metadata-sandbox`, account `service-token`, for future host wiring. For local `wrangler dev`, place a disposable token in an ignored `.dev.vars` file. Do not give that token, the Worker URL, or D1 bindings to an agent. The trusted host must derive owner/profile IDs from its authenticated session before calling the metadata API. A caller-provided owner/profile value is not proof of identity.

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

The current Worker cannot prove an OpenBao write by itself: the trusted ZeroCreds service must verify the KV-v2 version receipt before calling `complete`. The `receipt_ref` is a SHA-256 reference, not a signed receipt or secret. If OpenBao succeeds and D1 completion fails, retry `complete` with the same form/version/receipt; the Worker does not mint a second version. Runtime use must separately check that the connection is active and belongs to the run's owner/profile. No secret read endpoint exists here.

Before production: connect a trusted identity source, bind the signed form manifest to this D1 record, provision scoped OpenBao and D1 environments, establish service-token rotation and audit, and prove end-to-end retry/revocation against a real sandbox. See [the integration contract](../docs/serverlessagence-runner-credential-intake.md).

The local form-to-wallet flow and operator checklist are documented in [wallet-agent-e2e.md](../docs/wallet-agent-e2e.md).
