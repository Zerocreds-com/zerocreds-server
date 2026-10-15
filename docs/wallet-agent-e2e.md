# Wallet form path for an agent

This branch joins the ZeroCreds signed form API, the D1 metadata Worker and OpenBao KV v2. It is a sandbox implementation, not a deployed credential-use broker. A real local E2E with OpenBao 2.7.1 and Wrangler's local D1 passed on 2026-10-15. On 2026-10-16, separate EU-jurisdiction D1 databases were created for sandbox and production, their initial migrations applied, and the sandbox Worker deployed with a secret service token. An HTTP smoke test covered authentication, idempotent allocation, form registration, owner separation and revocation. It did not write an OpenBao value or connect the production Node service.
An isolated OpenCode run also invoked `zerocreds_wallet_form_create` through the new MCP server and received `form_id` and `connection_id` from a synthetic local API. This proves model-to-MCP tool discovery and invocation; it does not prove Runner credential use.

A value-free production inventory on 2026-10-15 found no admin token in the service environment, no global named-destination file, and ten legacy self-registered integrators; one has saved destinations. A private admin-token file has since been provisioned for the service user, but the currently deployed server does not read it until PR #71 is released. The inventory found 340 unfinished sessions from the last 30 days, including 252 created without a recognized integrator identity, and 18 completed form markers in the last seven days. Historical completion markers do not identify their creator. The hardened branch cannot be deployed until active anonymous callers are identified and migrated or given an explicit compatibility window.

The host gives the MCP process `ZEROCREDS_URL` and `ZEROCREDS_WALLET_API_TOKEN`. The wallet API token is bound server-side to an immutable `owner_id`, `profile_id` and one admin-configured OpenBao destination. The agent invokes `zerocreds_wallet_form_create` with a provider, credential kind and optional fields. It receives a one-time URL, `form_id` and `connection_id`, then calls `zerocreds_wallet_form_status` to observe `pending`, `done`, `expired` or `revoked`. After the form expires, `zerocreds_wallet_connection_status` still reports the connection state by ID; `zerocreds_wallet_connection_revoke` revokes it when the user explicitly requests that action. None of these tools accepts an owner, profile, destination or credential value. Existing `zerocreds_create_session` and `zerocreds_check_status` remain available for existing clients.

The browser form displays the wallet owner, profile, connection ID, exact OpenBao path and verified preflight time. It discloses that ZeroCreds infrastructure administrators can technically access the stored value. The user enters the value directly into ZeroCreds. The form writer uses a create-only KV-v2 write (`cas: 0`), captures the OpenBao version, and confirms the form in D1. The agent sees only the connection reference and version metadata. D1 stores no provider value or OpenBao token.

## Local configuration

The Node form service requires an admin token from `ZEROCREDS_ADMIN_TOKEN` or a private service-user file, a named OpenBao destination in `ZEROCREDS_DESTINATIONS_FILE`, `ZEROCREDS_WALLET_WORKER_URL`, `ZEROCREDS_WALLET_SERVICE_TOKEN`, and `ZEROCREDS_WALLET_CLIENTS_FILE`. The latter is an operator-owned mode-0600 JSON object keyed by host-issued API token:

```json
{
  "<at-least-32-character-random-api-token>": {
    "owner_id": "verified_owner_id",
    "profile_id": "authorized_profile_id",
    "destination": "wallet_openbao",
    "requester": "ServerlessAgence"
  }
}
```

The named destination is an OpenBao KV-v2 writer/probe configuration. Its configured `path` and `preflight_path_prefix` are placeholders; the wallet route replaces them with the path allocated by D1 for that owner and verifies the target path. The writer policy should grant only `create`/`update` to that owner's `connections/*` and `probes/*`; a separate metadata identity gets `read`/`delete` only for `probes/*`. Use HTTPS in production. The D1 Worker has its own `WALLET_SERVICE_TOKEN` secret and `OPENBAO_MOUNT` binding. The Node service and Worker must use the same token; the Worker mount must match the OpenBao mount. The MCP process receives only the scoped wallet API token, never the service token or OpenBao identities.

`POST /api/wallet/forms` accepts `provider`, `kind`, optional `fields`, `title`, `description`, `ttl_minutes` and optional `idempotency_key`. Reusing the same key and request returns the same pending form. `GET /api/wallet/forms/:form_id/status`, `GET /api/wallet/connections/:connection_id` and `POST /api/wallet/connections/:connection_id/revoke` are scoped by the same API token. The API returns no submit token; browser users submit through the one-time link. A retry after D1 failure must send exactly the same values. The server records a local HMAC of the submitted fields and the OpenBao version to finish D1 completion without a second OpenBao write.

## Verification

Run `node --test server/test/*.test.js`, `node --test mcp/test/*.test.js` and `npm test` in `wallet-worker/`. The optional `server/test/wallet-live.test.js` runs against a real sandbox when `ZEROCREDS_TEST_OPENBAO_URL`, `ZEROCREDS_TEST_OPENBAO_ROOT_TOKEN`, `ZEROCREDS_TEST_WALLET_WORKER_URL`, `ZEROCREDS_TEST_WALLET_SERVICE_TOKEN` and `ZEROCREDS_TEST_WALLET_MOUNT` are set. The KV-v2 mount must already exist. The test makes owner-scoped policies and disposable tokens, submits a synthetic value, reads it with a separate reader identity and checks D1-backed status. Do not point this test at production.

## Remaining production work

- Replace the static local wallet-client file with a trusted ServerlessAgence/Ladder identity bridge. It must derive owner from `verifyKey()` and authorize profile selection; never trust model-supplied owner/profile headers. Issue or exchange short-lived scoped wallet API credentials and support rotation.
- Provision persistent OpenBao with TLS, scoped per-owner writer/probe/reader identities, audit, backup, unseal/recovery and operational monitoring. The dedicated D1 databases and sandbox Worker now exist; distribute the sandbox service token to a trusted host, connect the Node service, and verify the full remote form-to-OpenBao-to-D1 path before publishing the production Worker. Store service credentials in operator secret stores and configure production domains.
- Harden the crash window after OpenBao accepts a write but before the local `.written` marker is durable. CAS prevents a second version, but this case currently needs operator reconciliation; add durable write-ahead state or metadata-based proof before public onboarding. Ensure expired forms with a confirmed OpenBao write can be reconciled.
- Add an owner-authorized connection list and rotate flow, revocation UX and retention cleanup. Scoped status and revoke endpoints are implemented; verify cross-owner denial with the real Worker and OpenBao policies.
- Build and review one narrow, open-source credential-use broker/MCP method. It must authorize the run, owner/profile, connection, provider, operation and resource; the agent must not receive a generic OpenBao reader. Validate actual Runner task completion and history/artifact compatibility.
- Complete PR #71's operator migration (anonymous session callers, named destinations and allowlists) before merging its changes into the production auto-deploy branch. The private admin token is already provisioned. Existing production integrator keys have no status and retain access; new self-registrations require approval. Review and rotate legacy keys deliberately instead of silently disabling them. PR #72's D1 Worker is local-only until separately provisioned.
