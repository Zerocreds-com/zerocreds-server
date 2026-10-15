# ServerlessAgence: credential forms through MCP

Status: architecture decision for [ZeroCreds #67](https://github.com/Zerocreds-com/zerocreds-server/issues/67), **not an implemented end-to-end path**. The opt-in OpenBao KV-v2 preflight and version receipt in this change have only a local HTTP fixture test. The current ZeroCreds server stores pending forms in local files. The OpenBao service, owner-scoped policies, D1 metadata and agent-side credential use are not yet deployed as one proven flow.

## Decision

An agent asks a **generic ZeroCreds MCP tool** to prepare fields for its task. The tool returns a short-lived form URL. The person enters credentials in the browser; neither the model nor an MCP result receives the values. Store submitted secret values in **OpenBao KV v2** under an owner-scoped path. A dedicated Cloudflare D1 database holds only non-secret form, owner, profile, connection, version-reference and lifecycle metadata. Do not create a GitHub-specific API, local OpenCode command, or credential Durable Object for this flow.

A stable `connectionId` points to an owner-bound credential record. A runner or trusted MCP capability can use it only after owner, run and operation authorization. The exact list and names of credential-using open-source MCP methods are deferred until their implementations and policies are reviewed. Creating a form is not permission to execute arbitrary code with its secret.

### Storage choice: OpenBao values, D1 metadata

OpenBao is a separate service, not a Cloudflare D1 feature. KV v2 supplies secret versions and path-scoped ACLs, and OpenBao has audit devices. It requires authentication, unseal, backups, monitoring and availability planning ([KV v2](https://openbao.org/docs/secrets/kv/kv-v2/), [storage operations](https://openbao.org/docs/configuration/storage/), [audit](https://openbao.org/docs/audit/)). ZeroCreds already has a `vault` destination adapter, but that does not mean a production OpenBao cluster or owner-scoped policies exist.

Use D1 for the application workflow only. It tracks who owns a form/connection, which profile may use it, and which OpenBao secret path/version the broker must resolve. D1 must not contain provider values, OpenBao tokens, AppRole SecretIDs, ciphertext copies or sufficient data to bypass OpenBao authorization. The ZeroCreds writer and runner reader use different OpenBao identities and policies. Keep the `connectionId` and storage adapter stable so a customer-owned Vault-compatible backend can be selected later without changing MCP or Runner contracts.

Cloudflare Secrets Store is another product, separate from D1 and OpenBao. Its current open beta supports at most 100 production secrets per account and is designed around secrets bound to Cloudflare services, so it is unsuitable as the default per-user credential wallet ([Cloudflare documentation](https://developers.cloudflare.com/secrets-store/manage-secrets/)). It can hold a small number of service-level keys, subject to its access rules.

```text
OpenCode agent -- intent + proposed fields --> trusted ZeroCreds MCP adapter
                                              | derives owner + destination
                                              v
                                      ZeroCreds form API -- URL --> person
                                              ^                    |
                                              |              browser submission
                                              |                    v
                                      ZeroCreds writer --> OpenBao KV v2
                                              |             (secret value)
                                              +-- metadata --> dedicated D1
                                              |
agent <-- status + opaque connectionId -------+

Later: authorized run/tool --> broker --> OpenBao read for narrowly scoped use
       (never return the value in a tool result, prompt, status or log)
```

## Existing behavior and gap

[`mcp/index.js`](../mcp/index.js) already exposes `zerocreds_create_session` with `title`, `description`, `fields[]`, `destination` and `ttl_minutes`, plus `zerocreds_check_status`. The first returns `token`, `url`, `expires_at`; the second reports status. [`server/src/server.js`](../server/src/server.js) persists pending sessions under `ZEROCREDS_PENDING_DIR`, and [`server/src/destinations.js`](../server/src/destinations.js) already writes through a Vault-compatible destination. The raw MCP signature is unsuitable for production agent use because it accepts agent-chosen and inline destinations; the form lifecycle is not backed by owner-bound D1 metadata. Keep existing clients compatible while a trusted ServerlessAgence adapter narrows the inputs.

The Runner developer API already has `model.connectionId` and stable run/status/result/artifact contracts. Keep these compatible. The Control Plane has a D1-backed credential-ready wait for task continuation: it stores the **requirement and readiness reference, never the credential value** ([contract](https://github.com/trained-assist/trained-assist-control-plane/blob/main/docs/CREDENTIAL-READY-V1.md)). Its task-store database must not be reused for wallet metadata.

## Form request and ownership

The agent supplies task intent and a proposed schema: service, purpose, field names, display labels, sensitivity and requested capability. The same tool handles GitHub, a model API key, a cloud token or a website login. The trusted adapter authenticates the actual user/tenant and binds `ownerId`, task/run ID and a **server-selected destination**. The prompt cannot select an owner or destination. The adapter validates field count, types, names and text length, applies a short form TTL and presents the requested purpose to the person. It returns only `formId`, `url`, `expiresAt` and a non-secret status reference.

Browser submission consumes the form once and checks its immutable owner, schema, purpose, destination and expiry. Only a confirmed OpenBao write and matching D1 metadata commit return a non-secret receipt and opaque `connectionId`. A failed write never reports `done`; a timed-out retry reconciles the same form/version instead of creating another credential. The `connectionId` is an identifier, not a bearer token: every later use needs independent authorization.

The form URL is a temporary bearer capability for the intended person. A returned browser link works with current MCP clients. MCP URL-mode elicitation may improve clients that support it, but is optional ([MCP SDK documentation](https://ts.sdk.modelcontextprotocol.io/v2/servers/elicitation)). Form-link expiry is separate from credential expiry and revocation.

## Destination preflight and what the person sees

Keep the existing **preflight-before-link** behavior. Today `/api/session/create` calls `testDestination` by default for an `http_post` destination, sends `X-ZeroCreds-Preflight: true` and a `_zerocreds_preflight` marker, and refuses to create a form if the endpoint does not return 2xx. Existing HTTP callers can set `test_destination: false`; the current MCP tool does not expose that option. This probe catches reachability/auth failures, but **2xx alone does not prove a credential was stored**. Other current destinations are not probed. Do not describe them as verified.

For the ServerlessAgence OpenBao path, preflight is mandatory before issuing a form URL. Check `sys/capabilities-self` for create/update on the exact target; use the same authenticated writer and KV-v2 serialization as real submission, but write a synthetic canary to a unique **probe path inside the same owner policy scope**. Confirm OpenBao's version receipt and non-secret metadata, then remove the probe with a separately scoped cleanup capability. Never use a real credential or overwrite the user's existing connection for a probe. A failed or ambiguous probe blocks the form and returns a safe diagnostic to the agent; retries use the same idempotency key. Probe records must not trigger provider calls, notifications or a credential-ready event. The legacy HTTP opt-out need not be removed, but it does not apply to the trusted OpenBao path.

The form must show a **server-issued storage disclosure**, not agent-authored text:

| Displayed item | Source and meaning |
| --- | --- |
| Storage | “ServerlessAgence Wallet · OpenBao KV v2” with a non-secret path/namespace reference. Say “Cloudflare D1” only for form and connection metadata. |
| Wallet owner | Authenticated account/tenant and stable wallet identifier. A form link alone must not let another signed-in person claim this wallet. |
| Bound profile | The trusted profile identity that may later request use, plus the task/run reference if this form was opened from a run. The profile is not chosen by prompt text. |
| Version | OpenBao service release and KV-v2 credential version, clearly distinguished. Before first submission, say “credential version: not created yet”. Never expose writer/reader identities or tokens. |
| Preflight | “Storage checked” with time and a short receipt reference only after the OpenBao canary round trip succeeds. Do not claim that a later provider login is guaranteed. |
| Access and lifetime | Which trusted service can use the credential, requested scope, form-link expiry, credential retention/rotation policy, and whether an isolated runtime will see plaintext. |

Bind those display fields, destination and proposed form schema to one immutable, server-signed form manifest. Render the same manifest before submission and include its ID in the resulting receipt; reject any mismatch. If owner/profile cannot be verified, state that plainly and block persistent wallet submission rather than displaying “your wallet”. Do not infer ownership from the browser cookie used by today's optional “remember me” behavior. The present form only shows a generic destination type and has broad “AI never sees it” copy; that is insufficient evidence of wallet ownership or the later execution boundary.

## OpenBao custody and use boundary

Use separate OpenBao mounts/identities for sandbox and production, with owner-scoped paths such as `secret/data/owners/<immutable-owner-id>/connections/<connection-id>`. ZeroCreds may create/update only its authorized owner path and probe path, with no value read; the broker has a separately scoped read identity and only after run authorization. Keep the writer's probe-cleanup capability limited to probe paths. Define OpenBao seal/unseal, backups, audit devices, root-token recovery and credential rotation before production deployment. Use a **dedicated D1 database per environment** for non-secret form and connection metadata; never replicate the provider value there.

The form service uses its scoped OpenBao writer identity; the runner broker uses a separate reader identity. An agent never receives an OpenBao token/AppRole credential, arbitrary path selector, D1 binding or plaintext read tool. If ZeroCreds remains on Node, the D1 metadata operation goes through an authenticated application Worker API, not the administrative D1 REST API as an agent endpoint ([Cloudflare guidance](https://developers.cloudflare.com/d1/tutorials/build-an-api-to-access-d1/)). A customer-owned Vault-compatible backend is a later explicit option, with the same owner policy and disclosure.

The broker checks owner, connection state, run identity, provider, operation, resource and scope before each use. Prefer a scoped provider call or proxy so OpenCode sees only a result. A browser/password or CLI environment variable requires a separately reviewed executor and an explicit disclosure that its isolated runtime can see the value; generic intake alone does not enable that. Use and rotation create value-free audit records; revocation blocks new grants. Existing MCP host `credentialBindings` and runner policy remain the enforcement boundary for tool calls.

## Implementation order and acceptance

1. Keep the generic ZeroCreds MCP tools compatible. Add a trusted ServerlessAgence adapter that derives owner, profile and a named OpenBao destination server-side, accepts task-specific fields, runs mandatory OpenBao preflight and returns the human form URL. Disallow inline destination selection on this path, without breaking unrelated legacy clients.
2. Provision a sandbox OpenBao KV-v2 mount, separate writer/reader/probe-cleanup identities and audit devices. The compatible `vault` adapter now has an opt-in version receipt and synthetic write/metadata/cleanup preflight with local fixture tests; repeat against an isolated **real OpenBao** instance before claiming this step complete.
3. Implement dedicated D1 metadata schema/Worker for forms, one-time submission state, owner-bound connections, receipts and revocation. Connect ZeroCreds submission/status and verified storage disclosure to it. Bind a confirmed `connectionId` to existing Runner and Control Plane contracts without putting values in their task stores.
4. Add one reviewed, open-source credential-using MCP capability and broker policy; prove a real sandbox task. Define further executor methods after this vertical slice works.

Acceptance tests: task-driven fields and URL; missing/unreachable OpenBao blocks form creation; canary uses the real write path but creates no usable credential, provider call or notification; writer cannot read values, broker cannot write, probe cleanup cannot delete real connections; owner B cannot submit, observe or use owner A's connection; prompt cannot choose another destination/profile or alter the displayed manifest; form shows the correct owner, profile, OpenBao storage and version before and after submission; one-time submission and timeout reconciliation; D1 contains no provider value or OpenBao credential; no value in status/result/history/webhook; revocation denies new use; restart resumes form state; existing ZeroCreds session clients and Runner run/status/artifact tests pass. Public onboarding waits for the runner's existing isolation and billing gates.
