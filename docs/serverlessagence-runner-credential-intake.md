# ServerlessAgence: credential forms through MCP

Status: architecture decision for [ZeroCreds #67](https://github.com/Zerocreds-com/zerocreds-server/issues/67), **not an implemented end-to-end path**. The current ZeroCreds server stores pending forms in local files, not D1. Do not claim D1 custody or agent-side credential use is live before a sandbox test proves it.

## Decision

An agent asks a **generic ZeroCreds MCP tool** to prepare fields for its task. The tool returns a short-lived form URL. The person enters credentials in the browser; neither the model nor an MCP result receives the values. Store submitted credentials as **application-encrypted ciphertext in a dedicated Cloudflare D1 credential database**. D1 also stores non-secret form, owner, connection, version and lifecycle metadata. Do not create a GitHub-specific API, local OpenCode command, or Durable Object for this flow.

A stable `connectionId` points to an owner-bound credential record. A runner or trusted MCP capability can use it only after owner, run and operation authorization. The exact list and names of credential-using open-source MCP methods are deferred until their implementations and policies are reviewed. Creating a form is not permission to execute arbitrary code with its secret.

### Why D1, rather than a Vault server?

“Vault” previously referred to a possible **OpenBao/HashiCorp Vault server**, not to a Cloudflare product or something already deployed. OpenBao KV v2 supplies secret versions and path-scoped ACLs, and OpenBao has audit devices. It also requires a separately operated stateful service, authentication and unseal, backups, monitoring and availability planning ([KV v2](https://openbao.org/docs/secrets/kv/kv-v2/), [storage operations](https://openbao.org/docs/configuration/storage/), [audit](https://openbao.org/docs/audit/)). ZeroCreds already has a `vault` destination adapter, but that does not mean a production OpenBao cluster or per-owner policies exist.

D1 is the ServerlessAgence **initial default** because it fits the existing Cloudflare control plane and avoids a new always-on service. This is an operational choice, not a claim that SQL rows are a ready-made vault: we must build and test envelope encryption, key rotation/recovery, per-owner authorization, audit, versioning and a broker. D1's platform encryption at rest is not a substitute for these application controls. If those controls cannot pass the sandbox security tests, do not ship the D1 wallet; use an operated OpenBao service instead. Keep the `connectionId` and storage adapter stable so the backend can change without changing the MCP or Runner contract.

Cloudflare Secrets Store is another product, separate from D1 and OpenBao. Its current open beta supports at most 100 production secrets per account and is designed around secrets bound to Cloudflare services, so it is unsuitable as the default per-user credential wallet ([Cloudflare documentation](https://developers.cloudflare.com/secrets-store/manage-secrets/)). It can hold a small number of service-level keys, subject to its access rules.

```text
OpenCode agent -- intent + proposed fields --> trusted ZeroCreds MCP adapter
                                              | derives owner + destination
                                              v
                                      ZeroCreds form API -- URL --> person
                                              ^                    |
                                              |              browser submission
                                              |                    v
                                      credential Worker -- encrypt --> dedicated D1
                                              |
agent <-- status + opaque connectionId -------+

Later: authorized run/tool --> broker --> decrypt for narrowly scoped use
       (never return the value in a tool result, prompt, status or log)
```

## Existing behavior and gap

[`mcp/index.js`](../mcp/index.js) already exposes `zerocreds_create_session` with `title`, `description`, `fields[]`, `destination` and `ttl_minutes`, plus `zerocreds_check_status`. The first returns `token`, `url`, `expires_at`; the second reports status. [`server/src/server.js`](../server/src/server.js) persists pending sessions under `ZEROCREDS_PENDING_DIR`, and [`server/src/destinations.js`](../server/src/destinations.js) writes to the selected destination. The raw MCP signature is unsuitable for production agent use because it accepts agent-chosen and inline destinations; the form lifecycle is not backed by D1. Keep existing clients compatible while a trusted ServerlessAgence adapter narrows the inputs.

The Runner developer API already has `model.connectionId` and stable run/status/result/artifact contracts. Keep these compatible. The Control Plane has a D1-backed credential-ready wait for task continuation: it stores the **requirement and readiness reference, never the credential value** ([contract](https://github.com/trained-assist/trained-assist-control-plane/blob/main/docs/CREDENTIAL-READY-V1.md)). Its task-store database must not be reused as the credential database.

## Form request and ownership

The agent supplies task intent and a proposed schema: service, purpose, field names, display labels, sensitivity and requested capability. The same tool handles GitHub, a model API key, a cloud token or a website login. The trusted adapter authenticates the actual user/tenant and binds `ownerId`, task/run ID and a **server-selected destination**. The prompt cannot select an owner or destination. The adapter validates field count, types, names and text length, applies a short form TTL and presents the requested purpose to the person. It returns only `formId`, `url`, `expiresAt` and a non-secret status reference.

Browser submission consumes the form once and checks its immutable owner, schema, purpose, destination and expiry. Only a confirmed encrypted D1 write returns a non-secret receipt and opaque `connectionId`. A failed write never reports `done`; a timed-out retry reconciles the same form/version instead of creating another credential. The `connectionId` is an identifier, not a bearer token: every later use needs independent authorization.

The form URL is a temporary bearer capability for the intended person. A returned browser link works with current MCP clients. MCP URL-mode elicitation may improve clients that support it, but is optional ([MCP SDK documentation](https://ts.sdk.modelcontextprotocol.io/v2/servers/elicitation)). Form-link expiry is separate from credential expiry and revocation.

## Destination preflight and what the person sees

Keep the existing **preflight-before-link** behavior. Today `/api/session/create` calls `testDestination` by default for an `http_post` destination, sends `X-ZeroCreds-Preflight: true` and a `_zerocreds_preflight` marker, and refuses to create a form if the endpoint does not return 2xx. Existing HTTP callers can set `test_destination: false`; the current MCP tool does not expose that option. This probe catches reachability/auth failures, but **2xx alone does not prove a credential was stored**. Other current destinations are not probed. Do not describe them as verified.

For the ServerlessAgence D1 wallet, preflight is mandatory before issuing a form URL. Route it through the same authenticated credential Worker and serialization/validation path used by a real submission. Write a synthetic, uniquely identified canary with the proposed field structure, confirm its committed version/receipt and read back its non-secret metadata, then delete or expire that canary. Never use a real credential or overwrite the user's existing connection for a probe. A failed or ambiguous probe blocks the form and returns a safe diagnostic to the agent; retries use the same idempotency key. Probe records must not trigger provider calls, notifications or a credential-ready event. The legacy HTTP opt-out need not be removed, but it does not apply to the trusted D1 wallet path.

The form must show a **server-issued storage disclosure**, not agent-authored text:

| Displayed item | Source and meaning |
| --- | --- |
| Storage | “ServerlessAgence Wallet · Cloudflare D1”, or the actual external destination type. Use “OpenBao” or “HashiCorp Vault” only when that actual product stores the value. |
| Wallet owner | Authenticated account/tenant and stable wallet identifier. A form link alone must not let another signed-in person claim this wallet. |
| Bound profile | The trusted profile identity that may later request use, plus the task/run reference if this form was opened from a run. The profile is not chosen by prompt text. |
| Version | Vault service release/schema version and current credential version, clearly distinguished. Before first submission, say “credential version: not created yet”. Never expose encryption-key material. |
| Preflight | “Storage checked” with time and a short receipt reference only after the D1 canary round trip succeeds. Do not claim that a later provider login is guaranteed. |
| Access and lifetime | Which trusted service can use the credential, requested scope, form-link expiry, credential retention/rotation policy, and whether an isolated runtime will see plaintext. |

Bind those display fields, destination and proposed form schema to one immutable, server-signed form manifest. Render the same manifest before submission and include its ID in the resulting receipt; reject any mismatch. If owner/profile cannot be verified, state that plainly and block persistent wallet submission rather than displaying “your wallet”. Do not infer ownership from the browser cookie used by today's optional “remember me” behavior. The present form only shows a generic destination type and has broad “AI never sees it” copy; that is insufficient evidence of wallet ownership or the later execution boundary.

## D1 custody and use boundary

Use a **dedicated D1 database per environment** for credential metadata and ciphertext. Encrypt inside the credential Worker before writing with authenticated encryption such as AES-GCM, a fresh nonce per version, associated data binding immutable owner/connection/version, and a versioned key in a Worker secret or managed KMS. D1 already encrypts its physical storage, but that does not replace application encryption when database readers must not see plaintext ([Cloudflare D1 data security](https://developers.cloudflare.com/d1/reference/data-security/)). Never place the encryption key in D1, source, run JSON, logs or model context. Define key rotation and recovery before production migration.

The form service writes through a scoped internal API; the runner broker receives narrowly scoped read/use access. An agent never receives a D1 binding, D1 API token, SQL endpoint, encryption key or plaintext read tool. If ZeroCreds remains on Node, it calls an authenticated credential Worker API, not the administrative D1 REST API as an agent endpoint ([Cloudflare guidance](https://developers.cloudflare.com/d1/tutorials/build-an-api-to-access-d1/)). For customer-owned storage, a later destination adapter may replace D1 by explicit owner choice and equivalent policy; D1 is the ServerlessAgence default.

The broker checks owner, connection state, run identity, provider, operation, resource and scope before each use. Prefer a scoped provider call or proxy so OpenCode sees only a result. A browser/password or CLI environment variable requires a separately reviewed executor and an explicit disclosure that its isolated runtime can see the value; generic intake alone does not enable that. Use and rotation create value-free audit records; revocation blocks new grants. Existing MCP host `credentialBindings` and runner policy remain the enforcement boundary for tool calls.

## Implementation order and acceptance

1. Keep the generic ZeroCreds MCP tools compatible. Add a trusted ServerlessAgence adapter that derives owner, profile and destination server-side, accepts task-specific fields, runs mandatory D1 preflight and returns the human form URL. Disallow inline destination selection on this path, without breaking unrelated legacy clients.
2. Implement dedicated D1 schema and credential Worker: forms, synthetic preflight canaries, one-time submission state, encrypted versions, owner-bound connections, receipts, revocation and audit. Do not implicitly migrate live secrets. Separate sandbox and production databases and keys.
3. Connect ZeroCreds submission/status and verified storage disclosure to that Worker. Bind a confirmed `connectionId` to the existing Runner contract and Control Plane credential-ready continuation without putting values in either task store.
4. Add one reviewed, open-source credential-using MCP capability and broker policy; prove a real sandbox task. Define further executor methods after this vertical slice works.

Acceptance tests: task-driven fields and URL; missing/unreachable D1 blocks form creation; canary uses the real write path but creates no usable credential, provider call or notification; owner B cannot submit, observe or use owner A's connection; prompt cannot choose another destination/profile or alter the displayed manifest; form shows the correct owner, profile, storage and version before and after submission; one-time submission and timeout reconciliation; D1 row contains ciphertext only; wrong key/owner/version cannot decrypt; no value in status/result/history/webhook; revocation denies new use; restart resumes form state; existing ZeroCreds session clients and Runner run/status/artifact tests pass. Public onboarding waits for the runner's existing isolation and billing gates.
