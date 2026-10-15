# ZeroCreds intake for ServerlessAgence runs

Status: design and implementation task [#67](https://github.com/Zerocreds-com/zerocreds-server/issues/67). This document is a contract for the next integration slice, **not a claim that the endpoints below are deployed**. It complements the [existing SAR credential architecture](https://github.com/servles-com/serverless-ai-agent-run/blob/main/docs/credential-passing-architecture-zerocreds-and-runs.md) and the [verifiable-form roadmap](trust-architecture-verifiable-forms-and-releases.md).

## Why this contract is needed

ServerlessAgence's sandbox developer API accepts a free-form prompt and an optional `model.connectionId`, then returns a stable run ID, result and artifacts. Today an operator registers the BYOK connection and stores its provider key in a Worker secret; the VM process receives that key. The [runner foundation](https://github.com/trained-assist/ai-agent-runner/blob/main/docs/DEVELOPER-API-FOUNDATION.md) explicitly treats this as trusted sandbox use, not public self-service or zero-access. A customer must eventually connect a provider without pasting its secret into the run request or the model conversation.

ZeroCreds is the **intake/write side**. It collects a value through a form or authenticated machine submission, writes it to a pre-approved destination and returns a non-secret handle and receipt. A **separate runner broker** owns vault read, authorization per run, short-lived grants, provider proxy and audit of use. ZeroCreds must not implement a generic plaintext read endpoint for the coding agent.

```text
Human / CLI ── secret ──► ZeroCreds ── write-only ──► owner-scoped vault
              ◄─ handle + signed receipt ──────────┘

Client ── connectionId + prompt ──► Runner API ──► runner broker ──► provider
            (no raw secret)             │            (owner/run/action policy)
                                       └──► OpenCode process on VM
```

The value can still be visible to the trusted runner/VM in the current hosted BYOK mode. Only a broker-side provider proxy or customer-owned gateway can keep it out of the agent process. ZeroCreds write-only storage alone does not establish that guarantee. The explicit list of credential-using executors, their allowed operations and audit fields belongs to the runner; see [runner issue #360](https://github.com/trained-assist/ai-agent-runner/issues/360) and [registry PR #362](https://github.com/trained-assist/ai-agent-runner/pull/362). ZeroCreds itself does not authorize an OpenCode tool or a Playwright script to read a stored value.

## Ownership and storage contract

| Data | Owner / storage | Must not contain |
| --- | --- | --- |
| `form_id`, expiry, field schema, destination reference, manifest/receipt metadata | ZeroCreds session store | provider value, vault writer token in responses |
| Raw provider credential | Approved owner-scoped Secret Manager/OpenBao/Vault destination | model prompt, run JSON, status, receipt, webhook, logs |
| `cred:<owner>/<name>` handle | ZeroCreds response and runner connection mapping | credential value or sufficient information to bypass authorization |
| `connectionId` and capability policy | Runner tenant/project connection registry | raw credential |
| Per-run grant and provider-use audit | Runner broker | prompt, full provider response, raw credential |

An owner is an immutable authenticated integrator/tenant identity, not a browser cookie, display name or user-supplied `owner` field. The runner maps a ZeroCreds handle to its own stable `connectionId`; the handle is an identifier, **not a bearer credential**. Existing developer requests with `model.connectionId` remain valid. A new secret version rotates the value behind the same logical connection; it must not silently transfer ownership or widen permissions.

For production, the destination is a **named, approved, owner-bound** entry. Its configured write identity can create/update only a restricted path such as `secret/data/tenants/<immutable-tenant-id>/connections/<connection-id>`; the runner broker has a separate read identity for that tenant's path. The concrete path is operator-configured, not accepted from the form requester. Sandbox/dev may retain explicit inline destinations, but production must reject them. Use separate vault mounts/projects and identities for sandbox and production. Write-only permission must be enforced by the destination IAM/policy, not a ZeroCreds UI label.

If a customer chooses its own vault, its operator registers a destination and narrowly scoped writer identity. The receipt names the destination and target resource **without** exposing auth material. A customer-owned runner/gateway may instead consume the secret entirely in the customer's environment. Google Cloud Workload Identity Federation, AWS STS or an equivalent provider mechanism should replace stored long-lived cloud keys when a supported trust relationship is available; otherwise describe the storage and reader boundary honestly.

## API shape and lifecycle

Build on [Z9 #63 / PR #65](https://github.com/Zerocreds-com/zerocreds-server/pull/65) rather than adding a parallel form API. Field names below are conceptual until that PR settles.

1. Authenticated client requests a form specification for `name`, `kind`, `provider`, requested capability and a **registered destination reference**. ZeroCreds derives `owner` from the authenticated identity, validates the destination binding and returns `form_id`, human URL, machine submit URL, expiry, signed manifest and one-time submission authority. No secret is in this response.
2. Human or machine submits the value to ZeroCreds. Both paths validate the same form schema, owner/destination/manifest binding and one-time state. A successful write returns a signed receipt containing handle, manifest ID, destination reference, owner, field **names**, secret version/evidence, time and submission mode. It contains no field values. A storage failure leaves the session retryable or explicitly failed; it never reports `done`.
3. The client registers the handle against its runner `connectionId` through a trusted server-to-server operation. Runner verifies the owner and expected provider/capability before activating it. ZeroCreds status can report `pending`, `done`, `expired` or `failed`, but cannot reveal the value.
4. Rotation creates a new value/version under the same owner and logical handle. Revocation disables new runner grants and, where possible, provider tokens. ZeroCreds must expose a non-secret status/receipt event the runner can consume; it does not independently authorize continued provider use.
5. A run passes only `connectionId`. The runner broker checks tenant, project, principal, run ID, provider, operation, resource, budget and active connection status. It then calls the provider through a trusted gateway or gives the isolated run a narrowly scoped, short-lived credential where supported. The agent cannot choose a vault path or secret name from its prompt.

The form URL and one-time submit token are sensitive capabilities until used/expired. Do not place them in public logs or return them to an unrelated tenant. The signed receipt proves what ZeroCreds says it wrote; it does not prove that a later runner grant had the right scope or that a provider call was safe.

## Provider profiles

- **Model API key:** the form stores a customer provider key in the customer's designated vault namespace. The runner uses its existing `connectionId` shape. In the first hosted mode, explicitly label the key as readable by the trusted runner/VM. Broker proxy is the target for keeping raw values out of OpenCode; model usage and spend remain attributable to the customer and run.
- **GitHub:** prefer an installed GitHub App with selected repositories and minimum permissions. The App private key belongs to a trusted broker/publisher. Create short-lived installation tokens just before repository read or branch/PR publication; do not inject a broad write PAT into OpenCode. The current legacy GitHub PAT form remains a compatibility path, not the recommended onboarding for this integration.
- **Customer cloud:** use workload federation/STS and resource-bound roles when available. If a long-lived credential is unavoidable, store it in the approved customer vault and make the trust boundary explicit. The ZeroCreds intake service must not gain read access merely to help the runner execute.

GitHub supports installation tokens scoped to selected repositories and permissions, expiring after one hour ([GitHub documentation](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)). Google recommends Workload Identity Federation and immutable attribute/audience checks ([Google Cloud guidance](https://docs.cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation)). OAuth token exchange defines audience/scope/actor terminology but does not automatically revoke exchanged tokens ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html)); follow the current [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html).

## Security and compatibility gates

- Production refuses inline destination objects, arbitrary URLs/paths and cross-owner named destinations. A second tenant cannot infer that a foreign handle or destination exists; responses are indistinguishable from an unknown resource.
- The displayed manifest and submitted manifest ID bind **exactly** the owner, field schema, destination, request template and release identity. Changing any after display fails. Do not claim this property complete before [Z1 #52](https://github.com/Zerocreds-com/zerocreds-server/issues/52) is implemented and tested.
- Intake credentials and destination writer credentials never appear in API responses, status, receipts, form HTML after submission, debug logs, error text or test snapshots. Validation errors must not echo a raw upstream response. Secret Manager guidance recommends least privilege and warns that process environment/debug output can expose secrets ([Google Cloud](https://docs.cloud.google.com/secret-manager/docs/best-practices)).
- One-time submission and machine/human paths have the same ownership and destination policy. Duplicate submit cannot create a second provider secret version; storage timeout has an explicit unknown/reconciliation path, not a blind retry.
- Revoked/expired connections block **new** runner grants. Use an independent runner audit for every grant/use. Do not equate form-link TTL with lifetime of a stored provider credential.
- The ZeroCreds change must not alter existing `/api/session/create`, `/f/{token}`, status or current destinations for established clients. The runner's legacy Control Plane and developer status/result/artifact contracts remain unchanged.
- Public runs remain blocked while the runner VM reports `isolation=none`; scoped credentials do not substitute for a per-run OS/container/VM boundary, resource limits and cross-tenant negative tests.

Suggested tests for the implementation: owner A creates a named destination and gets a signed non-secret receipt; owner B cannot target or observe it; attempted manifest/destination substitution fails; human/machine double submit writes once; failed destination write never yields `done`; rotation preserves owner and handle while changing version; revoked connection blocks runner renewal; canary secret is absent from response/log/history/webhook; existing session tests and runner canaries still pass.

## Delivery order

1. Land the in-flight hardening [#50 / PR #64](https://github.com/Zerocreds-com/zerocreds-server/pull/64) and form API [#63 / PR #65](https://github.com/Zerocreds-com/zerocreds-server/pull/65), without weakening their destination checks.
2. Add owner-bound destination registration and form/receipt fields required above; implement OpenBao/Vault policy templates and negative tests. Tie each receipt to a confirmed write.
3. Add the runner-side handle-to-`connectionId` adapter and per-run broker/proxy in the runner repository. Preserve current sandbox BYOK until migration is proven.
4. Run a bounded sandbox end-to-end test for managed and BYOK model use, GitHub publication, revocation and cross-tenant denial, plus the legacy runner canary. Enable public onboarding only after runner isolation, billing and artifact retention gates pass.
