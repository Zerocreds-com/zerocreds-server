# ZeroCreds product audit: scenarios and gaps

Date: 2026-10-20. Baseline: `main` after PR #138, commit `3ae313c9c920bb52e4cc73b6451ab3edaad98c36`. The review covered discovery → collection → waiting → storage → verification → use → rotation → revocation → recovery. It combined code and test review with synthetic HTTP scenarios on temporary local servers. It used no real secrets, Keychain items, or external APIs. This is a first product pass, not a comprehensive security audit.

The original pass found nine reproduced defects (F01–F09), four code-confirmed gaps (F10–F13), one observed agent scenario (F14), and three follow-up questions. P1 means data loss, false success, or a blocked core journey; P2 means a recoverable dead end or unclear contract. These are product priorities, not vulnerability ratings.

After the first pass, the working branch fixed F01, F04, F05, and F09 in the probes. F13 was addressed for failed completion-marker writes, local catalog updates, and a failure after the first successful write to multiple destinations. An ambiguous outcome on the **first external POST** remained: without an idempotency contract, the server cannot prove whether the recipient stored the value before failing. The OpenCode subscription reconnects after stream loss, but restoring the host session after a restart and resuming in other clients still need integration. The findings below record the original baseline, so compare against current code before treating one as open.

## User promise

“Grant the agent the required access once, and let it finish the task. If access already exists, use it. If something fails, recover without asking for the secret again whenever technically possible.” Storage success, provider token acceptance, and authorization for a specific operation are distinct results. Users should not need to understand JSON field names, storage internals, SSE wiring, or MCP version differences.

## Scenario matrix

| ID | User situation | Completion criterion | Baseline gap |
|---|---|---|---|
| S01 | Access already exists on the Mac | Find and use the Keychain item through an available authorized path | Discovery has metadata, but no shipped local bind/use path (F11) |
| S02 | Access is missing | Show a concise, disclosed form for the right secret | Forms exist; field roles were incomplete |
| S03 | User chooses a familiar field name | Custom names do not break later operations | Partial token-field mapping (F02, F06) |
| S04 | User opens a form | Agent subscribes by default and resumes the original task on completion | Only local OpenCode integration (F09, F10) |
| S05 | User submits before subscription | Stored terminal state triggers exactly one continuation | SSE mishandled claimed state (F09) |
| S06 | Form is submitted | Done only after every value is stored with a durable receipt | Missing route and marker failures (F01, F13) |
| S07 | Saved credential must work on repo X | Check account, resource, operation, and perform an authorized action | No unified task readiness or local use (F11, F12) |
| S08 | Personal and work accounts coexist | Stable connection ID and verified identity | Case-colliding aliases (F03) |
| S09 | Token expires | Rotate the selected connection without losing mappings or a working version | Implicit overwrite (F02) |
| S10 | Agent made a form mistake | Correct or replace an unsubmitted form explicitly | Old schema silently reused (F07) |
| S11 | Two agents work concurrently | Catalog writes and uses respect current version | Slow verification overwrites newer metadata (F04) |
| S12 | Network or process dies after Submit | Distinguish pending, processing, saved, and unknown; reconcile | Stale claim becomes expired (F05, F13) |
| S13 | Show saved connections | Show identity, purpose, mapping, freshness, readiness | Mapping hidden; wallet lookup needs known ID (F06, F11) |
| S14 | Revoke access | Explain use disablement, storage deletion, and provider revocation separately | Local lifecycle incomplete (F11) |
| S15 | Resume waiting after restart | Restore binding, subscription, and terminal state | Host memory only (F10) |
| S16 | Keep working after an update | Report actual runtime capabilities and compatibility | Git HEAD can differ from loaded local code (F10) |
| S17 | Create a PR and run CI with multiple access paths | After one authorization fails, try a verified alternate path | Local workflow dispatch failed, but connected GitHub created draft PR #170 and PR-triggered CI (F14) |

## Default credential-ready waiting requirement

The user clarified on 2026-10-20 that waiting should be on by default and the agent should resume the original task immediately after the form is filled. An SSE endpoint alone does not fulfill this promise. Proposed contract, not fully implemented at audit time:

- `wait_mode: auto | event | poll | none`, default `auto`. The host binds form ID to a task/session/run before showing the link; create returns promptly.
- Return truthful `waiting`, `resume_armed`, `wait_transport`, and `expires_at`. Do not promise auto-resume when the host cannot resume. Auto uses host events or polling where supported and reports unsupported hosts explicitly.
- Persisted status is authoritative; an event only prompts reconciliation. No credential value enters the event or resume prompt.
- Host persists the binding, reconnects with backoff, and checks status after reconnect. Handle early submit, duplicate events, server restart, and host restart.
- Deduplicate by form ID, task reference, and terminal version. Never replay an already completed external mutation automatically.
- Distinguish ready, expired, canceled/revoked, and failed/needs-attention. Waiting expiry, form-link expiry, and credential expiry are separate.
- For multiple forms, resume only after all task requirements are met. After readiness, verify the receipt/reference and continue the original authorized task.

Acceptance covers normal and early submission, subscription during write, SSE loss, server/host restart, duplicate events, multiple forms, cancellation, expiration, and unsupported hosts. Test from form creation through resumption of a concrete task, not merely SSE delivery.

## Reproduced findings

Run `node scripts/audit-product-scenarios.cjs` to reproduce using temporary directories, synthetic values, and an injected verifier. The probe does not call Keychain or real providers. Local metadata uses a local-file destination because the catalog-write defect is shared.

### F01 · P1 · Done without a stored value

A required field without a level and a `destinations_by_level` map containing only `secret` produced create 200 → submit 200 → status done, with no output file. The missing route in `submitPending()` was skipped. Validate complete routing before issuing a link; never report done when a required value was omitted. Multi-destination writes also need partial-outcome tracking.

### F02 · P1 · Rotation loses a saved field alias

Replacing `github/work` after saving `token_field: custom_pat` preserved the connection ID but dropped the mapping. Local submit built a new entry rather than transferring versioned role metadata. Rotation should select a connection ID, preserve only mappings compatible with the new schema, explicitly report `mapping_required` otherwise, and reset stale identity/scope evidence.

### F03 · P1 · Case variants create ambiguous connections

Saving `github/work` and `GitHub/Work` created two entries. Reads and verification lowercased strings and selected the first match, while writes compared exact strings. Canonicalize providers, define alias case semantics, enforce identity uniqueness, and reveal conflicts during migration instead of blindly deleting duplicates.

### F04 · P1 · Slow verification rolls back a newer change

Verification A read the catalog and paused; verification B saved `token_field: replacement`; A completed and wrote its stale catalog array. Atomic file rename prevents corruption but not lost updates. Patch a selected connection with optimistic version checks or use transactional storage. Validate the same boundary for concurrent submit and use metadata.

### F05 · P1 · Crash during Submit makes a link disappear

A crash after pending → claimed caused the sweeper to delete an ordinary form's stale claim. Status became expired before the form TTL. Track durable processing/write outcomes and reconcile; simply restoring pending is unsafe if an external write may already have succeeded.

### F06 · P2 · Saved mapping is invisible in connection list

The catalog stored `token_field`, but `/api/local/connections` omitted it. Return safe role-to-field mapping metadata with source/version, never values, so a later agent can explain and reuse the configuration.

### F07 · P1 · Corrected form reuses the old schema

An integrator created a form with `old_field`, then requested `token` for the same uid/service. Both calls returned 200; the second reused the first token and retained `old_field`. Deterministic reuse ignored field schema, destination, and purpose; MCP also hid `reused`. Fingerprint meaningful specifications and either return the identical form or explicitly conflict/replace it under a defined policy.

### F08 · P2 · Large discovery suggests an impossible preview search

One source/category with 201 candidates returned HTTP 413 and advised searching a preview that had not been created. Persist the complete preview, page it with query/cursor, and separate the catalog-selection limit from inventory size. Recovery guidance must name an action the user can actually take.

### F09 · P1 · Subscribing during save yields false expiration

For a claimed form, status returned pending while events returned `expired` and closed. OpenCode did not reconnect. Use one state resolver for status and SSE, distinguish processing from expiration, and wait for a terminal outcome.

## Code-confirmed gaps

### F10 · P1 · No universal default waiting or durable host resume

The OpenCode plugin responded to `form_create`, subscribed to loopback SSE, and called `session.promptAsync` on done. That did not cover wallet forms or other hosts. It stored active bindings in memory and did not originally reconnect. MCP notifications alone cannot prove that a host will resume an agent. Apply the waiting contract above and verify each host separately.

### F11 · P1 · Discovery, collection, and use were separate paths

Discovery and active local connections used different catalogs. Shipped MCP lacked a bind operation, local API use, and local revoke/rotate. Wallet status required a known connection ID without wallet search. Uncommitted local checkout work was not counted as shipped. Define a common connection/reference contract and environment-specific collect, discover, bind, verify, use, rotate, and revoke capabilities. A provider with a form is not thereby fully supported.

### F12 · P1 · Valid token does not imply task readiness

GitHub verification checked `/user` and scopes; Cloudflare checked a user-token endpoint. Neither established permission for a specific repo, account, or operation. Report readiness as satisfied/denied/unknown for provider identity, resource, and action, with evidence source/time. Unknown permissions should not trigger a request for a broader token automatically.

### F13 · P1 · Storage success and durable confirmation diverged

Ordinary submit originally dropped the claim before writing `.done`, suppressed marker-write errors, then returned 200 and emitted done. After restart, status could report expired despite a stored secret. Partial multi-destination writes were ambiguous. Durable receipts, write-outcome records, and reconciliation are needed; never require re-entering a value merely to check whether it was saved.

### F14 · P1 · One access failure blocks a reachable task

In a real `gpt-mem/opencode-mem` scenario, local `gh workflow run test.yml` returned HTTP 403, while push worked. The agent kept examining that PAT and local Bun. Connected GitHub created draft PR #170, and `pull_request` triggered CI. Hash-only comparison showed the local `gh` token differed from two named Keychain PATs; their exact permissions were not established. A failed workflow dispatch proves only that operation was denied for that authorization. ZeroCreds should help find and map Keychain items without limiting ordinary Keychain use. The host should identify available authorizations, verify identity and target access, and try an authorized alternate path. PR-triggered CI does not imply manual dispatch permission.

## Follow-up investigations

1. **Wallet grant semantics:** A trusted machine caller receives fields and expiry. `vaultRead()` logs a grant but does not consume the value or make `run_id` unique. Define whether one-time means per assertion, run, or connection; verify TTL, cleanup, and runner redaction. A server expiry cannot retract plaintext already delivered to a trusted host.
2. **Crash between custody write and journal/metadata completion:** Wallet `.written` and digest help retries, but fault-inject immediately after storage write and before `.written`, including across container restart. Confirm the actual durable sandbox and production backends; docs contained both historical OpenBao and newer D1 custody designs.
3. **Release/runtime map:** A Mac checkout ran server and MCP with uncommitted code. `/version` reported git HEAD, not a hash of loaded sources. Verify main capability/version handshake, isolated local release installation, and rollback without losing subscriptions or metadata; inspect existing local runtime diagnostics before duplicating them.

Original proposed order: eliminate false success and state loss (F01, F04, F05, F13); complete default waiting (F09, F10) in one host before expanding; repair connection lifecycle (F02, F03, F06, F07); join inventory → bind → task readiness → use → local revoke (F11, F12, F14), then discovery pagination (F08). Accept full user journeys and recovery outcomes, not merely endpoint 200s. The probe documents observations, not desired-behavior regression tests; findings were not individually published as GitHub issues.
