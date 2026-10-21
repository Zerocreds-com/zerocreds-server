# ZeroCreds integration plan for the Trained Assist agent

> Historical plan dated 2026-10-19. Its issue and deployment statuses are snapshots, not current release guarantees. Related ZeroCreds issues: #67, #91, #71, #72, #125. MCP Host PRs: #41, #42, #57. The Connected Apps prototype was retired in Ladder commit `978e510` in favor of the ZeroCreds wallet.

## Goal and architecture

A Trained Assist agent running in Runner, OpenCode VM, or MCP Host requests credentials such as GitHub PATs, Cloudflare tokens, and AWS keys through a user-facing form. A browser submission writes the value to owner/profile-scoped OpenBao KV v2 and safe connection metadata to D1. A later isolated run uses a broker with run-scoped identity to perform a narrow provider operation and receives only the result. The model, agent context, logs, and artifacts should never receive the raw secret. A `connectionId` is an opaque reference, not a bearer token.

## State recorded on 2026-10-19

| Component | Available then | Missing then |
|---|---|---|
| ZeroCreds sandbox API | Container, ephemeral OpenBao, D1 Worker at `zerocreds-wallet-api-sandbox.skillset-apply.workers.dev` | Production OpenBao and Worker, TLS, backup, unseal, audit |
| ZeroCreds MCP | Four wallet tools in `mcp/provider.js`; assertion verifier | Published `@zerocreds/mcp/provider@0.2.0` and pinned host-catalog digest |
| MCP Host | Composed wallet provider for authorized users; Ed25519 binding assertions | Production issuer keys, profile mapping, and caller audiences |
| Cloudflare Runner API | Control plane, RunCoordinator, VM worker, environment allowlist | `credentialBindings` returned 422 `FEATURE_UNSUPPORTED`; no profile workspace or ingress manifest |
| VM worker | EU VM2, per-run Unix identity, GCS storage, `setpriv --clear-groups` | Binding-to-process or binding-to-MCP delivery |
| Ladder | Owner/profile identity mapping and Connected Apps handoff | Wallet connection UI, owner-authorized list, rotation |
| Local Mac | Local proxy, 13 MCP tools, `mac-keychain` destination, explicit Saved to confirmation | Local GitHub operations bridge (#125) |

## Phase 0: production custody prerequisites

| ID | Work | Acceptance condition |
|---|---|---|
| Z0.1 | Merge hardened forms PR #71 and audit legacy integrators | Named destinations and admin token active; old keys reviewed and rotated |
| Z0.2 | Merge D1 wallet metadata PR #72 | Sandbox and production D1 migration `0002_assertion_replay.sql` applied |
| Z0.3 | Provision production OpenBao | TLS, owner-scoped KV v2, narrow writer/probe/reader identities, audit, backup, unseal runbook, monitoring |
| Z0.4 | Deploy production wallet Worker | Production OpenBao mount and `WALLET_SERVICE_TOKEN`; issuer/profile mapping; replay guard and cleanup validated |
| Z0.5 | Publish pinned MCP provider | Immutable commit/digest in host catalog; wallet tools available |
| Z0.6 | Configure issuer keys and profile mapping | Separate sandbox/production mappings and documented rotation |

The original blockers were OpenBao operations, approximately 340 unfinished anonymous sessions in 30 days, and a manual audit of ten legacy integrators.

## Phase 1: Runner binding delivery

| ID | Work | Acceptance condition |
|---|---|---|
| R1.1 | Support `credentialBindings` in the Cloudflare Runner API (`run-coordinator.ts`) | POST `/v1/runs` accepts scope and binding reference and forwards them to `LaunchRequest` |
| R1.2 | Add `profileWorkspace` | Workspace is attached to the run; its D1 traces remain separate from wallet D1 |
| R1.3 | Map wallet `connectionId` to a `wallet_connection` binding | Provider, scope, and reference reach VM worker |
| R1.4 | Deliver value to the engine process | `GITHUB_TOKEN`, `CF_API_TOKEN`, etc. appear only in the OpenCode process environment, never in logs |
| R1.5 | Authorize owner, profile, and scope | Foreign connection IDs return 403; only authorized scopes are delivered |

The original Phase 1 proposal used process environment variables for CLI compatibility (`gh`, `git`, `cf`, `aws`, `gcloud`). Phase 2 narrows use through a broker. This is a historical design proposal, not a claim that process environment delivery is the current product behavior.

## Phase 2: value-free credential-use broker

| ID | Work | Acceptance condition |
|---|---|---|
| B2.1 | Specify a narrow provider capability, starting with GitHub | Inputs include connection ID, operation, resource, parameters; output and audit fields contain no secret |
| B2.2 | Implement a separate broker Worker/service with OpenBao reader identity | `POST /broker/use` performs one approved API call and writes a value-free D1 audit record |
| B2.3 | Expose an MCP wrapper with run authorization | Agent calls an allowed operation and receives only the result |
| B2.4 | Add per-run broker URL and scoped token to Runner binding | Outside the run, broker access returns 403 |
| B2.5 | Sandbox end-to-end test | Create form, submit token, confirm status, run broker operation, and verify no secret in status/history/artifacts |

Candidate operations included `github.create_pull_request`, `github.dispatch_workflow`, `cloudflare.list_zones`, and a narrowly scoped AWS operation. The original spec target was `docs/BROKER-CAPABILITY-SPEC.md`.

## Phase 3: production hardening and onboarding

| ID | Work | Acceptance condition |
|---|---|---|
| H3.1 | Migrate operators and legacy integrators | No anonymous sessions; destination and key policy reviewed |
| H3.2 | Owner-authorized list, revoke, and rotate | Old connection no longer works; safe rotation preserves intended identity |
| H3.3 | Retention and cleanup | Expired/revoked OpenBao versions and D1 rows obey retention policy |
| H3.4 | Structured observability | Owner/profile/connection/operation/outcome metadata without values; health alerts |
| H3.5 | MCP Host rollback flag | Disable wallet provider in under one minute; preserve connections for re-enable |

## Phase 4: parallel local Mac bridge (#125)

| ID | Work | Acceptance condition |
|---|---|---|
| L4.1 | GitHub CLI destination in macOS Keychain | `gh auth status` and `git push` work for resolved login |
| L4.2 | Local safe GitHub operation tool | Read Keychain locally, perform a narrow operation, return only the result |
| L4.3 | Value-free local audit log | Record owner/profile, connection ID, operation, time, and outcome |

The dependency path was Z0 → R1/B2 in parallel → H3, with L4 parallel to production work. Principal risks were production OpenBao readiness, legacy integrator migration, Runner API contract changes, competing custody paths, broker leakage, and issuer-key rotation. Mitigations included staging OpenBao, a bounded migration window, narrow environment delivery as an interim option, retaining the Ladder handoff, value-free automated tests, and `kid`-based key rotation with replay protection.

Original effort estimate: Z0 4–6, R1 3–4, B2 4–5, H3 2–3, L4 1–2 engineer-weeks, totaling 14–20. Readiness required sandbox and production end-to-end runs, local bridge smoke, rapid rollback, and a custody-boundary security audit. The named area owner was `vova` across ZeroCreds, MCP Host, Runner, Ladder, and the local bridge. Track any new work in current issues and PRs; do not treat this 2026-10-19 list as an active schedule.
