# ZeroCreds developer diagnostics and verification

This checklist makes credential setup debuggable by separating each boundary. A successful form save proves storage; a provider verification proves the selected stored credential can perform one documented, bounded operation; neither proves that a different Cloudflare Worker deployment received the same credential.

## Safety boundaries

- Diagnostics are read-only. They do not accept secret values, change destinations, overwrite credentials, submit forms, or deploy configuration.
- The local doctor is available only in local mode, over the loopback-only server, with the local admin token. It returns component status, version, connection counts and repair steps; never file paths, Keychain item values, tokens, or catalog contents.
- Deepgram provider verification may return a one-response-only hint (character count, first three and last four characters) so an operator can distinguish aliases. This fragment is limited to an authenticated local verify call, is never persisted or logged, and is not a substitute for a deployment check.
- Keychain health runs a metadata-only Security.framework query. Provider verification reads one selected Keychain item inside the server, performs a fixed provider request, bounds response size and timeout, rejects redirects, discards temporary Deepgram grants, and returns an allowlisted diagnostic only.
- MCP errors and logs must not include request Authorization, form values, Keychain contents, raw upstream response bodies, cookies, browser storage, or unredacted URLs containing capabilities. Diagnostic IDs are correlation labels, not authorization credentials.
- CI and smoke tests use synthetic credentials and mocked provider responses. Never test by printing, uploading, or putting production secrets in command-line arguments, prompts, fixtures, screenshots, or CI output.
- On macOS, never run `security ... -g` or `security ... -w` in an agent-visible terminal: those options print the Keychain value. Use `zerocreds_connections_list`, `zerocreds_connection_verify`, and the local doctor for value-free diagnostics. A shell tool running as the same user can still read that user's Keychain, so MCP tool descriptions and local agent instructions must explicitly steer away from raw reads.
- The generic playground is local-mode-only and admin-authenticated. It accepts bounded declarative rules and runs fixed synthetic scenarios; it has no URL, provider, shell, destination, or arbitrary-sample input. Its form mode exercises rendering, submission, validation and completion, displays a prominent warning, evaluates input only in memory, and writes status/rule outcomes only. It does not call providers or credential stores. Treat any rule match as format validation, never proof of a live credential.
- Regex is limited to 128 characters, rejects backreferences/lookarounds/quantified groups and excessive quantifiers, and samples are bounded synthetic strings. Any relaxation needs a ReDoS-safe engine or equivalent execution timeout and tests.
- A production Worker diagnostic must be separately authenticated/rate-limited and report only a boolean/config revision plus sanitized provider status/code. It must not return a temporary grant, key length/fragments, or raw upstream body. A destructive secret write or deployment stays behind an explicit operator action and its own audit event.
- Browser diagnostics default to text summaries. Captures, OCR, console output, response headers and request URLs can contain user data or credentials; redact them, bound retention, and require explicit opt-in before transmitting them off-device.

## Diagnostic flow

1. `zerocreds_doctor` checks that the local MCP call reaches the server, the helper is installed and private, the macOS Keychain responds, the default destination is an OS Keychain, and the metadata catalog is readable. It provides an action for each failing check.
2. `zerocreds_connections_list` locates the provider/account alias without returning values.
3. `zerocreds_connection_verify` checks the selected stored credential against that provider. For Deepgram this mints and discards the documented short-lived grant; it does not make a transcription request.
4. The target application must separately prove which deployment/configuration it is serving. A local Keychain success cannot establish that a Worker secret was updated.
5. For generic format checks and lifecycle debugging, call `zerocreds_playground_scenarios`, then `zerocreds_playground_run` with the desired rules. Use `zerocreds_playground_form` when the browser form, submit response, status endpoint or local completion event needs an end-to-end replay. Never use a real credential in this path.

## Checklist

### Shipped in this change

- [x] Add an authenticated local doctor MCP tool and API report with clear statuses, safe counts, version/commit and repair actions.
- [x] Add a Keychain health action that performs a metadata-only query and never returns an item value.
- [x] Check helper ownership/mode, named Keychain destination, and catalog integrity without exposing their paths or contents.
- [x] Add route, doctor, MCP registration, locked-Keychain and malformed-catalog tests; assert report contains no synthetic secret.
- [x] Provision the doctor through the existing local MCP install path used by Codex and OpenCode; rebuild the helper and restart the local LaunchAgent.
- [x] Add a provider-agnostic local credential playground with regex/length/equality/contains/one-of rules and fixed valid, invalid, empty, expiry, timeout and storage-failure scenarios.
- [x] Add an explicit test form mode and MCP tools. Submitted values are never saved or returned; tests verify only status/rule metadata remains on disk.
- [x] Bound regex patterns and reject common catastrophic-backtracking constructs; no arbitrary provider endpoints, live credential probes, destinations or shell commands are configurable.
- [x] Document the Keychain `security -g/-w` value disclosure hazard and route agent troubleshooting through value-free ZeroCreds tools.

### Follow-up developer work

- [ ] Add an authenticated, non-secret diagnostic endpoint to each consuming Worker that identifies its deployment revision and reports the fixed provider probe status/code. Keep it separate from the user-facing temporary-token endpoint.
- [ ] Correlate form creation, submission, Keychain write, provider verification and deployment probe using random diagnostic IDs; persist only stage, timestamp, status and allowlisted provider codes.
- [ ] Add an end-to-end sandbox test with synthetic credentials for form → Keychain → provider grant → consuming Worker probe, including wrong-key, locked-Keychain, timeout and missing-configuration cases.
- [ ] Finish the web tooling backlog in [MCP Host issue #54](https://github.com/trained-assist/trained-assist-mcp-host/issues/54): soft navigation waits, challenge/pending-request diagnostics, bounded console/error forwarding, text-only screenshot/OCR, custom-domain vs workers.dev smoke tests, asset-hash/cache checks, and cf-ray/cf-cache-status reporting.
- [ ] After each consuming-app deploy, verify both its workers.dev and custom-domain route, compare served asset hashes, and report cache/CDN headers. Do not equate a successful deploy command with a working credential flow.

## External guidance

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) and [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): never log secrets; use least privilege and auditable lifecycle events.
- [Cloudflare Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/) and [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/): keep credentials in Worker secret bindings and use observability for operational debugging without exposing their values.
- [Deepgram token-based authentication](https://developers.deepgram.com/guides/fundamentals/token-based-authentication): use grant issuance as the non-billable credential-capability check; discard the temporary token.
