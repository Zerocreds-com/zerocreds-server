# Local macOS ZeroCreds

The local installer runs the form server as a per-user LaunchAgent bound only to `127.0.0.1`. Submitted values go to the macOS login Keychain through a small Swift helper that reads the payload from stdin; values are not placed in command-line arguments. A private local catalog stores provider/account aliases, storage references, expiry metadata and verification state, never credential values.

From a clean checkout on macOS:

```sh
./scripts/setup-local-mac.sh
```

## Where the runtime lives

The installer copies the server, MCP and plugin into a stable directory
(`~/.zerocreds/runtime` by default) and points the LaunchAgent and agent
configs at that copy. The source checkout is only used to build the runtime;
it is never referenced by the running service. This keeps the service working
when the checkout moves or is a git worktree that later gets pruned.

Override the install root with `ZEROCREDS_INSTALL_ROOT`:

```sh
ZEROCREDS_INSTALL_ROOT=/some/stable/path ./scripts/setup-local-mac.sh
```

Re-running the installer from any checkout refreshes the same stable runtime.

## The local address

The service listens on `127.0.0.1:3456`. On top of that the installer sets up a small loopback-only reverse proxy (`scripts/local-proxy.js`, a root LaunchDaemon) so the address a human is handed — the credential-form link — reads `http://localhost/zerocreds` instead of a raw IP and a port. The proxy forwards the path unchanged and the server itself strips the mount prefix, so the same build answers both `/zerocreds/api/...` and `/api/...`.

Port 80 is privileged, so the proxy needs one root step. When `sudo` is not available without a password, the installer prints the command to run by hand and keeps the direct address; re-running the installer afterwards switches over:

```sh
sudo ./scripts/install-local-proxy.sh
```

`ZEROCREDS_PROXY_MODE=off ./scripts/setup-local-mac.sh` skips the proxy and stays on `http://localhost:3456`.

Restart Codex and OpenCode after setup. The installer backs up their existing configuration before adding the local MCP server. It also registers a local OpenCode plugin: after `form_create`, it listens for the form completion event and resumes that same session. The event contains status only; OpenCode then checks the form status through MCP. Codex and hosted agents continue using their existing status/event flow. To stop the service:

```sh
launchctl bootout "gui/$(id -u)/com.zerocreds.local-server"
```

The local MCP exposes `doctor`, `form_create`, `form_status`, `credentials_overview`, `connection_bind_existing`, `connections_list`, `connection_resolve`, `connection_verify`, `connection_scopes_inspect`, `any_api_request`, and the `playground_*` test tools. Start with `doctor` when setup or storage is unclear; it reports safe readiness checks and repair steps, and never reads or returns credential values. Use the playground only with invented strings: it can replay generic format rules and local form lifecycle paths, but never contacts a provider or stores the submitted value. For a new real credential, request a normal form with a provider slug and a distinct account alias (for example provider `github`, aliases `work` and `personal`). Include `credential_expires_at` only when the actual expiry is known; omit it otherwise. Credential expiry is independent of the one-time form link expiry.

Credential discovery is deliberately staged. When asked what access is available, the agent can call `discovery_sources` and `discovery_preview`. These inspect `gh auth`, Wrangler, gcloud and macOS Keychain item attributes; they never request token/password values. Chrome can be detected, but browser credential databases are not read. The agent presents the preview first. A preview remains available in the local server's memory for six hours; after that, discovery must be run again. Only after the user chooses entries and confirms should the agent call `discovery_catalog`; `credentials_search` then searches the local metadata catalog. Discovery never grants access or proves a token works. Verify supported saved ZeroCreds connections separately. The catalog is private local metadata at `~/.config/zerocreds/local/discovery-catalog.json`.

The form URL stays on the Mac. This local catalog is not synchronized to cloud Runner tasks. `connection_verify` checks GitHub and Cloudflare credentials from the local server, records identity and only permissions explicitly returned by the provider, and never returns the token. Cloudflare token validity does not prove a particular resource permission. Other providers remain unverified until a provider-specific safe probe is implemented.

The local server also exposes a broker protocol for safe-playwright. It is disabled for every provider until an operator adds a private mode-0600 entry to `~/.config/zerocreds/local/provider-policies.json`. A policy pins HTTPS login/auth URLs, username/password selectors and the exact source field names stored in Keychain. The model cannot choose the origin or selectors. The broker issues a one-use grant that expires in 60 seconds; safe-playwright's audited filler redeems it directly over loopback, and the ZeroCreds MCP process receives only the grant and non-secret policy metadata. Redemption rechecks that the connection is active and unexpired, returns only the two approved fields, and records a value-free `browser_login` use event. Grants are in-memory and are invalidated on server restart.

### Map local access before declaring credentials missing

Use `credentials_overview` (optionally with `provider`) when asked what access exists. It combines the connection catalog with live source discovery into a map. Each provider has separate `cli`, `saved_connections`, `keychain_candidates`, `next_steps`, and `execution` fields. CLIs may query their authentication status; the overview does not read secret values or persist catalog changes.

For example, a Cloudflare row can legitimately say all of the following:

| Layer | Result |
| --- | --- |
| Wrangler | Unavailable: absent or not authenticated; discovery did not distinguish these causes |
| Keychain | Candidate `Trained Assist Cloudflare Sandbox API Token`, account `trained-assist-sandbox`, metadata found |
| ZeroCreds catalog | Not registered |
| Provider validity/scopes | Not checked |
| Deployment | Not checked; needs an execution path and target configuration |

That is a found candidate with an unfinished binding, not evidence that a token is absent. Do not search agent session/chat logs for credentials. Label/service matching is a provider hint, not provider verification. If Keychain discovery fails, the map directs the agent to `doctor`. Unclassified entries can be explored through `discovery_preview`; oversized maps mark `truncated`.

The map returns a six-hour `preview_id` and candidate refs. `connection_bind_existing` accepts that preview (or a `discovery_preview`), one `ref`, `provider`, `account_alias` and `credential_format` (`raw_token` or `json`). Use a credential the user already selected or authorized by name; clarify only if the choice is ambiguous. Binding checks metadata presence, records the exact original service/account reference, and does not read/copy/rewrite the secret. It does not need a new form, token, or prior `discovery_catalog` call. `discovery_catalog` only builds the searchable metadata inventory and never establishes a usable connection.

Binding supports generic Keychain items with exact, untruncated service/account identifiers supported by the native helper. Internet passwords and unsupported item identities are not bindable. `raw_token` wraps the existing plaintext token internally for provider verification/inspection; `json` preserves ZeroCreds form fields. For Yandex OAuth use JSON with an explicit OAuth field; a raw Yandex token is interpreted as IAM. Reusing the same binding is idempotent; conflicting aliases and revoked connections return a conflict instead of being overwritten. The preview remains usable until expiry. No CLI login is changed.

Resolver callers must handle `not_registered`, `secret_missing`, `ready`, `ambiguous`, `keychain_locked`, `unavailable_here`, `expired`, `invalid` and `revoked`. The old ambiguous `missing` status is replaced. Follow the structured `next_step`; registration/presence is separate from validity and scopes, and all of these are separate from deployment execution.

HTTP routes: `GET /api/local/credentials/overview?provider=cloudflare` and `POST /api/local/connections/bind-existing`. Both are local-mode-only and admin-authenticated. These changes require restarting the local server and reconnecting MCP; changing descriptions alone does not update an already running process.

### Inspect account and scopes

Call `connection_scopes_inspect` with a saved connection's `provider` and `account_alias`, for example `{"provider":"github","account_alias":"gha-compute-cluster"}`. The local API is `POST /api/local/connections/scopes/inspect`, authenticated with the local admin token. Alias is a storage label; provider identity is returned separately.

| Provider | Identity | Rights evidence |
| --- | --- | --- |
| GitHub | User ID and login from `GET /user` | `X-OAuth-Scopes`; a present empty header means reported empty scopes, an absent header means unknown. Fine-grained permissions are not inferred. |
| Cloudflare user API token | Token ID, plus up to 20 visible accounts when account listing succeeds | Best-effort token details show permission groups with their allow/deny effects. Resource/condition restrictions are not expanded, so policy results are partial. |
| Deepgram API key | Project ID and key ID when disclosed by `GET /v1/auth/token` | Scopes only when the token-details response supplies them. No grant is minted. |
| Google Cloud OAuth access token | Subject ID and email when disclosed by `POST /tokeninfo` | OAuth scopes and expiry. IAM roles, project access and resource permissions are not inferred. |
| GitLab.com PAT | User ID and username from `GET /api/v4/user` | Standard PAT scopes and expiry from `GET /api/v4/personal_access_tokens/self`. Granular/resource scopes remain unknown. |
| Yandex Cloud IAM / OAuth token | OAuth: Yandex ID login and ID. IAM: owner unknown, first 20 visible clouds if listing is allowed. | IAM roles and scopes remain unknown. OAuth identity alone does not prove Cloud access. |

Stored credential fields for the added providers:

- `google_cloud`: `access_token`, `google_access_token` or `token`. Uses the Google auth library's tokeninfo POST convention; the secret is never put in the URL. Refresh tokens, service-account JSON/private keys, ADC and API keys are not exchanged or loaded from CLI stores.
- `gitlab`: `personal_access_token`, `gitlab_token` or `token`, for GitLab.com only. Self-managed instance URLs are not accepted by this tool.
- `yandex_cloud`: `iam_token`, `yandex_iam_token` or `token` for IAM; `oauth_token` or `yandex_oauth_token` for Yandex ID OAuth. IAM fields take precedence if both types are present. OAuth is not exchanged for an IAM token. API keys and service-account private keys are not supported by this inspection. IAM results may include `clouds`, `clouds_status: partial` and `visibility_evidence`; OAuth results include `identity_evidence`.

Missing supported fields return `credential_field_missing`. Unknown rights never mean no access, and no new credential is requested automatically. Inspection always uses the selected saved connection, not the active CLI account.

The report includes `status`, `identity`, `scopes`, `scopes_status`, `evidence`, `credential_expires_at`, `expiry_evidence`, `inspected_at`, `limitations`, and `resource_access_checked: false`. Cloudflare additionally includes `policies` when readable, `accounts` and `accounts_status`. Empty arrays with an `unknown` status mean the information could not be established. Account visibility and policy groups do not prove effective access to an operation. Known expiry is tagged as provider-reported or catalog metadata.

Only fixed HTTPS read-only requests are made (GET, plus Google tokeninfo POST with the token in the Authorization header), with redirects rejected, an eight-second timeout per request and a 64 KiB response limit. Provider bodies/errors and credential fragments are not returned. Inspection does not write to the local catalog, replace a PAT, change permissions, configure `gh`, or execute an operation. Revoked, expired and ambiguous connections are rejected before any secret read; unsupported providers are reported without reading their credential. No broader permissions are requested when introspection fails.

Provider contracts: [GitHub OAuth scopes](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps), [Cloudflare token details](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/get/), [Deepgram token inspection](https://developers.deepgram.com/guides/fundamentals/authenticating).

### Agent runbook for an existing GitHub PAT

When a user says an existing PAT should be restored, treat the catalog alias as a ZeroCreds storage label, not as the GitHub username. For the `gha-compute-cluster` connection, use provider `github` and account alias `gha-compute-cluster`:

1. Call `doctor` if local ZeroCreds or Keychain access is in doubt. Follow its returned repair action and rerun it; do not diagnose with raw Keychain commands.
2. Call `connection_resolve` with the exact provider and alias. `ready` means the referenced Keychain item exists. `not_registered` means no matching catalog connection; call `credentials_overview` to find existing Keychain candidates. `secret_missing` means an existing binding references an absent item; inspect the source map and report the mismatch without overwriting that binding. Do not silently create another form, replace the PAT, or conflate it with another alias. `keychain_locked` and `unavailable_here` are local access problems, not evidence that the PAT is invalid.
3. Only for `ready`, call `connection_verify` with the same provider and alias. Report the verified GitHub login and permissions from the result. A successful verification does not mean the secret has been imported into `gh` or made available to arbitrary shell commands.
4. Do not ask the user to run `zerocreds-keychain get`, `security ... -g/-w`, or any command that prints a secret. Do not request a PAT in chat or inject it into `gh auth login`, shell history, process arguments, or environment variables.
5. Use `any_api_request` for user-authorized API operations such as GitHub workflow dispatch. The local server supplies the selected credential internally. This does not authenticate `gh` or expose the PAT to shell. See [API execution](local-api-request.md) for pinned origins, request formats, capture and failure handling.

`connection_verify` separates storage from provider validity: it reads the selected Keychain item internally and reports only safe metadata. For Deepgram it calls `POST /v1/auth/grant`, checks that the API key can mint the default 30-second temporary grant, and discards that token without returning it or making a transcription request. A `valid` result confirms that the Mac Keychain value can mint a grant; it does not update or verify a different environment such as a Cloudflare Worker secret. Check a Worker deployment through that app's own non-secret diagnostic endpoint.

Example policy shape (replace selectors and fields with values reviewed for the actual site):

```json
{
  "example": {
    "login_url": "https://accounts.example.com/login",
    "auth_url": "https://accounts.example.com/api/session",
    "username_selector": "input[name=email]",
    "password_selector": "input[type=password]",
    "submit_selector": "button[type=submit]",
    "success_selector": "[data-authenticated=true]",
    "username_field": "username",
    "password_field": "password"
  }
}
```

The example is documentation only; no provider is broker-enabled by the installer. The current broker flow supports an approved username/password form. OTP/CAPTCHA, federated redirects and storage-state TTL/revocation require the safe-playwright side of the linked integration before using this for real accounts.

To remove the local integration, remove the `zerocreds` MCP entry from Codex and OpenCode, unload the LaunchAgent, then remove `~/.config/zerocreds/local` and `~/Library/Application Support/ZeroCreds` after deciding whether to retain metadata. Credentials stored in Keychain are separate and can be removed through Keychain Access.

Additional provider contracts: [Google tokeninfo implementation](https://github.com/googleapis/google-auth-library-nodejs/blob/main/src/auth/oauth2client.ts), [GitLab PAT self inspection](https://docs.gitlab.com/api/personal_access_tokens/), [Yandex Cloud listing](https://yandex.cloud/en/docs/resource-manager/api-ref/Cloud/list), [Yandex OAuth identity](https://yandex.ru/dev/id/doc/en/user-information).


### Diagnose missing tools before recommending restart

`doctor` now separates local storage health from execution availability. Its server `capabilities` report also appears in `connections_list` and `connection_resolve`, so even an older MCP handler can surface the updated server's guidance.

Example diagnostic (the agent must fill `visible_tools` from its actual session, not copy this illustrative subset as an inventory):

```json
{
  "provider": "github",
  "account_alias": "gha-compute-cluster",
  "required_tool": "any_api_request",
  "visible_tools": ["doctor", "connection_resolve", "connection_verify"]
}
```

The optional provider/alias triggers metadata-only resolution and returns cached identity/scopes with their `last_verified_at`. It does not revalidate the provider or read the token. CLI authentication is not a prerequisite for `any_api_request`.

The server and MCP report their source entrypoints, startup timestamps and fingerprints of selected source files. `changed_since_startup` is evidence that files changed after that process started; `matches_startup` only describes those tracked files. It does not prove provider access or that this is the desired checkout. If their real repository paths differ, doctor points to launch configuration before suggesting restarts. No environment values, config contents, credentials or process arguments are included.

| Evidence | Next action |
| --- | --- |
| Server source changed since startup | Restart the identified local server, then rerun doctor |
| MCP source changed since startup | Reconnect the MCP process, then rerun doctor |
| Both current, but agent reports required tool missing | Inspect client tool visibility/filtering and refresh/reconnect MCP |
| No agent-provided tool list | Visibility is unknown; inspect the actual session tools |
| Server has no capability report | Check server launch path and installed code; an old server is possible but not proven |
| Credential ready, CLI invalid | Continue identity/scope checks and authorized execution through ZeroCreds |
| No catalog binding | Follow `credentials_overview`; do not infer that no token exists |

A source update cannot retrofit these diagnostics into an already running older process. After initial activation, future calls can distinguish tracked source changes from absent session tools. The diagnostic never restarts applications or performs API mutations. An intended dispatch, a GitHub connector lookup and an actual ZeroCreds dispatch response are separate evidence; only the last establishes that the dispatch request was sent through ZeroCreds.


### Multiple aliases and provider accounts

`connections_list` and `connection_resolve` include `account_inventory`: cached identity groups, unresolved connections and `identity_checks` for active connections. The MCP can derive this map from a legacy server's connection list too. Two GitHub aliases with the same verified user ID are grouped as one cached account; that does not mean the user's second account does not exist.

The agent must determine token ownership itself using `connection_scopes_inspect`, with `connection_verify` as the GitHub fallback when an older local server lacks the scopes route. It must not ask the user who owns a token that the provider can identify. Next, inspect target repository/resource access through read-only requests. A choice is only a user-preference question if multiple usable identities remain and the task has not selected one. Never silently switch identities after a failed mutation.

GitHub PAT requests can specify `expected_login`. ZeroCreds then queries `/user` using the same in-memory credential before sending the target request; mismatch or unconfirmed identity prevents that request. This is optional and not appropriate for GitHub App installation tokens, which cannot establish a user through `/user`.

A local 404 from the scopes or API execution route is reported as `local_endpoint_unavailable`, `outcome: not_sent`, with runtime/launch-path diagnostics. It is not a GitHub permission denial and should not trigger another API operation or collection of a replacement token.


### Platform-oriented access overview

Ask `platform_overview({"platform":"github"})`, or omit `platform` to list supported platforms. No CLI or alias needs to be known. `platforms[].access_methods` contains:

- `cli`: discovery status, reason, reported accounts and resource-access uncertainty. Discovery may not distinguish missing CLI from failed authentication; the report preserves that uncertainty.
- `api`: ZeroCreds transport, available registered connections, `connection_id`, optional label, cached identity/permissions with timestamps, and current Keychain metadata presence. CLI authentication is not required. `credential_present` does not assert current provider validity or resource authorization.

Keychain candidates stay distinct from usable registered connections and carry preview refs. An optional binding can generate an internal label automatically; the caller uses the returned `connection_id`. Binding, introspection, direct API requests and diagnostics are independent operations, not prescribed steps. Missing identity/scopes can be learned through the relevant tool or a provider API call when appropriate for the task.

`connection_resolve`, `connection_verify`, `connection_scopes_inspect`, `doctor` and `any_api_request` accept `provider` plus `connection_id`. Alias remains supported for compatibility. Inspection/execution require an ID or alias; if both are present, they must identify the same connection. A provider-only resolver may return ambiguity and never silently chooses a credential for execution.

The existing overview HTTP endpoint and `credentials_overview` remain compatible. The new tool presents its results under `platforms`; legacy `providers`, `saved_connections` and `next_steps` fields remain available to existing clients. The new API and CLI objects express evidence independently of any preferred tool sequence.

### Cloudflare: deployment blockers and credential checks

Acceptance scenario from the user: the deployment agent finds an outdated checkout, cannot confirm the merge SHA or staging instructions, sees a registered Cloudflare credential, has no usable CLI, but has ZeroCreds API execution available.

Expected behavior: report the deployment blocker separately from credential validity and API availability. The agent can use the available verification tool or a documented minimal API check to determine whether the selected credential is accepted, without changing Cloudflare resources. No mandatory order of tools is required. Lack of CLI is not an API-access blocker. An unavailable staging configuration does not establish anything about token validity.

If a known verification tool supports the credential, it is sufficient. If no supported check exists, the minimal task for the agent/LLM is:

> Using the platform's official documentation and the credential type (never its value), propose one minimal authenticated API request that checks whether the credential is accepted. Do not deploy, modify resources, mint or rotate tokens, or invoke a billable workload. Return the documented method/path, required non-secret parameters, authentication scheme, source URL, and explicit rules for valid / invalid / unknown. A public endpoint returning 200 is not proof of authentication. Interpret the response body as well as HTTP status where required by the provider. Do not assume that 403 or 404 means the credential is invalid. If no suitable check is documented, return unknown with the reason; do not invent an endpoint. The generated request is a proposal: it does not authorize sending credentials to a new host or change ZeroCreds' pinned-origin policy.

The current agent can do this documentation task; an embedded LLM call or provider adapter is not required. Execution still uses a supported ZeroCreds route and its existing credential reference. Unknown platforms cannot be executed by the current fixed provider allowlist merely because a request was proposed. Extending that execution support remains separate work.

A minimal check returns only `valid`, `invalid` or `unknown`, evidence and a short reason. Network failures, local route 404, rate limiting, malformed responses and insufficient permissions for the check are distinct reasons for `unknown`; they are not a reason to ask for another PAT. Validity does not establish account ownership, all scopes, Worker-write permission or deployment readiness. Agent-selected read-only resource queries can provide additional evidence if useful, but full scope discovery is not mandatory for a validity check.

Example response structure for the Cloudflare scenario (fill exclusively from observed results):

- Deployment: blocked by the unconfirmed SHA/staging configuration; no resources changed.
- Cloudflare API: check performed through ZeroCreds using connection_id; result valid / invalid / unknown, with the actual check result.
- CLI: unavailable, independently of API access.
- Resource permissions: list only those actually checked; otherwise unknown.
- Remaining blocker: obtain the correct checkout/deployment configuration, or repair the local ZeroCreds route if that route itself failed.

Do not state that API validity or scopes were checked when only Keychain presence or cached verification was inspected. Do not stop at “only ZeroCreds API is available” when that API can perform the needed read-only check. If that tool returns a local endpoint error, report the failed execution path instead of attributing it to Cloudflare credentials. This scenario requires no new credential form or secret in the conversation.

The local MCP tool `credential_check_plan` exposes this minimal prompt and points to a built-in check when available. It accepts platform, optional connection_id, credential_type and an official documentation URL. It does not call an embedded model or read a credential: the current agent handles the documentation task. Generated requests do not enable unknown-provider execution.
