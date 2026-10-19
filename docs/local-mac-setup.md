# Local macOS ZeroCreds

The local installer runs the form server as a per-user LaunchAgent bound only to `127.0.0.1`. Submitted values go to the macOS login Keychain through a small Swift helper that reads the payload from stdin; values are not placed in command-line arguments. A private local catalog stores provider/account aliases, storage references, expiry metadata and verification state, never credential values.

From a clean checkout on macOS:

```sh
./scripts/setup-local-mac.sh
```

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

The local MCP exposes `doctor`, `form_create`, `form_status`, `connections_list`, `connection_resolve`, `connection_verify`, and the `playground_*` test tools. Start with `doctor` when setup or storage is unclear; it reports safe readiness checks and repair steps, and never reads or returns credential values. Use the playground only with invented strings: it can replay generic format rules and local form lifecycle paths, but never contacts a provider or stores the submitted value. For a new real credential, request a normal form with a provider slug and a distinct account alias (for example provider `github`, aliases `work` and `personal`). Include `credential_expires_at` only when the actual expiry is known; omit it otherwise. Credential expiry is independent of the one-time form link expiry.

Credential discovery is deliberately staged. When asked what access is available, the agent can call `discovery_sources` and `discovery_preview`. These inspect `gh auth`, Wrangler, gcloud and macOS Keychain item attributes; they never request token/password values. Chrome can be detected, but browser credential databases are not read. The agent presents the preview first. A preview remains available in the local server's memory for six hours; after that, discovery must be run again. Only after the user chooses entries and confirms should the agent call `discovery_catalog`; `credentials_search` then searches the local metadata catalog. Discovery never grants access or proves a token works. Verify supported saved ZeroCreds connections separately. The catalog is private local metadata at `~/.config/zerocreds/local/discovery-catalog.json`.

The form URL stays on the Mac. This local catalog is not synchronized to cloud Runner tasks. `connection_verify` checks GitHub and Cloudflare credentials from the local server, records identity and only permissions explicitly returned by the provider, and never returns the token. Cloudflare token validity does not prove a particular resource permission. Other providers remain unverified until a provider-specific safe probe is implemented.

The local server also exposes a broker protocol for safe-playwright. It is disabled for every provider until an operator adds a private mode-0600 entry to `~/.config/zerocreds/local/provider-policies.json`. A policy pins HTTPS login/auth URLs, username/password selectors and the exact source field names stored in Keychain. The model cannot choose the origin or selectors. The broker issues a one-use grant that expires in 60 seconds; safe-playwright's audited filler redeems it directly over loopback, and the ZeroCreds MCP process receives only the grant and non-secret policy metadata. Redemption rechecks that the connection is active and unexpired, returns only the two approved fields, and records a value-free `browser_login` use event. Grants are in-memory and are invalidated on server restart.

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
