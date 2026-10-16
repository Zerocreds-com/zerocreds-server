# Local macOS ZeroCreds

The local installer runs the form server as a per-user LaunchAgent bound only to `127.0.0.1`. Submitted values go to the macOS login Keychain through a small Swift helper that reads the payload from stdin; values are not placed in command-line arguments. A private local catalog stores provider/account aliases, storage references, expiry metadata and verification state, never credential values.

From a clean checkout on macOS:

```sh
./scripts/setup-local-mac.sh
```

Restart Codex and OpenCode after setup. The installer backs up their existing configuration before adding the local MCP server. To stop the service:

```sh
launchctl bootout "gui/$(id -u)/com.zerocreds.local-server"
```

The local MCP exposes `zerocreds_create_session`, `zerocreds_check_status`, `zerocreds_connections_list`, `zerocreds_connection_resolve` and `zerocreds_connection_verify`. For a new credential, request a form with a provider slug and a distinct account alias (for example provider `github`, aliases `work` and `personal`). Include `credential_expires_at` only when the actual expiry is known; omit it otherwise. Credential expiry is independent of the one-time form link expiry.

The form URL stays on the Mac. This local catalog is not synchronized to cloud Runner tasks. `zerocreds_connection_verify` checks GitHub and Cloudflare credentials from the local server, records identity and only permissions explicitly returned by the provider, and never returns the token. Cloudflare token validity does not prove a particular resource permission. Other providers remain unverified until a provider-specific safe probe is implemented.

The local server also exposes a broker protocol for safe-playwright. It is disabled for every provider until an operator adds a private mode-0600 entry to `~/.config/zerocreds/local/provider-policies.json`. A policy pins HTTPS login/auth URLs, username/password selectors and the exact source field names stored in Keychain. The model cannot choose the origin or selectors. The broker issues a one-use grant that expires in 60 seconds; safe-playwright's audited filler redeems it directly over loopback, and the ZeroCreds MCP process receives only the grant and non-secret policy metadata. Redemption rechecks that the connection is active and unexpired, returns only the two approved fields, and records a value-free `browser_login` use event. Grants are in-memory and are invalidated on server restart.

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
