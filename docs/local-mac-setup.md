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

The local MCP exposes `zerocreds_create_session`, `zerocreds_check_status`, `zerocreds_connections_list` and `zerocreds_connection_resolve`. For a new credential, request a form with a provider slug and a distinct account alias (for example provider `github`, aliases `work` and `personal`). Include `credential_expires_at` only when the actual expiry is known; omit it otherwise. Credential expiry is independent of the one-time form link expiry.

The form URL stays on the Mac. This local catalog is not synchronized to cloud Runner tasks. The first slice records declared expiry and marks provider verification as unknown; provider checks, credential use broker and cross-machine sync remain later work.

To remove the local integration, remove the `zerocreds` MCP entry from Codex and OpenCode, unload the LaunchAgent, then remove `~/.config/zerocreds/local` and `~/Library/Application Support/ZeroCreds` after deciding whether to retain metadata. Credentials stored in Keychain are separate and can be removed through Keychain Access.
