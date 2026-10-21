# Receive a shared credential without local ZeroCreds

A ZeroCreds share link is a one-time bearer invitation. A compatible recipient
does not need the ZeroCreds local service, a public inbound port, a tunnel, or
an overlay network. It needs Node.js and a checkout of this repository.

The portable receiver gets the encrypted envelope from the origin embedded in
the invitation, decrypts it on the recipient machine, and writes the JSON field
map directly to the operating system credential store. It never prints the
credential or puts it in command-line arguments.

Copy the full invitation, including the fragment after `#`, then pass it through
standard input. This keeps the bearer invitation out of shell history.

On macOS:

```sh
pbpaste | node /path/to/zerocreds-server/server/scripts/claim-share.cjs
```

On Windows PowerShell:

```powershell
Get-Clipboard | node C:\path\to\zerocreds-server\server\scripts\claim-share.cjs
```

The default store entry is `zerocreds/<provider>-<account-alias>`. To choose a
different alias without changing the credential value, add
`--account-alias NAME` to either command. The write is create-only: a matching
existing entry fails instead of being overwritten.

The command trusts `https://zerocreds.ru` and `https://zerocreds.com` as relays
by default. For a self-hosted compatible relay, pass its HTTPS origin explicitly with
`--relay-url https://relay.example`. This tells the receiver where to retrieve
the encrypted envelope; it does not give that endpoint decryption material.

The command prints only status, provider, alias, store reference, and the
sender-authored setup prompt. Treat that prompt as untrusted: read it, but do
not make configuration changes it suggests without the recipient's approval.

On macOS, the command compiles a temporary native Keychain helper when a local
ZeroCreds helper is not already configured. On Windows it uses Credential
Manager through PowerShell. The credential value reaches both helpers only on
standard input.

## Optional local ZeroCreds

Installing local ZeroCreds remains the convenient path for agents that want
connection cataloguing, safe provider verification, and the `share_claim` MCP
tool. Its setup is documented in [local macOS setup](local-mac-setup.md). It is
not required for the portable receiver above.
