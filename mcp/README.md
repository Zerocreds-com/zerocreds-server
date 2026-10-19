# ZeroCreds MCP provider

Package subpath `@zerocreds/mcp/provider` exports a Worker-compatible wallet provider. Package version `0.2.0` contains provider version `1.0.0` and the existing stdio server.

```js
const { createWalletProvider } = require('@zerocreds/mcp/provider');

const provider = createWalletProvider({
  baseUrl: 'https://zerocreds.example',
  fetchImpl: globalThis.fetch,
});
```

Compose the returned descriptor in the trusted host. It declares a value-free `service_catalog` discovery tool (no wallet API binding) and four wallet operations with one operation-specific required binding each:

- `zerocreds.wallet-api:wallet.forms.create`
- `zerocreds.wallet-api:wallet.forms.status`
- `zerocreds.wallet-api:wallet.connections.status`
- `zerocreds.wallet-api:wallet.connections.revoke`

The host `resolveBindings` implementation must issue an Ed25519 assertion for the exact required operation. Derive owner and canonical wallet profile IDs from verified identity and profile authorization. The host must authorize each tool in its `allowedTools` list and keep human and machine audiences separate. The provider reads the assertion only from `context.bindings`; owner, profile, destination and API authorization are never tool arguments. Missing binding or provider configuration fails closed.

Assertions use `aud` `zerocreds-wallet:human` or `zerocreds-wallet:machine`, `owner_id`, `profile_id`, `caller_class`, `operations`, `iat`, `exp`, `iss`, `jti`, and JWT header `kid`; machine calls also include `run_id`. Keep expiry within five minutes and issue a unique `jti` for each tool invocation. ZeroCreds maps `(iss, kid, profile_id)` to a configured owner and named destination. Its wallet D1 Worker consumes each `jti` digest once; apply migration `0002_assertion_replay.sql` before using assertions.

The provider forwards only the wallet API request, returns an explicit value-free projection, and sanitizes upstream errors. It never logs the assertion. `wallet_form_create` may return a one-time form URL; the browser submits credential values directly to ZeroCreds. The existing stdio MCP continues to support its configured legacy scoped wallet token during migration.

The catalog currently includes GitHub, GitLab, Cloudflare, Google Cloud, AWS, OpenAI, Anthropic, Slack, Notion, npm, Vercel, Sentry, Stripe and Linear. These entries are conservative collection hints, not service-auth documentation or permission scopes. For a listed provider, omit `kind` and `fields` to let the ZeroCreds API use its canonical token/login defaults. Never ask for secrets in chat. For an unlisted provider, ask only for required non-secret details, draft the smallest plausible form, and make no claims about OAuth/scopes/verification unless supported by that service's documentation. Current wallet form kinds are token, login (username/password) and SSH private key; composite access-key forms are not yet supported.
