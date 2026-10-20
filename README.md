# ZeroCreds

**Open-Source credential collection server for AI agents. Credentials never reach the LLM — the agent only sees `{ status: "ok" }`.**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-22%2B-green.svg)](https://nodejs.org)

---

## The problem

AI agents need to connect to services on the user's behalf — but passing login/password through the LLM context is a security risk: credentials can be logged, cached, or leaked through prompt injection.

ZeroCreds puts a form between the agent and the user. The user enters their credentials directly into a web form. The form saves them to a secret store. The agent only learns whether it succeeded.

## How it works

```
Agent                    ZeroCreds Server             User
  │                            │                        │
  ├─POST /api/session/create──►│                        │
  │  { fields, destination }   │                        │
  │◄─{ url, expires_at }───────┤                        │
  │                            │                        │
  ├─sends URL to user ─────────────────────────────────►│
  │  (Telegram, email, etc.)   │                        │
  │                            │◄──GET /f/{token}───────┤
  │                            │────form HTML──────────►│
  │                            │◄──POST /f/{token}──────┤
  │                            │   { fields }           │
  │                            ├─writes to secret store►│
  │                            │◄─{ ok }────────────────┤
  │                            │                        │
  ├─GET /api/session/{t}/status►│                        │
  │◄─{ status: "done" }────────┤                        │
  │                            │                        │
  │ (never saw credentials)    │                        │
```

---

## Quick Start

```bash
git clone https://github.com/Zerocreds-com/zerocreds-server
cd zerocreds-server/server
npm ci
npx playwright install chromium --with-deps   # only needed for nalog.ru

export ZEROCREDS_ADMIN_TOKEN=your-secret-token   # or use a private admin token file (see Deployment)
PORT=3456 npm start
```

For a purely local setup (inline destinations, http:// or localhost targets) see [Configuration](#configuration).

---

## MCP Integration (no-code setup)

The fastest way to give an agent access to ZeroCreds is via the MCP server in `mcp/`. It exposes credential forms and, in local mode, connection discovery and peer sharing without giving the agent credential values.

### Supported agents

| Agent | Config file | Status |
|-------|-------------|--------|
| **Claude Code** | `~/.claude/settings.json` | ✅ |
| **Codex CLI** | `~/.codex/config.toml` | ✅ |
| **Cursor** | `~/.cursor/mcp.json` | ✅ |
| **Gemini CLI** | `~/.gemini/settings.json` | ✅ |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` | ✅ (same format as Cursor) |
| **Cline / RooCode** | VS Code Settings → MCP | ✅ (same format) |

### Setup (2 minutes)

**1. Get your integrator token** — ask the server admin (`POST /admin/integrators/create`), or request one via `POST /api/register`. Self-registered tokens stay inactive until the admin approves them (`POST /admin/integrators/approve`).

**2. Add to your agent's config:**

#### Claude Code (`~/.claude/settings.json`)
```json
{
  "mcpServers": {
    "zerocreds": {
      "command": "node",
      "args": ["/path/to/zerocreds-server/mcp/index.js"],
      "env": {
        "ZEROCREDS_URL": "https://zerocreds.ru",
        "ZEROCREDS_ADMIN_TOKEN": "tok_..."
      }
    }
  }
}
```

#### Codex CLI (`~/.codex/config.toml`)
```toml
[mcp_servers.zerocreds]
command = "node"
args = ["/path/to/zerocreds-server/mcp/index.js"]
env = {ZEROCREDS_URL = "https://zerocreds.ru", ZEROCREDS_ADMIN_TOKEN = "tok_..."}
```

#### Cursor / Windsurf / Cline (`~/.cursor/mcp.json` or equivalent)
```json
{
  "mcpServers": {
    "zerocreds": {
      "command": "node",
      "args": ["/path/to/zerocreds-server/mcp/index.js"],
      "env": {
        "ZEROCREDS_URL": "https://zerocreds.ru",
        "ZEROCREDS_ADMIN_TOKEN": "tok_..."
      }
    }
  }
}
```

#### Gemini CLI (`~/.gemini/settings.json`)
```json
{
  "mcpServers": {
    "zerocreds": {
      "command": "node",
      "args": ["/path/to/zerocreds-server/mcp/index.js"],
      "env": {
        "ZEROCREDS_URL": "https://zerocreds.ru",
        "ZEROCREDS_ADMIN_TOKEN": "tok_..."
      }
    }
  }
}
```

**3. Restart the agent** — the tools `form_create` and `form_status` will appear automatically.

### MCP tools

Tool names carry only the action and the object (`form_create`, `discovery_sources`, `connection_verify`). The provider name already lives in the MCP namespace, so it is not repeated in every tool name.

**`form_create`** — create a form, get a URL to send to the user:
```
title, description, fields[], destination, ttl_minutes, notify
→ { token, url, expires_at, credential_contract: { format: "json", provider, account_alias, fields: [{ name, label, type, required, level }] } }
```
Submitted values are stored as a JSON object keyed by the exact `fields[].name` values. The same value-free contract is returned by `form_status` while pending or after completion, so an agent can select the declared key without inspecting the secret store.

**`form_status`** — poll until the user submits:
```
token
→ { status: "pending" | "done" | "expired" | "unknown", credential_contract? }
```

### Local credential discovery (macOS)

Local mode (`ZEROCREDS_LOCAL_MODE=1`) exposes a staged, value-free inventory flow. No tool in this flow reads or stores a secret value.

**`discovery_sources`** — report which credential sources are available (`github_cli`, `cloudflare_cli`, `gcloud_cli`, `macos_keychain`, `chrome`). Read-only; browser password stores may be detected but never read.

**`discovery_preview`** — scan the available sources and return metadata candidates (provider, account, label, source, category, scopes) without saving anything:
```
source_ids?  (narrow by source)
categories?  (narrow by category; omit to receive everything)
→ { preview_id, expires_at, candidate_count, category_counts, filtered_out, candidates[] }
```
- Previews expire 6 hours after creation.
- A successful catalog call consumes the preview, so run preview again before adding more.
- `category_counts` always describes the full inventory the filter was applied to. Categories are `credential`, `wifi`, `bluetooth`, `apple-system`, `browser`, `vpn`, `other` — OS noise is separable but never hidden by default.

**`discovery_catalog`** — add only the refs the user explicitly approved, from the same `preview_id`. Writes searchable metadata only, never secrets:
```
preview_id, refs[]  (1–200 refs, each from that preview)
→ { catalogued, already_present, total_catalog_entries }
```
Every candidate carries a unique `ref`; two Keychain items that share an account and label are told apart by their service. A ref is identified by exactly one candidate, so a repeated ref can never be mistaken for an unknown one.

**`credentials_search`** — search the *approved* catalog by provider, account, source, label, service or scope. It is not a live Keychain scan: use `discovery_preview` for a fresh inventory.

**`connections_list` / `connection_resolve`** — list saved connections and resolve one into a value-free handle.

**`connection_verify`** — verify a saved credential against its provider. Provider-native verification exists for `github`, `cloudflare` and `deepgram`; any other provider slug is accepted and answered with `verification: "unsupported_provider"` (nothing is contacted), so the tool stays honest for services ZeroCreds cannot check. The tool never returns the credential or a grant value.

**`share_create` / `share_claim`** — transfer an existing local Keychain connection between two Macs when the owner explicitly requests it. The user flow has two outcomes: the sender first checks direct reachability if needed (reachable returns the public address and port; unreachable offers the relay), then chooses a route and receives a one-time link; the recipient claims the full link and receives a `saved` result with the new connection ID, provider and account alias. The value is never returned. `share_status` and `share_cancel` let the sender track or stop a pending transfer. `share_create` requires the owner's explicit choice between the configured ZeroCreds relay and direct transfer. Direct transfer may require changing the sender's router; the relay needs only outbound HTTPS and does not let the website read the encrypted credential. If the optional direct check is rate-limited, the same port is retried with bounded exponential backoff for at most 10 seconds; checks are limited per public IP to prevent port-scanning abuse. See the two step-by-step user scenarios in [local macOS setup and sharing](docs/local-mac-setup.md#share-an-existing-credential-with-another-mac).

Use `token` as the field name for a new GitHub token form (`label` can be descriptive, and `uid` distinguishes accounts). Legacy aliases `github_token` and `personal_access_token` also work. Custom field names are supported: if an existing credential was saved as `github_pat_admin`, call:

```json
{ "provider": "github", "account_alias": "github-admin", "token_field": "github_pat_admin", "save_token_field": true }
```

`token_field` selects the original saved field; it does not rename, copy or return the secret. Add `save_token_field: true` to persist this alias on the connection after successful provider verification (`token_field_saved: true`). Later checks can omit `token_field`. Saving another successfully verified field replaces the alias; failed verification leaves the previous alias intact. Without this option the override applies only to the current check. An explicit field takes precedence over default aliases; a missing or empty field fails without contacting the provider. On `credential_field_missing`, retry with the original field name instead of asking the user to submit another form.


---

For the planned ServerlessAgence wallet, see the [task-driven MCP form, OpenBao preflight and owner/profile disclosure contract](docs/serverlessagence-runner-credential-intake.md). OpenBao will store secret values; D1 will hold non-secret form and connection metadata. The current end-to-end integration is not deployed.

---

## Agent Integration (HTTP API)

Three steps from the agent's side:

### 1. Create a form session

```http
POST /api/session/create
Authorization: Bearer {ZEROCREDS_ADMIN_TOKEN}
Content-Type: application/json

{
  "title": "Connect GitHub",
  "description": "Paste your GitHub token with repo scope",
  "fields": [
    { "name": "username", "label": "GitHub Username", "type": "text",     "required": true },
    { "name": "token",    "label": "Personal Access Token", "type": "password", "required": true }
  ],
  "destination": "prod-gcp",           // named destination configured by the server admin
  "ttl_minutes": 30,
  "notify": {
    "tg_bot_token": "...",
    "tg_chat_id": "..."
  }
}
```

Response:
```json
{
  "token": "8a3f1c2d...",
  "url": "https://your-server/f/8a3f1c2d...",
  "expires_at": "2026-09-05T13:30:00Z"
}
```

### 2. Send the URL to the user

Send `url` via Telegram, email, or any channel. The user opens it, fills in the form, and clicks Submit. The form POSTs directly to ZeroCreds — the agent never sees the values.

If you pass `notify.tg_bot_token` + `notify.tg_chat_id`, the server sends the link automatically.

### 3. Poll for completion

```http
GET /api/session/{token}/status
Authorization: Bearer {ZEROCREDS_ADMIN_TOKEN}
```

```json
{ "status": "pending" }   ← still waiting
{ "status": "done" }      ← credentials saved to destination
{ "status": "expired" }   ← user didn't submit in time
```

Poll every 5–10 seconds. When `done`, credentials are in the secret store — read them from there however your stack requires.

---

## API Reference

### POST /api/session/create

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `title` | string | yes | Form heading shown to the user |
| `description` | string | no | Subtext on the form |
| `fields` | array | yes | Form fields (see below) |
| `destination` | string or object | yes | Where to save credentials |
| `ttl_minutes` | number | no | Link expiry (default: 30, max: 1440) |
| `notify` | object | no | `{ tg_bot_token, tg_chat_id }` — sends the link via Telegram |

Limits: `title` ≤ 200 chars, `description` ≤ 2000 chars (rendered as plain text), at most 50 fields. `allow_save` is accepted for compatibility and ignored — the form never stores submitted values for pre-filling.

### Field definition

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Key in the saved JSON (`[a-zA-Z0-9_]`, max 64, unique) |
| `label` | string | yes | Label shown on the form |
| `type` | string | no | `text` · `password` · `email` · `tel` · `number` · `textarea` · `url` (default: `text`) |
| `placeholder` | string | no | Input placeholder |
| `required` | boolean | no | Default: `true` |

### GET /api/session/{token}/status

Returns `{ "status": "pending" | "done" | "expired" | "unknown" }`. `unknown` means the server cannot safely determine whether an interrupted write completed; do not submit the form again automatically. An integrator only sees its own sessions — anyone else's token reports `expired`. `done` and `unknown` markers are kept for 24 hours.

### API-friendly forms (handles and signed receipts)

A form spec is one form with two ways in: a URL for a human and a machine endpoint with the same schema. Both return the same signed receipt with a **handle** — `cred:<name>` in the owner's space. The handle is not a secret: pass it to runs, prompts and logs instead of the value.

```http
POST /api/forms
Authorization: Bearer {integrator or admin token}

{ "name": "cloudflare", "kind": "token", "destination": "prod-vault" }
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Handle name, `[a-z0-9][a-z0-9_.-]{0,63}` → `cred:<name>`. Also available as `{{name}}` in `local_file` destination templates |
| `kind` | string | no | `token` (default: one password field `token`) · `ssh` (`private_key`) · `login` (`username`, `password`) |
| `fields` | array | no | Overrides the kind's default fields (same rules as sessions) |
| `destination` | string or object | yes | Same rules as sessions: named destinations only unless inline is enabled; `http_post` allowlist applies |
| `title`, `description`, `ttl_minutes`, `test_destination` | | no | As for sessions (`title` defaults to `Save <name>`) |

Response: `form_id`, `handle`, `url` (human form, `/f/{form_id}`), `submit_url`, `status_url`, a one-time `submit_token` (returned once, stored only as a hash), `expires_at`, a signed `manifest` (`manifest_id` = sha256 of the canonical manifest: fields, destination, exact submit request, owner, server version) and `api_example` (`curl` and `sar cred put` with placeholders).

```http
POST /api/forms/{form_id}/submit
Authorization: Bearer {owner key | submit_token}

{ "manifest_id": "…", "fields": { "token": "…" } }
```

→ `{ ok, handle, receipt }`. Only the owner (the integrator that created the form, or the admin) or the form's submit token may submit; `manifest_id` is optional and must match if sent (409 otherwise). A form is one-time: after either the human or the machine submit it is closed. The human form (`POST /f/{form_id}`) returns the same receipt with `submitted_via: "form"`, and `GET /api/session/{form_id}/status` returns it to the owner once `done`.

The receipt is `{ payload, alg: "Ed25519", key_id, signature }`; `signature` is base64url over the canonical JSON (sorted keys, no whitespace) of `payload`, which holds `handle`, `form_id`, `owner`, `manifest_id`, submitted field names, destination and `destination_ref`, `submitted_via`, `submitted_at` and the server version. It never contains values. The public key is at `GET /.well-known/zerocreds-signing-key`.

The human form shows the handle next to the destination and has a **Copy as API request** block with the same request as `curl` (values read from env variables via `jq`) and `sar cred put …`; it never shows the submit token.

### Integrator management (admin token)

| Endpoint | Body | Effect |
|----------|------|--------|
| `POST /admin/integrators/create` | `{ id, name }` | Creates an active integrator, returns its token |
| `POST /admin/integrators/approve` | `{ id }` | Activates a self-registered integrator |
| `POST /api/destinations` | `{ name, destination, integrator_id? }` | Adds a named destination — server-wide, or for one integrator |

`POST /api/register` (`{ email, category, website? }`, rate-limited per client IP) returns a token with `status: "pending_approval"`; it cannot be used until approved.

### GET /version

Returns the git commit the server process reports it is running. This is self-reported by the server: it tells you which revision the operator says is deployed, not proof that the running code is unmodified (see [trust architecture](docs/trust-architecture-verifiable-forms-and-releases.md) for the planned signed-release verification).

---

## Destinations

**Named destinations only (default).** The admin configures destinations once — in `~/zerocreds-destinations.json` (or `ZEROCREDS_DESTINATIONS_FILE`), or via `POST /api/destinations` with the admin token — and callers reference them by name. An integrator can use server-wide destinations and the ones the admin attached to it (`integrator_id`). SA keys never travel through API requests, and whoever creates a session cannot choose an arbitrary target.

**Inline objects (dev only)** — passing the destination config in the API call, and integrators adding their own destinations, are disabled unless `ZEROCREDS_ALLOW_INLINE_DESTINATIONS=1`. Even then, server-local types (`local_file`, keychains) stay admin-only.

**Destination rules** (enforced at session creation and again when saving):

- `http_post` — `https://` only, and the host must be listed in `ZEROCREDS_HTTP_POST_ALLOWED_HOSTS`. With no allowlist, `http_post` is disabled. `{field}` placeholders are allowed in the path/query, not in the host.
- `http_post` and `vault` never connect to private, loopback, link-local or metadata addresses; every resolved address is checked at connect time.
- `local_file` from an integrator's session is written under `~/agent-tokens/_integrators/{integrator_id}/{uid}/{filename}`; only admin sessions write to `~/agent-tokens/{uid}/`.
- Error responses never include the upstream service's response body — only the HTTP status.

**Named destinations file** (`~/zerocreds-destinations.json`):

```json
{
  "prod-gcp": {
    "type": "gcp_secret_manager",
    "secret": "projects/my-project/secrets/github-creds",
    "credentials": "<base64 of service account key JSON>"
  },
  "prod-aws": {
    "type": "aws_secrets_manager",
    "secret_id": "arn:aws:secretsmanager:us-east-1:123:secret:github-creds",
    "region": "us-east-1",
    "access_key_id": "AKIA...",
    "secret_access_key": "..."
  },
  "vault-prod": {
    "type": "vault",
    "address": "https://vault.example.com",
    "path": "secret/data/github-creds",
    "token": "hvs...."
  },
  "local-dev": {
    "type": "local_file",
    "uid": "123456",
    "filename": "github"
  }
}
```

**Inline destination** (only with `ZEROCREDS_ALLOW_INLINE_DESTINATIONS=1`):

```json
{
  "destination": {
    "type": "local_file",
    "uid": "123456",
    "filename": "github"
  }
}
```

For a named OpenBao KV-v2 destination, `vault` remains the compatible destination type. An optional preflight configuration checks the writer's `create/update` capability on the exact target path, writes a synthetic value to an owner-scoped `probes/` path, verifies the returned version through the metadata endpoint, and deletes the probe metadata before returning the form link. This path currently accepts one named destination, not `destinations_by_level` or an inline destination. The writer identity needs `create/update` on its owner's `connections/` and `probes/` data paths plus access to `sys/capabilities-self`, but no data `read`; `preflight_metadata_token` needs metadata `read/delete` only for that owner's `probes/` path. A failed or skipped cleanup blocks form creation. `test_destination: false` cannot bypass this configured OpenBao probe.

```json
{
  "owner-a-openbao": {
    "type": "vault",
    "address": "https://openbao.example.com",
    "path": "secret/data/owners/owner-a/connections/connection-a",
    "token": "<scoped-writer-token>",
    "preflight_path_prefix": "secret/data/owners/owner-a/probes",
    "preflight_metadata_token": "<probe-metadata-only-token>"
  }
}
```

This probe verifies the configured OpenBao write path and returns no credential value. `POST /api/forms` can create a signed manifest and receipt for this named destination. That still does not establish authenticated wallet ownership or profile binding, D1 metadata, a runner read broker, or a production OpenBao deployment; those remain part of the [ServerlessAgence integration contract](docs/serverlessagence-runner-credential-intake.md).

### The ZeroCreds custody destination

`zerocreds_vault` is the durable custody: the value is encrypted with a key only this service holds and is written to the custody store as ciphertext, and the store answers it only to a run-scoped grant. The destination is named and configured once, like any other:

```json
{
  "runner-custody": {
    "type": "zerocreds_vault",
    "vault_url": "https://zerocreds-wallet-api-runner-sandbox.example.workers.dev",
    "service_token": "<custody service token>",
    "data_key": "<base64 of the 32-byte data key>",
    "key_ref": "k1",
    "connection_id": "conn_1",
    "owner_id": "owner_1",
    "profile_id": "profile_1",
    "provider": "github",
    "lease_ttl_minutes": 1440
  }
}
```

`lease_ttl_minutes` is optional and it is the only bound on how long the stored value may leave the custody: it starts when the value is stored and ends after that many minutes. `lease_expires_at` (an ISO-8601 instant) names the end instead of a duration. Without either, the value has no lease and lives in the custody until it is revoked — the right default for a credential a user minted for a long-lived integration. Once the lease has ended, a grant is refused with `CREDENTIAL_LEASE_EXPIRED` and no value. The lease is host policy: the submitted form values never change it.

### Who can read what

| Destination | Mechanism | Guarantee |
|-------------|-----------|-----------|
| GCP Secret Manager | `roles/secretmanager.secretVersionAdder` | IAM: ZeroCreds can add but cannot read versions |
| AWS Secrets Manager | `secretsmanager:PutSecretValue` only | IAM policy: `GetSecretValue` not granted |
| HashiCorp Vault | `capabilities = ["create", "update"]` | Policy: `read` not listed = denied |
| Local file / keychain | file 0600 in a 0700 directory on the server | Readable by the server operator's processes — **not** write-only |
| `http_post` | HTTPS POST to an allowlisted host | The endpoint owner receives the values in readable form — **not** write-only |

The form always shows, above the Submit button, who requested the data and the exact destination (type and host/path or file path) for each group of fields.

---

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `ZEROCREDS_ADMIN_TOKEN` | — | Admin bearer token. Required unless a private admin token file exists. |
| `ZEROCREDS_ADMIN_TOKEN_FILE` | `~/.config/zerocreds/admin-token` | Alternate file containing a single admin token of at least 32 characters. Must be a regular file owned by the service user with mode 0600. |
| `ZEROCREDS_HTTP_POST_ALLOWED_HOSTS` | empty (http_post disabled) | Comma-separated hostnames `http_post` may send to. |
| `ZEROCREDS_ALLOW_INLINE_DESTINATIONS` | off | `1` accepts inline destination objects and lets integrators add their own destinations. Local/dev only. |
| `ZEROCREDS_ALLOW_PRIVATE_DESTINATIONS` | off | `1` allows `http://` and private/loopback addresses for `http_post` and `vault`. Local/dev only. |
| `ZEROCREDS_PENDING_DIR`, `ZEROCREDS_TOKENS_DIR` | `~/connect-pending`, `~/agent-tokens` | Storage (created 0700). Expired session files are swept every 10 minutes. |
| `ZEROCREDS_SIGNING_KEY_FILE` | `~/zerocreds-signing-key.pem` | Ed25519 key (PKCS#8 PEM) that signs form manifests and receipts. Created 0600 on first start; back it up — a new key means old receipts verify only against the old public key. |
| `ZEROCREDS_DESTINATIONS_FILE`, `ZEROCREDS_INTEGRATORS_FILE` | `~/zerocreds-destinations.json`, `~/zerocreds-integrators.json` | Named destinations and integrator registry. |

Status-less integrator records issued before approval existed retain access to legacy session creation and destination registration, including inline local-file destinations. New self-registrations are explicitly pending until approved; newly active integrators and the new `/api/forms` endpoint require named destinations. Legacy network destinations still require the current HTTPS and host-allowlist checks. Rotate old keys to explicit active records after migrating their destinations.

---

## Form UX

The form the user sees has a few conveniences:

- **Password fields** — show/hide toggle (👁) and a **Paste** button that reads the clipboard, since most passwords are copy-pasted
- **Destination box** — always visible above Submit: who requested the data and where each field goes
- No cookies and no "remember me": submitted values are never kept for pre-filling

---

## Security model

- **Credentials bypass LLM context** — the form posts directly to ZeroCreds, never through the agent
- **One-time links** — tokens expire (default 30 min); a link is claimed atomically on submit, so it can succeed only once
- **Admin-approved destinations** — in the default configuration a session can only target destinations the admin configured; the form shows the exact destination and requester
- **Write-only stores where possible** — GCP/AWS/Vault can be set up so ZeroCreds cannot read back; files, keychains and `http_post` are readable by their owner (see the table above)
- **Escaping and CSP** — all session metadata (title, description, labels, placeholders) is HTML-escaped; pages send a strict nonce-based Content-Security-Policy, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`
- **You trust the operator** — on a hosted instance the server sees the values in transit
- **Version reporting** — `GET /version` returns the git commit the server reports it runs. It is self-reported, so it does **not** prove the deployed code is unmodified; verifiable signed releases are planned (see [trust architecture](docs/trust-architecture-verifiable-forms-and-releases.md))
- **No analytics or telemetry** — the server sends no usage data to us or any third party. Outbound connections are only: the configured destination (secret store / `http_post` URL), the Telegram Bot API when `notify` is set, and the target sites of the legacy built-in services (e.g. nalog.ru via Playwright)

---

## Deployment (systemd)

```ini
# /etc/systemd/system/zerocreds-server.service
[Unit]
Description=ZeroCreds Server
After=network.target

[Service]
WorkingDirectory=/home/vova/zerocreds-server/server
ExecStart=/usr/bin/node src/server.js
Restart=always
Environment=PORT=3456
# Supply ZEROCREDS_ADMIN_TOKEN here or create a private admin token file.
Environment=ZEROCREDS_HTTP_POST_ALLOWED_HOSTS=hooks.example.com
User=vova

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now zerocreds-server
```

For a file-backed token, create it as the service user before the first restart:

```bash
umask 077
mkdir -p ~/.config/zerocreds
openssl rand -hex 32 > ~/.config/zerocreds/admin-token
chmod 600 ~/.config/zerocreds/admin-token
```

Keep this file out of the repository and backups accessible to other users. A missing,
symlinked, group-readable or world-readable file prevents startup when no environment
token is configured.

nginx proxy: route `/connect/*`, `/f/*`, and `/api/*` to `:3456`.

---

## Built-in services (legacy)

The original hardcoded service endpoints are still supported:

| Service | Endpoint | Method |
|---------|----------|--------|
| nalog.ru (FNS) | `/connect/nalog` | Playwright login via Gosuslugi |
| GitHub | `/connect/github` | API token paste |
| Weeek CRM | `/connect/weeek` | API token paste |
| Tilda | `/connect/tilda` | Session cookie paste |

These predate the dynamic form API and use `~/connect-pending/{token}.json` files. Prefer the dynamic API for new integrations.

---

## Contributing

Pull requests and issues are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

MIT licensed — use it commercially, fork it, build on it.

---

## Claude Code Instructions

### Architecture

```
nginx (443/80)
  └── /connect/* /f/* /api/* → zerocreds-server :3456
  └── /                      → /home/vova/zerocreds-landing/ (static)

~/connect-pending/          ← agent writes (legacy) or server creates (dynamic API)
~/agent-tokens/             ← server writes (local_file destination; integrators under _integrators/{id}/)
~/zerocreds-destinations.json ← named destination configs (server reads at startup)
~/zerocreds-integrators.json  ← integrator registry (tokens, status, per-integrator destinations)
~/zerocreds-signing-key.pem   ← Ed25519 key for form manifests and receipts (created on first start)
```

Forms (`POST /api/forms`) are stored as pending sessions with a `form` block (`name`, `kind`, `handle`, `manifest_id`, `submit_token_hash`), so `/f/{form_id}`, status polling, one-time claiming and the sweeper work unchanged. Human and machine submits share `submitPending()` in `server/src/server.js`; signing lives in `server/src/receipts.js`.

### Deployment

Server: `178.212.14.192` (Hostland RU VM)
Service: `zerocreds-server.service`
Landing: `/home/vova/zerocreds-landing/`

### CI/CD

- `main` is protected: PR + required `test` check, enforced for admins. There is no auto-merge — a human merges.
- `test.yml` (job `test`, the required check): gitleaks over full history (pinned binary, sha256-verified) → `npm ci` in `server/` and `mcp/` (lockfiles are mandatory) → `npm audit --omit=dev` → syntax lint (`node --check`) → `node --test`. Node 22.
- `deploy.yml`: runs on push to `main` (or manual dispatch from `main` only), re-runs `test` on that exact sha, then the `deploy` job waits for approval in the GitHub Environment `production` (required reviewer) before SSHing to the server.
- All third-party actions are pinned by full commit SHA (tag in a trailing comment). When bumping, resolve the new SHA with `git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>`.
- Changing dependencies: update `package.json` and commit the regenerated `package-lock.json`; CI fails on lockfile drift.
