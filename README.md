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

export ZEROCREDS_ADMIN_TOKEN=your-secret-token   # required — the server refuses to start without it
PORT=3456 npm start
```

For a purely local setup (inline destinations, http:// or localhost targets) see [Configuration](#configuration).

---

## MCP Integration (no-code setup)

The fastest way to give any agent access to ZeroCreds is via the MCP server in `mcp/`. The agent gets two tools — `zerocreds_create_session` and `zerocreds_check_status` — and never touches the HTTP API directly.

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

**3. Restart the agent** — the tools `zerocreds_create_session` and `zerocreds_check_status` will appear automatically.

### MCP tools

**`zerocreds_create_session`** — create a form, get a URL to send to the user:
```
title, description, fields[], destination, ttl_minutes, notify
→ { token, url, expires_at }
```

**`zerocreds_check_status`** — poll until the user submits:
```
token
→ { status: "pending" | "done" | "expired" }
```

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

Returns `{ "status": "pending" | "done" | "expired" }`. An integrator only sees its own sessions — anyone else's token reports `expired`. `done` markers are kept for 24 hours.

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
| `ZEROCREDS_ADMIN_TOKEN` | — (required) | Admin bearer token. The server refuses to start without it. |
| `ZEROCREDS_HTTP_POST_ALLOWED_HOSTS` | empty (http_post disabled) | Comma-separated hostnames `http_post` may send to. |
| `ZEROCREDS_ALLOW_INLINE_DESTINATIONS` | off | `1` accepts inline destination objects and lets integrators add their own destinations. Local/dev only. |
| `ZEROCREDS_ALLOW_PRIVATE_DESTINATIONS` | off | `1` allows `http://` and private/loopback addresses for `http_post` and `vault`. Local/dev only. |
| `ZEROCREDS_PENDING_DIR`, `ZEROCREDS_TOKENS_DIR` | `~/connect-pending`, `~/agent-tokens` | Storage (created 0700). Expired session files are swept every 10 minutes. |
| `ZEROCREDS_DESTINATIONS_FILE`, `ZEROCREDS_INTEGRATORS_FILE` | `~/zerocreds-destinations.json`, `~/zerocreds-integrators.json` | Named destinations and integrator registry. |

Integrator records created by the old open `/api/register` (they carry an `email` but no `status`) are treated as pending until approved.

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
Environment=ZEROCREDS_ADMIN_TOKEN=your-token
Environment=ZEROCREDS_HTTP_POST_ALLOWED_HOSTS=hooks.example.com
User=vova

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now zerocreds-server
```

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
```

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
