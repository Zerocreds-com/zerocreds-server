# ZeroCreds

**Open-Source credential collection server for AI agents. Credentials never reach the LLM — the agent only sees `{ status: "ok" }`.**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-green.svg)](https://nodejs.org)

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
npm install

export ZEROCREDS_ADMIN_TOKEN=your-secret-token
PORT=3456 npm start
```

---

## Agent Integration

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
  "destination": "prod-gcp",           // named (recommended) — OR inline object (see below)
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
| `allow_save` | boolean | no | Allow browser to remember non-password fields (default: `true`). Set `false` for ephemeral sessions like OTPs. |

### Field definition

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Key in the saved JSON (`[a-zA-Z0-9_]`, max 64) |
| `label` | string | yes | Label shown on the form |
| `type` | string | no | `text` · `password` · `email` · `tel` · `number` · `textarea` · `url` (default: `text`) |
| `placeholder` | string | no | Input placeholder |
| `required` | boolean | no | Default: `true` |

### GET /api/session/{token}/status

Returns `{ "status": "pending" | "done" | "expired" }`.

### GET /version

Returns the running git commit hash. Compare it to this repo for security audits.

---

## Destinations

Two ways to pass `destination` in the API:

**Named (recommended)** — configure once in `~/zerocreds-destinations.json` (or `ZEROCREDS_DESTINATIONS_FILE`), reference by name. SA keys never travel through API requests.

**Inline object** — pass the destination config directly in the API call. Simpler for local/dev setups, but means credentials are in the request body.

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

**Inline destination** (pass directly in API call — simpler for dev/local, but config travels in the request):

```json
{
  "destination": {
    "type": "local_file",
    "uid": "123456",
    "filename": "github"
  }
}
```

### Write-only by design

| Destination | Mechanism | Guarantee |
|-------------|-----------|-----------|
| GCP Secret Manager | `roles/secretmanager.secretVersionAdder` | IAM: ZeroCreds can add but cannot read versions |
| AWS Secrets Manager | `secretsmanager:PutSecretValue` only | IAM policy: `GetSecretValue` not granted |
| HashiCorp Vault | `capabilities = ["create", "update"]` | Policy: `read` not listed = denied |
| Local file | `~/agent-tokens/{uid}/{name}` (0600) | Filesystem permissions |

---

## Form UX

The form the user sees has a few conveniences:

- **Password fields** — show/hide toggle (👁) and a **Paste** button that reads the clipboard, since most passwords are copy-pasted
- **Remember me** — a "Save for next time" checkbox. When checked, non-password fields (email, username, etc.) are stored server-side, keyed to a browser cookie (`zc_uid`). On the next visit from the same browser, those fields are pre-filled. Passwords are never saved. Set `allow_save: false` in the session to disable this entirely.

---

## Security model

- **Credentials bypass LLM context** — the form posts directly to ZeroCreds, never through the agent
- **One-time links** — tokens expire (default 30 min) and are deleted after use
- **Write-only destinations** — ZeroCreds can write to secret stores but not read from them (IAM/policy enforced)
- **Input escaping** — all user-supplied session metadata (title, field labels) is HTML-escaped before rendering
- **Auditable** — `GET /version` returns the running git commit hash; compare to this repo to verify no modifications
- **No telemetry** — nothing leaves your machine except to the configured secret store

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
~/agent-tokens/             ← server writes (local_file destination)
~/zerocreds-saved/          ← server writes non-password field values per browser uid
~/zerocreds-destinations.json ← named destination configs (server reads at startup)
```

### Deployment

Server: `178.212.14.192` (Hostland RU VM)
Service: `zerocreds-server.service`
Landing: `/home/vova/zerocreds-landing/`
