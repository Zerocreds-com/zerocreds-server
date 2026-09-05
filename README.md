# ZeroCreds

**Self-hosted credential collection server for AI agents. Credentials never reach the LLM — the agent only sees `{ status: "ok" }`.**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-green.svg)](https://nodejs.org)

---

## The problem

AI agents need to connect to services on the user's behalf — but that means handling credentials. Passing login/password through the LLM context is a security risk: it can be logged, cached, or leaked through prompt injection.

## How it works

```
Agent                    ZeroCreds Server             User
  │                            │                        │
  ├─POST /api/session/create──►│                        │
  │  { fields, destination }   │                        │
  │◄─{ url, expires_at }───────┤                        │
  │                            │                        │
  ├─sends URL via Telegram ────────────────────────────►│
  │                            │                        │
  │                            │◄──GET /f/{token}───────┤
  │                            │────form HTML──────────►│
  │                            │◄──POST /f/{token}──────┤
  │                            │   { fields }           │
  │                            ├─writes to─────────────►│ Secret Store
  │                            │◄─{ ok }────────────────┤
  │                            │                        │
  ├─GET /session/{t}/status───►│                        │
  │◄─{ status: "done" }────────┤                        │
  │                            │                        │
  │ (never saw credentials)    │                        │
```

The agent learns credentials are saved — but never sees the values.

---

## Quick Start

```bash
git clone https://github.com/Zerocreds-com/zerocreds-server
cd zerocreds-server/server
npm install
npx playwright install chromium --with-deps   # only needed for nalog.ru

# Optional: protect session creation with a token
export ZEROCREDS_ADMIN_TOKEN=your-secret-token

PORT=3456 npm start
```

---

## API

### Create a form session

```
POST /api/session/create
Authorization: Bearer {ZEROCREDS_ADMIN_TOKEN}

{
  "title": "Connect GitHub",
  "description": "Paste your GitHub token with repo scope",
  "fields": [
    { "name": "token", "label": "GitHub Token", "type": "password", "required": true }
  ],
  "destination": "prod-gcp",          // named destination (recommended)
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

### Poll for completion

```
GET /api/session/{token}/status
Authorization: Bearer {ZEROCREDS_ADMIN_TOKEN}

← { "status": "pending" | "done" | "expired" }
```

### Field types

`text` · `password` · `email` · `tel` · `number` · `textarea`

---

## Destinations

Configure once in `~/zerocreds-destinations.json` (or `ZEROCREDS_DESTINATIONS_FILE`):

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

Agents reference destinations by name — credentials never travel in API requests.

### Write-only by design

| Destination | Mechanism | Guarantee |
|-------------|-----------|-----------|
| GCP Secret Manager | `roles/secretmanager.secretVersionAdder` | IAM: ZeroCreds can add but physically cannot read versions |
| AWS Secrets Manager | `secretsmanager:PutSecretValue` only | IAM policy: `GetSecretValue` not granted |
| HashiCorp Vault | `capabilities = ["create", "update"]` | Policy: `read` not listed = denied |
| Local file | `~/agent-tokens/{uid}/{name}` (0600) | Filesystem permissions |

---

## Built-in services (legacy)

The original API for pre-defined services is still supported:

| Service | Endpoint | Method |
|---------|----------|--------|
| nalog.ru (FNS) | `/connect/nalog` | Playwright login via Gosuslugi |
| GitHub | `/connect/github` | API token paste |
| Weeek CRM | `/connect/weeek` | API token paste |
| Tilda | `/connect/tilda` | Session cookie paste |

These use `~/connect-pending/{token}.json` files written by the agent.

---

## Security model

- **Credentials bypass LLM context** — the form posts directly to this server
- **One-time links** — tokens expire (default 30 min) and are deleted after use
- **Auditable** — `GET /version` returns the running git commit hash; match it to this repo
- **Self-hosted** — you control the server, the network, the storage
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

nginx proxy: route `/connect/*` and `/f/*` and `/api/*` to `:3456`.

---

## Contributing

Pull requests and issues are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

This project is MIT licensed — use it commercially, fork it, build on it.

---

## Claude Code Instructions

### Architecture

```
nginx (443/80)
  └── /connect/* /f/* /api/* → zerocreds-server :3456
  └── /                      → /home/vova/zerocreds-landing/ (static)

~/connect-pending/   ← agent writes (legacy) or server creates (dynamic API)
~/agent-tokens/      ← server writes (local_file destination)
~/zerocreds-destinations.json ← named destination configs (server reads at startup)
```

### Deployment

Server: `178.212.14.192` (Hostland RU VM)
Service: `zerocreds-server.service`
Landing: `/home/vova/zerocreds-landing/`
