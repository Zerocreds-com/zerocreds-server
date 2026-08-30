# zerocreds.ru

Self-hosted auth form server. Credentials never reach the LLM context — they go directly to your machine.

## How it works

An AI agent generates a one-time link and sends it to the user via Telegram. The user opens the link, fills the form, and credentials are saved locally on the agent's machine. The LLM only receives `{ status: "ok" }`.

## Services supported

| Service | Method |
|---------|--------|
| nalog.ru | Playwright login via Госуслуги (headless browser) |
| GitHub | API token paste |
| Weeek CRM | API token paste |
| Tilda | Session cookie paste |

## Running the server

```bash
cd server
npm install
npx playwright install chromium --with-deps
PORT=3456 npm start
```

## Pending token format

The agent creates `~/connect-pending/{32-hex-token}.json`:

```json
{
  "uid": "123456789",
  "service": "nalog",
  "expires": 1700000000000,
  "tg_bot_token": "optional",
  "tg_chat_id": "optional"
}
```

After form submission, credentials are saved to `~/agent-tokens/{uid}/{service}`.

## Auditability

`GET /version` returns the running git commit hash. A security specialist can:
1. Check `https://your-vm/version` for the commit hash
2. Match it to the GitHub source code
3. Verify the form does exactly what it says

## Claude Code Instructions

### Architecture

```
nginx (443/80)
  └── /connect/* → zerocreds-server :3456
  └── /          → /home/vova/zerocreds-landing/ (static)

zerocreds-server shares filesystem with trained-assist-agent:
  ~/connect-pending/   ← agent writes, zerocreds-server reads
  ~/agent-tokens/      ← zerocreds-server writes, agent reads
```

### Deployment

Server: `178.212.14.192` (Hostland RU VM)
Service: `zerocreds-server.service`
Landing: `/home/vova/zerocreds-landing/`
