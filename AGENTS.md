# Repository instructions

AGENTS.md — короткая точка входа. Основные инструкции, команды, среды и порядок deploy описаны в [README.md](README.md); здесь не дублируются.

## Credentials

Используйте macOS Keychain; секреты не печатаются и не попадают в файлы:

### Login Keychain (legacy / прямые обращения)
- **GitHub default PAT** (gh CLI): service `github.com`, account `kobzevvv`, label `Trained Agent GitHub Token`. Используется `gh` CLI и Codex.
- **Azure/GHA PAT** (`gha-compute-cluster`): service `github.com`, account `gha-compute-cluster`, label `GHA Compute Cluster GitHub PAT`. Используется CI/CD.
- **Cloudflare sandbox** (`trained-assist-sandbox`): service `cloudflare.com`, account `trained-assist-sandbox`, expected account `d740a05e9442c1d0feacae2dfc673e93`. Это **Trained Assist** (не Typeform!) — сервис для работы с LLM/агентами.
- `gh:github.com` / `kobzevvv` — кэш `gh` CLI (не трогать).

### ZeroCreds catalog (через MCP `connections_list` / `connection_verify`)
Все секреты хранятся в Keychain под service `zerocreds`:
- `github-admin` — **канонический** classic PAT `kobzevvv` (20 scopes). Алиасы `gha-compute-cluster` и `github-admin-shared-f7a596` были дублями и **удалены 2026-10-28**.
- `github-flexi-crm` — fine-grained PAT `kobzevvv` (узкие права на репозиторий).
- `github-zen-rings` — classic PAT `vovalikessmoothy-png` (21 scope, включает `delete_repo`), Zen-Rings CI/CD.
- `trained-assist-sandbox` — Cloudflare API Token для **Trained Assist** (аккаунт `Typeformowner@gmail.com`, id `d740a05e...`). Имеет **максимальные права** (Workers Admin, K2, Websearch, DNS, Access, Registrar...). Истекает 2027-10-09. Дубликаты `trained-assist-sandbox-alt`, `trained-assist-cloudflare-admin`, `trained-assist-sandbox-refresh`, `trained-assist-sandbox-refresh-2` — **удалены 2026-10-28**.
- `chemistry-gpt-deepgram` — Deepgram API key для chemistry-gpt.
- `flexi-test-bot` — Weeek API key (verify unsupported).
- `ru-host-admin` — SSH ключ (verify unsupported).

> ⚠️ **Путаница, которую частые агенты делают:**
> - `gha-compute-cluster` в **login keychain** — это отдельный Azure PAT (service `github.com`). В **ZeroCreds catalog** алиас `gha-compute-cluster` БЫЛ дублем `github-admin` и **удален**. Не путайте!
> - Cloudflare аккаунт называется «Typeformowner@gmail.com's Account», но это **Trained Assist** сервис, не Typeform. Агенты часто путаются из-за названия аккаунта в Cloudflare Dashboard.

### Передача кредов коллеге
Если владелец просит передать сохранённую креду коллеге, отвечайте на языке владельца и простыми словами. Найдите точный `connection_id` и вызовите `share_options`. До создания ссылки спросите, передавать ли её через указанный сайт ZeroCreds или напрямую с этого компьютера. Объясните: через ZeroCreds ссылка проходит по сайту, но сам секрет зашифрован и сайту не виден; напрямую сайт не участвует, зато коллеге нужно подключиться к этому компьютеру через интернет, а для этого иногда меняют настройку роутера. Если это звучит сложно или недоступно, предложите ZeroCreds. При неоднозначности выбора спросите, какую именно креду передать. После выбора соединения и способа вызовите `share_create`: передавайте только одноразовую ссылку, не значение секрета. Поясните, что владелец отправит полную ссылку через доверенный канал, агент коллеги с локальным ZeroCreds сохранит креду в Keychain; компьютер отправителя должен быть включён и подключён к интернету. Для GitHub PAT предупредите, что коллега получит доступ от имени владельца. Если инструментов передачи нет, проверьте MCP и предложите переподключить ZeroCreds вместо общего отказа.

## Sandbox / deploy

Порядок sandbox, проверок, deploy и rollback берётся из README.md и referenced docs/workflows этого репозитория.
После merge нельзя считать задачу завершённой без deploy/verify по этому порядку.
Самые опасные изменения — запреты/ограничения прав; они требуют собранного evidence.