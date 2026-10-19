# План работ: интеграция ZeroCreds в агент Trained Assist

> **Ссылки:** ZeroCreds #67 (Z10, umbrella), #91 (closed, sandbox API deployed), #71 (hardened forms), #72 (D1 wallet metadata), #125 (local bridge — параллельный поток).
> **MCP Host PRs:** #41 (wallet tools, merged), #42 (sandbox binding, merged), #57 (user sandbox, merged).
> **Ladder handoff:** commit `978e510` — Connected Apps передан ZeroCreds wallet, прототип удалён.

---

## Executive summary

**Цель:** агент на Trained Assist (Runner / OpenCode в VM / MCP Host) может безопасно запрашивать у пользователя креды (GitHub PAT, Cloudflare token, AWS keys, …), сохранять их в **OpenBao KV v2** под владельцем/профилем, а позже **использовать** их в изолированном запуске — не получая секрет в контекст модели, не в логах, не в артефактах.

**Архитектурная сделка (ZeroCreds ADR):**
- Форма: `wallet_form_create` → user-facing URL → browser submit → OpenBao write (secret) + D1 metadata (connectionId, owner, profile, OpenBao path/version).
- Использование: **broker** (отдельный компонент, читает OpenBao под run-scoped identity) → делает целевой API-вызов → возвращает агенту только **результат** (PR number, workflow run id, file listing, …).
- Модель/агент/ранер **никогда** не видят значение секрета. `connectionId` — opaque reference, не bearer token.

---

## Текущее состояние (2026-10-19)

| Слой | Что готово | Что не готово |
|---|---|---|
| **ZeroCreds sandbox API** | `https://zerocreds-wallet-api-sandbox.skillset-apply.workers.dev` (Container + ephemeral OpenBao + D1 Worker) ✓ | Production OpenBao + production Worker + TLS + backup/unseal/audit |
| **ZeroCreds MCP tools** | 4 wallet tools в `mcp/provider.js`; пакет `@zerocreds/mcp/provider@0.2.0` (не опубликован); assertion verifier ✓ | Публикация пакета, версия зафиксирована в host-catalog digest |
| **MCP Host** | Wallet provider скомпонован в human catalog; tools видны authorised users; Ed25519 assertions signing (`resolveBindings`) ✓ | Production issuer keys / profile mapping / caller audiences не задеплоены |
| **Runner API (CF)** | Control Plane / RunCoordinator / VM worker запускают opencode; env-allowlist работает (`LLM_LADDER_TOKEN`) ✓ | **`credentialBindings` — 422 FEATURE_UNSUPPORTED**; no `profileWorkspace`; no ingressManifest |
| **VM Worker** | `eu-vm-agent-run` (France VM2); `per_run_unix_identity`; GCS storage; `setpriv --clear-groups` ✓ | Нет канала для доставки секрета в run (binding → env/MCP) |
| **Ladder / Connected Apps** | Handoff документ (commit `978e510`); прототип удалён; identity `verifyKey()` → owner/profile mapping ✓ | Ladder UI для wallet connections, owner-authorized connection list, rotate flow |
| **ZeroCreds local (Mac)** | `http://localhost/zerocreds` + 13 MCP tools; keychain destination `mac-keychain`; form "Saved to" ✓ | Bridge для GitHub-операций без выдачи секрета агенту (#125) |

---

## Фаза 0 — Подготовка (ZeroCreds production hardening) — *блокирует всё*

| ID | Задача | Ответственный | DoD |
|---|---|---|---|
| Z0.1 | **Merge PR #71** (hardened forms: named destinations only, admin token, allowlisted http_post, anonymous session migration) | ZeroCreds team | PR #71 в main; production auto-deploy branch обновлён; legacy integrators audited/rotated |
| Z0.2 | **Merge PR #72** (D1 wallet metadata Worker standalone) | ZeroCreds team | Worker деплоен в sandbox + prod D1; migrace `0002_assertion_replay.sql` применена |
| Z0.3 | **Provision production OpenBao** (TLS, per-owner KV-v2 mount, scoped writer/probe/reader identities, audit devices, backup, unseal/recovery runbook, monitoring) | Infra | OpenBao доступен по prod endpoint; writer может create/update только `secret/data/owners/{ownerId}/connections/*` + `probes/*`; reader — read-only на `connections/*` |
| Z0.4 | **Deploy production wallet Worker** (connect to prod OpenBao mount, `WALLET_SERVICE_TOKEN` secret, `ZEROCREDS_WALLET_ASSERTION_ISSUERS_FILE` с prod issuer keys/profile mapping) | ZeroCreds team | Worker отвечает на `/api/wallet/*`; replay guard работает; probe/cleanup policies валидны |
| Z0.5 | **Publish `@zerocreds/mcp/provider@0.2.0`** (immutable Git commit, pinned digest in host catalog) | ZeroCreds team | Пакет установлен в MCP Host; `tools.zerocreds.wallet_*` доступны через composed provider |
| Z0.6 | **Configure production issuer keys & profile mapping** в `ZEROCREDS_WALLET_ASSERTION_ISSUERS_FILE` (MCP Host `kid` → `profiles[profile_id] = {owner_id, destination, callers}`) | MCP Host team | Sandbox + prod mappings разные; key rotation процедура документирована |

**Риски:** OpenBao ops expertise; migration legacy анонимных сессий (340 unfinished за 30 дней); PR #71 требует операторский аудит ключей.

---

## Фаза 1 — Runner wire-up: credentialBindings & profileWorkspace (unblocks use)

| ID | Задача | Репозиторий / Компонент | DoD |
|---|---|---|---|
| R1.1 | **Lift 422 на `credentialBindings`** в `src/cloudflare/run-coordinator.ts:208` — реализовать поддержку `credentialBindings` в CF Runner API: парсинг, валидация, прокидывание в `LaunchRequest` | ai-agent-runner / `run-coordinator.ts` | POST `/v1/runs` с `credentialBindings: [{scope, bindingRef}]` → 201, binding приходит в `LaunchRequest.credentialBindings` |
| R1.2 | **Profile workspace** — включить `profileWorkspace` в CF Runner API (наподобие Node API); D1 trace storage для профилей не путать с wallet D1 | ai-agent-runner / `run-coordinator.ts`, `runner-api.ts` | `profileWorkspace` в запросе → workspace создаётся/подключается к run |
| R1.3 | **Mapping wallet `connectionId` → Runner `credentialBinding`**: новый тип биндинга `wallet_connection` с полями `connection_id`, `provider`, `scope`; резолвер в `run-coordinator` / `external-worker-adapter` | ai-agent-runner / `src/adapters/remote-mcp.ts` (новая ветка резолвера), `src/release/placement.ts` | `LaunchRequest` содержит `credentialBindings` с `scope: github:repo` + `bindingRef: connectionId`; runner передаёт в VM worker |
| R1.4 | **VM worker: deliver binding value** — в `src/vm-worker/main.ts` / `http-server.ts`: на основе `LaunchRequest.credentialBindings` запросить у брокера/ZeroCreds секрет и прокинуть как **env var** (`GITHUB_TOKEN`, `CF_API_TOKEN` и т.д.) **только в процесс движка** (opencode), не в лог | ai-agent-runner / `vm-worker` | В env процесса opencode появляется `GITHUB_TOKEN=<value-from-openbao>`; в логах — только `bindingRef` |
| R1.5 | **Runner-side authorization**: проверка `ownerId == run.owner`, `profileId` ∈ `run.allowedProfiles`, `scope` ⊆ `requestedScope` перед доставкой значения | ai-agent-runner / `run-coordinator.ts`, `external-worker-adapter.ts` | Чужой `connectionId` → 403; только авторизованные scope → env |

**Примечание:** Фаза 1 доставляет секрет в **env процесса агента** (простейший паттерн). Это работает для `gh`, `git`, `cf`, `aws`, `gcloud` CLI — они читают стандартные env vars. MCP bridge (фаза 2) даст более тонкий контроль.

---

## Фаза 2 — Credential-use broker (MCP capability, value-free для агента)

| ID | Задача | Компонент | DoD |
|---|---|---|---|
| B2.1 | **Спецификация broker capability**: `github.create_pull_request` (или `github.dispatch_workflow`), `cloudflare.list_zones`, `aws.secretsmanager.get_secret_value` — один provider на первый слайс | ZeroCreds / Runner | Описание в `docs/BROKER-CAPABILITY-SPEC.md`: входы (connectionId, operation, resource, params), выходы (value-free), audit fields |
| B2.2 | **Broker implementation**: отдельный Worker / service (не в ZeroCreds core), читает OpenBao под reader identity, выполняет узкий API-вызов, возвращает только JSON-результат | ZeroCreds (new: `wallet-broker` Worker) | `POST /broker/use` с `connectionId`, `operation`, `params` → 200 + result; секрет не в ответе; audit record в D1 |
| B2.3 | **MCP capability wrapper** в `trained-assist-mcp-host`: новый tool `wallet_broker_use` (или `wallet.github.create_pr`), `allowedTools` ограничен, `authorize` проверяет run binding | trained-assist-mcp-host | Агент вызывает `wallet.github.create_pr {connectionId, ...}` → broker → результат; секрет не в MCP result |
| B2.4 | **Runner integration**: `credentialBinding` с `broker: true` флагом; `LaunchRequest` включает `brokerUrl` + `brokerToken` (scoped per-run) | ai-agent-runner / broker | Агент в run может дергать broker; без run — 403 |
| B2.5 | **E2E test**: sandbox run → `wallet_form_create` (GitHub) → user submit → `wallet_form_status`=done → run с `credentialBinding` → `wallet.github.create_pr` → PR создан → секрет не в status/history/artifacts | All | Зелёный sandbox E2E в CI |

---

## Фаза 3 — Production hardening & onboarding

| ID | Задача | DoD |
|---|---|---|
| H3.1 | **Operator migration** (PR #71 completion): rotate legacy integrator keys, named destinations, allowlist, admin token file; disable anonymous sessions | Production env: 0 анонимных сессий; все интеграторы имеют статус |
| H3.2 | **Revocation & rotation UX**: owner-authorized connection list (MCP tool), `wallet_connection_revoke` + `wallet_connection_rotate` (new OpenBao version, same connectionId) | Агент/пользователь может отозвать/ротировать; старый `connectionId` → 404 на использовании |
| H3.3 | **Retention & cleanup**: TTL для OpenBao versions, D1 cleanup job для expired/revoked connections, probe cleanup policy | Нет мёртвых данных старше политики |
| H3.4 | **Observability**: structured logs (ownerId, profileId, connectionId, operation, outcome — no values), metrics (forms created/submitted, broker calls, revocations), alerting на OpenBao health | Дашборд + алерты |
| H3.5 | **Rollback switch**: feature flag в MCP Host `zerocreds_wallet_enabled` — отключает provider без затрагивания существующих connections | Отключение за <1 мин, connections остаются рабочими при re-enable |

---

## Фаза 4 — Local Mac bridge (ZeroCreds #125) — параллельно, не блокирует прод

| ID | Задача | DoD |
|---|---|---|
| L4.1 | **Destination `github_cli`**: писать в macOS Keychain сервис `gh:github.com`, account = resolved GitHub login (server-side `GET /user` на отправленном токене) | `gh auth status` показывает аккаунт; `git push` работает |
| L4.2 | **Safe bridge tool**: `zerocreds.github_use {connectionId, operation, params}` → локальный ZeroCreds читает keychain, выполняет `gh`/`curl` под сущностью пользователя, возвращает только результат | Агент не видит токен; работает `gh pr create`, `gh api`, `git push` |
| L4.3 | **Audit log** в локальном ZeroCreds: кто (owner/profile), какой `connectionId`, какая операция, когда, исход | Лог не содержит секретов |

---

## Зависимости и критический путь

```
Z0.1 → Z0.2 → Z0.3 → Z0.4 → Z0.5 → Z0.6
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    ▼                     ▼                     ▼
               R1.1-R1.5            B2.1-B2.5            L4.1-L4.3
               (Runner              (Broker               (Local
                wire-up)             capability)           bridge)
                    │                     │                     │
                    └─────────────────────┼─────────────────────┘
                                          ▼
                                   H3.1-H3.5
                                   (Production
                                    hardening)
```

**Blocking items:**
- Z0.1 (PR #71) — требует операторский аудит 10 legacy интеграторов.
- Z0.3 (prod OpenBao) — infra lead time (TLS, backup, audit, unseal runbook).
- R1.1 (lift 422) — архитектурное решение в Runner API (сегодня Cloudflare Worker path не поддерживает `credentialBindings`); потребует ревью Control Plane контракта.

---

## Issues / PRs для отслеживания

| Репозиторий | Issue/PR | Название | Статус |
|---|---|---|---|
| Zerocreds-com/zerocreds-server | #67 | Z10: ServerlessAgence owner-scoped credential intake and runner binding | OPEN (umbrella) |
| Zerocreds-com/zerocreds-server | #71 | Hardened API forms (named destinations, admin token, allowlists) | OPEN |
| Zerocreds-com/zerocreds-server | #72 | D1 wallet metadata Worker | OPEN |
| Zerocreds-com/zerocreds-server | #91 | Deploy/configure non-production wallet API | CLOSED ✓ |
| Zerocreds-com/zerocreds-server | #125 | feat(local): gh destination + safe bridge | OPEN |
| trained-assist/ai-agent-runner | — | Lift 422 on credentialBindings in CF Runner API | NEW |
| trained-assist/ai-agent-runner | — | VM worker env delivery for credentialBindings | NEW |
| trained-assist/ai-agent-runner | — | Broker capability + MCP wrapper | NEW |
| trained-assist/trained-assist-mcp-host | #41 | Register ZeroCreds wallet tools for authorized users | MERGED ✓ |
| trained-assist/trained-assist-mcp-host | #42 | Configure ZeroCreds wallet sandbox binding | MERGED ✓ |
| trained-assist/trained-assist-mcp-host | #57 | Provision ZeroCreds user sandbox | MERGED ✓ |

---

## Риски и митигации

| Риск | Вероятность | Влияние | Митигация |
|---|---|---|---|
| **OpenBao production ops** (unseal, backup, audit) не готовы к дедлайну | High | Блокирует Z0.3 → всё | Запустить OpenBao staging параллельно; использовать managed Vault (HashiCorp Cloud) как fallback для sandbox |
| **PR #71 migration legacy integrators** затягивается | Medium | Блокирует Z0.1 | Explicit compatibility window (2 недели) с_feature_flag_ `allow_legacy_inline_destinations`; параллельный аудит ключей |
| **Runner API `credentialBindings`** требует изменения Control Plane контракта (D1 trace, task-store) | High | Блокирует R1.1 | Минимум: env-delivery (R1.4) без полного `credentialBindings` — достаточно для CLI tools; broker — след. фаза |
| **Два конкурирующих custody path** (Ladder D1 encrypted vs ZeroCreds OpenBao) | Low (handoff done) | Путаница / duplication | Handoff doc `connected-apps-zerocreds-handoff.md` зафиксирован; Ladder D1 migration `0010_connected_credentials.sql` откатан; enforcer в CI: запрет записи кредов в Ladder trace D1 |
| **Secret leakage в broker/logs/artifacts** | Medium | Security incident | Code review checklist: `no-value-in-response`, `no-value-in-log`, `audit-record-value-free`; автоматизированные тесты сканируют выводы на наличие токен-паттернов |
| **Key rotation / issuer key compromise** | Low | Credential theft | Ed25519 JWS с `kid`, `jti` replay guard (уже в D1 Worker); процедура ротации: добавить новый `kid` → переключить issuer → удалить старый после TTL |

---

## Оценка трудоёмкости (инженер-недели)

| Фаза | Задачи | Оценка (чел.-нед.) | Зависит от |
|---|---|---|---|
| Z0 | 0.1–0.6 | 4–6 | Infra (OpenBao), Security review |
| R1 | 1.1–1.5 | 3–4 | Z0.4–Z0.6 |
| B2 | 2.1–2.5 | 4–5 | R1.3–R1.5 |
| H3 | 3.1–3.5 | 2–3 | B2.5 green |
| L4 | 4.1–4.3 | 1–2 | ZeroCreds #125 (параллельно) |
| **Total** | | **14–20** | — |

---

## Критерии готовности (Definition of Done)

1. **Sandbox E2E**: агент в sandbox run создаёт форму (`wallet_form_create`), пользователь сабмитит PAT, `wallet_form_status` → `done`, run с `credentialBinding` вызывает `wallet.github.create_pr` → PR создан в целевом репо; **в run status/history/artifacts нет секрета**.
2. **Production smoke**: та же цепочка на prod Worker + prod OpenBao; TLS, audit, backup пройдены.
3. **Local bridge**: `zerocreds.github_use` делает `gh pr merge` с PAT из keychain; агент не видит токен; `gh auth status` не сломан.
4. **Rollback**: feature flag выключает wallet provider в MCP Host за <1 мин; существующие connections продолжают работать при повторном включении.
5. **Security audit**: внешний аудит custody boundary (OpenBao writer/reader separation, D1 no-values, broker no-read) — PASS.

---

## Следующие конкретные шаги (на этой неделе)

1. **ZeroCreds**: ревью/мерж PR #71 (приоритет #1) → PR #72.
2. **Infra**: запуск staging OpenBao (HCP Vault или self-hosted) + writer/reader policies + canary preflight.
3. **Runner API**: задача R1.1 (lift 422) — оформить как issue в `trained-assist/ai-agent-runner`, назначить владельца, начать прототип env-delivery.
4. **MCP Host**: проверить, что composed provider digest (`483e6d2f...`) совпадает с опубликованным пакетом; добавить production issuer keys в секрет `ZEROCREDS_WALLET_ASSERTION_ISSUERS_FILE` (Wrangler secret).
5. **Ladder**: убедиться, что `connected-apps-zerocreds-handoff.md` в main ветке Ladder (PR) и старый Connected Apps код удалён из CI.
6. **Local bridge (#125)**: начать параллельно `github_cli` destination + `github_use` tool — не блокирует прод.

---

## Контакты / владельцы зон

| Зона | Репозиторий | Владелец |
|---|---|---|
| ZeroCreds wallet API / OpenBao / D1 Worker | Zerocreds-com/zerocreds-server | vova |
| MCP Host composition / assertions | trained-assist/trained-assist-mcp-host | vova |
| Runner API (CF) / VM worker | trained-assist/ai-agent-runner | vova |
| Ladder identity / Connected Apps handoff | trained-assist/trained-assist-llm-ladder-zerocreds | vova |
| Local Mac bridge / opencode integration | Zerocreds-com/zerocreds-server | vova |

---

*План живёт в этом документе. Обновления — через PR в репозитории ZeroCreds (docs/integration-plan.md) с ссылками на соответствующие issues.*