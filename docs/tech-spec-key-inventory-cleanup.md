# ТЗ: Инвентаризация ключей, удаление дубликатов, добавление пояснений

**Сессия:** Локальная инвентаризация ZeroCreds  
**Цель:** Полная инвентаризация всех сохранённых кред (Keychain + catalog), удаление дубликатов, добавление человекочитаемых пояснений  
**Срок:** 1 сессия (2–4 часа)  
**Ограничение:** Только чтение и ручное управление через MCP-инструменты; автоматическая очистка — по явному подтверждению пользователя

---

## 1. Диагноз: что сейчас не так

### 1.1. Дубликаты в Keychain

В macOS Keychain сейчас есть **минимум 3 GitHub-токена для одного аккаунта `kobzevvv`**:

| Keychain Service | Account | Label | Что это |
|-----------------|---------|-------|---------|
| `trained-agent-github-token` | `kobzevvv` | Trained Agent GitHub Token | ✅ «Main» токен (из AGENTS.md) |
| `github.com` | `kobzevvv` | Trained Agent GitHub Token | ❓ Дубль или другой токен? |
| `gh:github.com` | `kobzevvv` | (нет) | ❓ Кеш `gh` CLI? |

Плюс отдельные:
- `github.com` / `gha-compute-cluster` — Zen-Rings CI/CD PAT
- `zerocreds` / `github-github-admin` — ZeroCreds-запись
- `zerocreds` / `github-github-flexi-crm` — ZeroCreds-запись
- `zerocreds` / `github-github-zen-rings` — ZeroCreds-запись

**Проблема:** Непонятно, какой из `github.com` токенов для `kobzevvv` — активный, а какой — мусор.

### 1.2. ZeroCreds catalog: несогласованность

В `~/.config/zerocreds/local/connections.json` сейчас **5 GitHub-записей**, но проверка через `connection_verify` показывает:

| Account Alias | Verification | Identity | Permissions | Что видно |
|---------------|--------------|----------|-------------|-----------|
| `github-flexi-crm` | `valid` | `kobzevvv` (id: 24790956) | `[]` (unknown) | ⚠️ **Неизвестные права** |
| `github-admin` | `valid` | `kobzevvv` (id: 24790956) | 20 scopes | ✅ Полные права |
| `gha-compute-cluster` | `unavailable_here` | — | — | ❌ **Недоступен отсюда** |
| `github-admin-shared-f7a596` | `unknown` | — | — | ❓ **Никогда не проверялся** |
| `github-zen-rings` | `valid` | `vovalikessmoothy-png` (id: 269787219) | 21 scopes | ✅ Другой аккаунт! |

**Проблема:** 
- `github-flexi-crm` и `github-admin` — оба для `kobzevvv`, но с разными правами (или `flexi-crm` просто не имеет `permission_evidence`).
- `github-admin-shared-f7a596` — неизвестно что это.
- `gha-compute-cluster` — нечитаем отсюда (возможно, другой machine).

---

## 2. Какие инструменты нужны (и каких не хватает)

### 2.1. Что уже есть ✅

| Инструмент | Что делает | Готовность |
|------------|-----------|------------|
| `discovery_preview` | Показывает кандидатов из CLI/Keychain | ✅ Работает |
| `connections_list` | Список записей catalog | ✅ Работает |
| `connection_verify` | Проверяет токен против провайдера | ✅ Работает (github, cloudflare, deepgram) |
| `connection_delete` | Удаляет запись из catalog + Keychain | ✅ Работает |
| `doctor` | Диагностика инфраструктуры | ✅ Работает |

### 2.2. Чего не хватает (Gap Analysis)

#### Gap 1: Нет «отпечатка» токена (Fingerprinting)

**Сейчас:** `connection_verify` возвращает `identity.id` (user ID), но **не показывает реальные возможности** токена.

**Пример проблемы:**
```
github-flexi-crm → login: kobzevvv, permissions: [] (unknown)
github-admin     → login: kobzevvv, permissions: [20 scopes]
```
Визуально — это один и тот же человек, но непонятно:
- Видит ли `flexi-crm` те же репозитории?
- Может ли писать в `admin`?
- Это `classic PAT` или `fine-grained`?

**Что нужно:**
- Добавить в `connection_verify` поле `capabilities`:
  ```json
  {
    "capabilities": {
      "repository_count": 42,
      "organization_count": 3,
      "can_write_repos": ["owner/repo1", "owner/repo2"],
      "token_type": "fine-grained",
      "expires_at": "2027-10-09"
    }
  }
  ```
- Или хотя бы `repository_count` и `organization_count` — чтобы сразу видеть разницу.

**Как реализовать (для GitHub):**
```javascript
// GET /user → id, login
// GET /user/repos?per_page=100&page=1 → count + names
// GET /user/orgs → org count
// GET /user/installations/installations → installations (для fine-grained)
```

#### Gap 2: Нет редактирования метаданных (Metadata Editing)

**Сейчас:** В `connections.json` поля `description`, `tags`, `notes` — **не существуют**.

**Пример проблемы:** Запись `github-admin-shared-f7a596` — что это? Когда создана? Для чего? Непонятно.

**Что нужно:**
- Добавить в `connections.json` поля:
  ```json
  {
    "connection_id": "...",
    "provider": "github",
    "account_alias": "github-admin",
    "description": "Main admin PAT для Zerocreds-com org",
    "tags": ["admin", "production", "zen-rings"],
    "notes": "Создан 2026-10-20, используется для деплоя",
    "superseded_by": null,
    "duplicate_of": null
  }
  ```
- Добавить MCP-инструмент `connection_update`:
  ```javascript
  server.tool('connection_update',
    'Update metadata for a saved connection: description, tags, notes. Use to mark duplicates (duplicate_of), deprecated credentials (superseded_by), or add context for humans.',
    {
      connection_id: z.string(),
      description: z.string().optional(),
      tags: z.array(z.string()).optional(),
      notes: z.string().optional(),
      superseded_by: z.string().optional().describe('connection_id that replaces this one'),
      duplicate_of: z.string().optional().describe('connection_id this one duplicates'),
    },
    ...
  );
  ```

#### Gap 3: Нет bulk-операций (Bulk Operations)

**Сейчас:** Каждое действие — отдельный вызов. Для инвентаризации из 13 записей это 13 × `connection_verify` + ручной анализ.

**Что нужно:**
- Добавить `connections_verify_all`:
  ```javascript
  server.tool('connections_verify_all',
    'Verify all (or filtered) connections and return a consolidated report: identity, permissions, capabilities, and duplicate detection.',
    {
      provider: z.string().optional(),
      include_capabilities: z.boolean().optional(),
    },
    ...
  );
  ```
- Или хотя бы CLI-скрипт `scripts/audit-connections.sh`, который делает то же самое.

#### Gap 4: Нет визуального сравнения (Visual Comparison)

**Сейчас:** Агент видит JSON и должен сам сравнивать массивы scopes.

**Что нужно:**
- В `connections_list` добавить `duplicate_candidates`:
  ```json
  {
    "connections": [...],
    "duplicate_candidates": [
      {
        "reason": "same_identity",
        "identity": { "id": "24790956", "login": "kobzevvv" },
        "connection_ids": ["...flexi-crm", "...admin"],
        "differences": {
          "permissions": { "flexi-crm": "[]", "admin": "[20 scopes]" },
          "repository_count": { "flexi-crm": "42", "admin": "128" }
        }
      }
    ]
  }
  ```

#### Gap 5: Discovery не показывает реальные capability

**Сейчас:** `discovery_preview` возвращает только `scopes` из `gh auth status`, но не показывает:
- Сколько репозиториев видит токен
- Какие именно
- Есть ли `write` доступ

**Пример проблемы:**
```json
{
  "ref": "disc_efd277ac77bc32859321ee88",
  "provider": "github",
  "account": "kobzevvv",
  "scopes": [],  // ← пусто!
  "display_label": "GitHub Token (Project: kobzevvv)"
}
```
Пустой массив `scopes` — это что? Токен без прав? Или просто `gh auth status` не вернул scopes?

**Что нужно:**
- В `scanGithub` добавить вызов `gh api /user` и `gh api /user/repos` для получения:
  - `capabilities.repository_count`
  - `capabilities.organization_count`
  - `capabilities.can_write` (есть ли хотя бы один repo с write)

#### Gap 6: auth_check не показывает repository diff

**Сейчас (в PR #187):** `auth_check` показывает `identity_mismatch` и `permissions_changed`, но не показывает **какие именно репозитории** изменились.

**Пример:**
```json
{
  "conflicts": [{
    "kind": "permissions_changed",
    "detail": "provider now reports different permissions",
    "recorded_permissions": ["repo", "admin:org"],
    "live_permissions": ["repo", "admin:org", "workflow"]
  }]
}
```
Это полезно, но не показывает:
- Был ли добавлен доступ к новому репозиторию
- Был ли удалён доступ к старому

**Что нужно (nice-to-have):**
- В `auth_check` добавить `capabilities_diff`:
  ```json
  {
    "capabilities_diff": {
      "repository_count": { "recorded": 42, "live": 43, "delta": "+1" },
      "new_repos": ["new-repo"],
      "removed_repos": ["old-repo"]
    }
  }
  ```

---

## 3. План действий для сессии инвентаризации

### Этап 1: Сбор данных (read-only)

1. **Запустить `doctor`** — убедиться, что инфраструктура работает.
2. **Запустить `discovery_preview`** для `github_cli` + `macos_keychain` — собрать всех GitHub-кандидатов.
3. **Запустить `connections_list?provider=github`** — получить все записи catalog.
4. **Для каждой записи вызвать `connection_verify`** — собрать `identity` + `permissions`.
5. **Сопоставить:**
   - Кто `login: kobzevvv` → какие `permissions` → какой `account_alias`?
   - Какие записи нечитаемы (`unavailable_here`) → пометить как «проверить на другой машине»?
   - Какие записи `unknown` → вызвать `auth_check` (после merge PR #187)?

### Этап 2: Анализ дубликатов

Для каждого `identity.id` найти все `connection_id`:
- Если один `identity.id` → несколько `connection_id`:
  - Сравнить `permissions` (если оба `provider_verified`).
  - Если `permissions` одинаковые → **дубликат**.
  - Если `permissions` разные → **разные токены** (оставить оба, но добавить `description`).

Пример вывода:
```
Identity: kobzevvv (id: 24790956)
├── github-flexi-crm (permissions: unknown)
├── github-admin (permissions: 20 scopes)
└── github-admin-shared-f7a596 (permissions: unknown)

Решение: 
- github-admin → ✅ Оставить (основной)
- github-flexi-crm → ❓ Проверить: если permissions == github-admin → удалить
- github-admin-shared-f7a596 → ❓ Проверить: если не используется → удалить
```

### Этап 3: Очистка

1. **Для каждого дубликата:**
   - Спросить пользователя: «Удалить `github-flexi-crm`? Это дубликат `github-admin` с теми же правами».
   - Если да → `connection_delete(connection_id)`.
2. **Для нечитаемых записей:**
   - Спросить: «`gha-compute-cluster` недоступен отсюда. Удалить или оставить?».

### Этап 4: Добавление метаданных

После очистки — для оставшихся записей добавить `description`:
- `github-admin` → `"Main admin PAT для Zerocreds-com org (kobzevvv)"`
- `github-zen-rings` → `"Zen-Rings CI/CD PAT (vovalikessmoothy-png)"`

**Проблема:** Сейчас нет инструмента `connection_update`!

**Workaround (на время):**
- Вручную отредактировать `~/.config/zerocreds/local/connections.json`.
- Или открыть PR с `connection_update` и подождать merge.

### Этап 5: Отчёт

Создать `docs/key-inventory-report-2026-10-28.md`:
- Сколько ключей было.
- Сколько удалено.
- Сколько осталось (с описаниями).
- Какие инструменты не хватало.

---

## 4. Бэклог (Future Work)

### 4.1. Fingerprinting (P0)

**Цель:** Сразу видеть возможности токена.

**Задачи:**
- [ ] В `verifyLocalCredential` для GitHub добавить `GET /user/repos` и `GET /user/orgs`.
- [ ] Вернуть `capabilities: { repository_count, organization_count, can_write_repos }`.
- [ ] В `auth_check` добавить `capabilities_diff`.

**Ожидаемый результат:**
```
github-flexi-crm → 42 repos, 3 orgs, can write: owner/repo1, owner/repo2
github-admin     → 128 repos, 5 orgs, can write: * (all repos)
```
Сразу видно, что это разные токены.

### 4.2. Metadata Editing (P0)

**Цель:** Добавлять человекочитаемые пояснения.

**Задачи:**
- [ ] В `connections.json` добавить поля `description`, `tags`, `notes`, `superseded_by`, `duplicate_of`.
- [ ] Добавить MCP-инструмент `connection_update`.
- [ ] В `connections_list` отдавать эти поля.

### 4.3. Duplicate Detection (P1)

**Цель:** Автоматически показывать кандидатов на удаление.

**Задачи:**
- [ ] В `connections_list` добавить `duplicate_candidates` (group by `identity.id`).
- [ ] Показывать `differences` (permissions, capabilities).

### 4.4. Discovery Capability (P1)

**Цель:** В `discovery_preview` показывать реальные возможности.

**Задачи:**
- [ ] В `scanGithub` добавить `gh api /user/repos` для `repository_count`.
- [ ] Добавить `capabilities` в кандидатов.

### 4.5. Bulk Verification (P2)

**Цель:** Одна команда → полный отчёт.

**Задачи:**
- [ ] `connections_verify_all` (MCP tool).
- [ ] Или CLI: `scripts/audit-connections.sh`.

---

## 5. Риски

| Риск | Вероятность | Влияние | Mitigation |
|------|-------------|---------|------------|
| Удаление «хорошего» ключа | Средняя | Высокое | Всегда спрашивать пользователя перед `connection_delete` |
| `connection_verify` ломает CI | Низкая | Среднее | Запускать только вручную, не в CI |
| PR #187 не смержен → нет `auth_check` | Высокая | Низкое | Использовать `connection_verify` + `connections_list` для анализа |
| `gh api /user/repos` rate limit | Низкая | Низкое | Кэшировать результат, не запускать чаще 1 раза/час |

---

## 6. Критерии успеха

- [ ] Все GitHub-ключи в Keychain сопоставлены с `connections.json`.
- [ ] Дубликаты удалены (после подтверждения пользователя).
- [ ] Для каждой записи есть `description`.
- [ ] Отчёт создан (`docs/key-inventory-report-2026-10-28.md`).
- [ ] Бэклог (п. 4) создан как GitHub issues.

---

## 7. Как начать сессию

```bash
# 1. Убедиться, что runtime обновлён (с scripts/)
cd ~/.zerocreds/runtime
ls scripts/setup-local-mac.sh && echo "✅ OK" || echo "❌ Нужен PR #185"

# 2. Убедиться, что MCP подключён
# (в OpenCode: /mcp → zerocreds → должен быть 24+ tools)

# 3. Запустить doctor через MCP
# doctor → overall: ok

# 4. Начать инвентаризацию
# discovery_preview(source_ids: ["github_cli", "macos_keychain"])
# connections_list(provider: "github")
# connection_verify(provider: "github", account_alias: "...")
```

---

## 8. Связанные PR/Issues

- **PR #185** (fix: copy scripts/) — нужен для запуска `setup-local-mac.sh` из runtime.
- **PR #187** (feat: auth_check) — нужен для детальной диагностики `identity_mismatch` / `permissions_changed`.
- **Issue #186** — создан вместе с PR #187.

---

## 9. Ссылки

- `server/src/credential-discovery.js` — логика `scanGithub`, `makeCandidate`.
- `server/src/server.js:3550` — `/api/local/connections/verify`.
- `server/src/server.js:3655` — `/api/local/auth/check` (в PR #187).
- `~/.config/zerocreds/local/connections.json` — текущий catalog.
- `~/.config/zerocreds/local/discovery-catalog.json` — текущий discovery catalog.

---

**Создан:** 2026-10-28  
**Автор:** AI-assisted  
**Статус:** Draft (требуется ревью)
