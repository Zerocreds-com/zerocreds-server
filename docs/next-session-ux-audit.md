# Промпт следующей сессии: Аудит UX ZeroCreds

## Контекст

Сегодня (2026-10-28) были смержены два важных PR:
- **PR #187**: `auth_check` MCP tool + фикс Keychain ACL (теперь `gh` видит токены ZeroCreds)
- **PR #185**: Копирование `scripts/` в runtime (чинит `install-local-proxy.sh`)

Теперь нужно проверить, насколько удобно работает ZeroCreds в реальном сценарии и где остались проблемы.

---

## Что уже сделано (не повторять)

1. ✅ `auth_check` tool добавлен и работает (read-only диагностика токенов)
2. ✅ Keychain ACL исправлен (пустые флаги = доступ для всех приложений)
3. ✅ `scripts/` копируется в runtime при setup
4. ✅ Оба PR смержены в `main`

---

## Задачи для следующей сессии

### 1. Проверить что фикс Keychain ACL реально работает

```bash
# 1. Обновить runtime с новым кодом
cd ~/.zerocreds/runtime && git pull 2>/dev/null || true
# Или скопировать обновлённый binary:
cp /Users/vova/code/zerocreds-server/server/bin/zerocreds-keychain ~/.zerocreds/runtime/bin/
chmod +x ~/.zerocreds/runtime/bin/zerocreds-keychain

# 2. Проверить что gh видит токены ZeroCreds
# Если ZeroCreds сохранил GitHub токен, он должен быть доступен через:
security find-generic-password -w -s "zerocreds" -a "github-github-admin"
# Должен вернуть токен (hex-encoded)

# 3. Проверить что gh auth status работает
gh auth status
# Должен показать авторизованные аккаунты
```

### 2. Аудит текущего состояния Keychain

```bash
# Посмотреть все ZeroCreds записи
~/.config/zerocreds/local/zerocreds-keychain list | python3 -m json.tool | grep -A5 -B5 "zerocreds"

# Посмотреть все connections в catalog
curl -s -H "Host: localhost" -H "Authorization: Bearer $(cat ~/.config/zerocreds/local/admin-token)" \
  http://localhost:8080/api/local/connections | python3 -m json.tool
```

### 3. Проверить auth_check tool

```bash
# Проверить что auth_check работает
curl -s -H "Host: localhost" -H "Authorization: Bearer $(cat ~/.config/zerocreds/local/admin-token)" \
  -H "Content-Type: application/json" \
  -X POST http://localhost:8080/api/local/auth/check \
  -d '{"provider":"github","account_alias":"github-admin"}' | python3 -m json.tool
```

### 4. Найти дубликаты и проблемы

На основе предыдущего анализа, в Keychain есть дубли:
- `kobzevvv` → 3 записи (`trained-agent-github-token`, `github.com`, `gh:github.com`)
- `gha-compute-cluster` → 1 запись
- ZeroCreds catalog: 5 GitHub записей

**Задача:** Определить, какие из них дубли, какие устарели, какие используются.

### 5. UX-аудит: что удобно, что нет

#### Удобно ✅
- [ ] `doctor` показывает состояние инфраструктуры
- [ ] `connections_list` показывает все записи
- [ ] `connection_verify` проверяет токены
- [ ] `auth_check` показывает детали (если работает)
- [ ] `discovery_preview` находит кандидатов

#### Неудобно ❌
- [ ] Нет `connection_update` для описаний/тегов
- [ ] Нет bulk-верификации (`connections_verify_all`)
- [ ] Нет визуального сравнения дубликатов
- [ ] `discovery_preview` не показывает `repository_count`
- [ ] Нет веб-интерфейса для управления ключами

### 6. Проверить что стандартные CLI не сломаны

```bash
# gh должен видеть токены ZeroCreds
gh auth status
gh api /user

# git должен работать с credential helper
git config --get credential.helper
git ls-remote https://github.com/Zerocreds-com/zerocreds-server.git
```

---

## Доступ (уже решён)

Активный токен `gh` — fine-grained PAT без права создавать PR в org `Zerocreds-com`
(REST и GraphQL отвечают `403`). Рабочий classic PAT лежит в Keychain:

```bash
security find-generic-password -w -s github.com -a kobzevvv -l "Trained Agent GitHub Token"
```

Для любых gh-команд по этому репозиторию — через `GH_TOKEN`, не печатая значение:

```bash
cd /Users/vova/code/zerocreds-server
export GH_TOKEN=$(security find-generic-password -w -s github.com -a kobzevvv -l "Trained Agent GitHub Token" 2>/dev/null)
gh pr ...   # любые операции
unset GH_TOKEN
```

Не запускай `gh auth refresh`/`gh auth login` — это не заменяет fine-grained PAT автоматически
и требует интерактивного browser device flow.

---

## Чеклист перед началом

1. [ ] `git pull origin main` — получить последний код
2. [ ] Проверить что `~/.zerocreds/runtime` обновлён (или скопировать `server/bin/zerocreds-keychain`)
3. [ ] Проверить что `launchctl list | grep zerocreds` показывает active сервисы
4. [ ] Запустить `doctor` через MCP — убедиться что всё ок

---

## Ожидаемый результат

1. **Отчёт** `docs/ux-audit-2026-10-28.md`:
   - Что работает хорошо
   - Что не работает / неудобно
   - Список дубликатов с рекомендациями
   - Бэклог улучшений

2. **Issue в GitHub** для каждой проблемы:
   - `connection_update` tool (metadata editing)
   - `connections_verify_all` (bulk verification)
   - `discovery_preview` → `repository_count` (fingerprinting)
   - Веб-интерфейс (P2)

---

## Связанные PR/Issues

- **PR #187** (merged): `auth_check` + Keychain ACL fix
- **PR #185** (merged): scripts copy to runtime
- **Issue #186**: создан вместе с PR #187

---

## Технические детали

### Где что лежит

| Компонент | Путь |
|-----------|------|
| Keychain helper | `~/.zerocreds/runtime/bin/zerocreds-keychain` |
| Keychain source | `server/scripts/macos-keychain.swift` |
| Connections catalog | `~/.config/zerocreds/local/connections.json` |
| Discovery catalog | `~/.config/zerocreds/local/discovery-catalog.json` |
| Admin token | `~/.config/zerocreds/local/admin-token` |
| MCP config | `~/.config/opencode/opencode.json` (mcpServers.zerocreds) |

### API endpoints

| Endpoint | Method | Описание |
|----------|--------|----------|
| `/api/local/doctor` | GET | Диагностика инфраструктуры |
| `/api/local/connections` | GET | Список connections |
| `/api/local/connections/verify` | POST | Верификация токена |
| `/api/local/auth/check` | POST | Детальная диагностика (auth_check) |
| `/api/local/discovery/preview` | POST | Превью discovery |

### MCP tools (24 шт)

`form_create`, `form_status`, `connections_list`, `connection_resolve`, `connection_verify`, `connection_delete`, `auth_check`, `doctor`, `discovery_sources`, `discovery_preview`, `discovery_catalog`, `credentials_search`, `share_options`, `share_create`, `share_status`, `share_cancel`, `share_claim`, `share_tunnel_providers`, `share_tunnel_start`, `share_tunnel_stop`, `share_tunnel_setup`, `share_direct_setup`, `playground_scenarios`, `playground_run`, `playground_form`

---

**Создан:** 2026-10-28  
**Автор:** AI-assisted  
**Статус:** Ready for next session
