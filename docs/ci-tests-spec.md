# CI/CD Tests Spec

## Цель

Покрыть ключевое поведение сервера автотестами.
Деплой на прод идёт только после зелёных тестов.

## Технологии

- **Фреймворк:** `node:test` + `node:assert` — встроены в Node 18+, нулевые зависимости
- **HTTP-клиент:** `node:http` (встроенный) — сервер поднимается на случайном порту в процессе теста
- **Запуск:** `node --test server/test/*.test.js`

## Структура

```
server/
  src/
    server.js
    destinations.js
  test/
    helpers.js          ← startServer / stopServer / request
    session.test.js     ← POST /api/session/create
    form.test.js        ← GET+POST /f/:token
    status.test.js      ← GET /api/session/:token/status
    destinations.test.js← by-level routing, local_file, http_post
    auth.test.js        ← токены, регистрация, integrators
    html.test.js        ← escaping, level badges
```

## Что покрываем

### 1. `session.test.js` — создание сессии

| Сценарий | Ожидание |
|----------|----------|
| Корректный запрос с `destination` | `200 { token, url, expires_at }` |
| Корректный запрос с `destinations_by_level` | `200 { token, url, expires_at }` |
| Оба поля: `destination` + `destinations_by_level` | `200` (оба принимаются) |
| Без `destination` и без `destinations_by_level` | `400` |
| Невалидное имя поля (`name: "a b"`) | `400` |
| Невалидный `type` поля | `400` |
| Невалидный `level` поля | `400` |
| Невалидный named destination | `400 "unknown named destination"` |
| Без Authorization | `401` |
| `ttl_minutes` > 1440 зажимается до 1440 | expires_at ≤ now + 1440min |

### 2. `form.test.js` — форма

| Сценарий | Ожидание |
|----------|----------|
| GET /f/:token — валидный токен | `200` HTML |
| GET /f/:token — истёкший токен | `410` |
| GET /f/:token — несуществующий | `404` |
| POST /f/:token — все поля заполнены | `200 { ok: true }` |
| POST /f/:token — missing required field | `400` |
| POST /f/:token — невалидный URL в url-поле | `400` |
| POST /f/:token — повторная отправка (токен уже использован) | `403` |
| POST /f/:token — token mismatch в теле | `400` |

### 3. `status.test.js` — статус

| Сценарий | Ожидание |
|----------|----------|
| Pending сессия | `{ status: "pending" }` |
| После отправки формы | `{ status: "done" }` |
| Несуществующий токен | `{ status: "expired" }` |
| Истёкший pending файл | `{ status: "expired" }` |
| Done с `destination` → `secret_id` | `{ status: "done", secret_id: "..." }` |
| Done с `destinations_by_level` → `secret_ids` | `{ status: "done", secret_ids: { secret: "...", pii: "..." } }` |

### 4. `destinations.test.js` — destinations

| Сценарий | Ожидание |
|----------|----------|
| `local_file` — один destination | файл создан, содержит JSON с полями |
| `destinations_by_level` — поля secret+attribute | два отдельных файла |
| Поле без `level` → fallback на `default` в destinations_by_level | попадает в default-destination |
| Поле без `level`, нет `default`, нет `destination` | предупреждение, не падает |
| `http_post` — возвращает `{}` при 200 от upstream | `200 { ok: true }` на форме |
| `http_post` — upstream 500 | `500` на форме |

### 5. `auth.test.js` — авторизация

| Сценарий | Ожидание |
|----------|----------|
| POST /api/register — валидный email + category | `200 { token, base_url }` |
| POST /api/register — без email | `400` |
| POST /api/register — невалидная category | `400` |
| Rate limit — 4й запрос с одного IP | `429` |
| Integrator token — создать сессию | `200` |
| Integrator token — использует свои named destinations | роутится правильно |
| Admin /admin/integrators/create | `200 { token, id, name }` |
| Admin endpoint с integrator токеном | `401` |

### 6. `html.test.js` — HTML-рендеринг

| Сценарий | Ожидание |
|----------|----------|
| XSS в `title` (`<script>alert(1)</script>`) | escapeHtml в title тега и h1 |
| XSS в `label` поля | escapeHtml в label |
| XSS в `placeholder` | escapeAttr в placeholder |
| Поле с `level: "secret"` | HTML содержит `class="level-btn"` + иконку 🔒 |
| Поле без `level` | нет `.level-btn` |
| `description` с HTML тегами | рендерится as-is (description доверенная) |

## CI pipeline (`.github/workflows/test.yml`)

```yaml
name: Test

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: cd server && npm install
      - run: cd server && node --test test/*.test.js
```

## Изменение `deploy.yml`

Добавить `needs: test` в deploy job:

```yaml
jobs:
  test:
    # ... (как выше, но inline или через reusable workflow)
  deploy:
    needs: test   # ← деплой только после зелёных тестов
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      # ... текущий SSH-деплой
```

## Что не покрываем (сознательно)

- **GCP Secret Manager / AWS / Vault** — внешние сервисы с реальными ключами; тестируем через http_post mock
- **Telegram notifications** — достаточно проверить, что tgNotify не падает (fire-and-forget)

## Приоритет реализации

1. `helpers.js` — startServer с local_file destination во временной папке
2. `session.test.js` + `status.test.js` — core API flow
3. `form.test.js` — form submission
4. `destinations.test.js` — by-level routing
5. `html.test.js` — XSS escaping
6. `auth.test.js` — integrators
