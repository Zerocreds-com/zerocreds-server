# Requirements Log — zerocreds.ru

## Реализовано

- [реализовано] zerocreds-server v0.1.0 — самохостируемый сервер форм авторизации на Node.js (порт 3456)
- [реализовано] Форма nalog.ru — 3-шаговая (логин/пароль Госуслуг → 2FA → успех), Playwright headless
- [реализовано] Форма GitHub — вставка API токена
- [реализовано] Форма Weeek CRM — вставка API токена
- [реализовано] Форма Tilda — вставка cookie строки
- [реализовано] GET /version — git commit для аудита безопасности
- [реализовано] Деплой на 178.212.14.192 (Hostland RU VM), systemd сервис zerocreds-server
- [реализовано] nginx vhost zerocreds.ru — /connect/* → :3456, / → статика

- [реализовано] Dynamic Form API v0.2.0 — POST /api/session/create создаёт форму с произвольными полями, GET /f/{token} отдаёт её пользователю, POST /f/{token} сохраняет данные
- [реализовано] Multi-destination: local_file, gcp_secret_manager (write-only через secretVersionAdder), aws_secrets_manager (PutSecretValue), vault
- [реализовано] GET /api/session/{token}/status — агент опрашивает статус без видимости credentials
- [реализовано] ZEROCREDS_ADMIN_TOKEN — опциональная защита API создания сессий
- [реализовано] GCP Secret Manager write-only auth — JWT без SDK, roles/secretmanager.secretVersionAdder
- [реализовано] AWS Secrets Manager write-only — AWS4 HMAC подпись, PutSecretValue без GetSecretValue

- [реализовано] Remember me — cookie `zc_uid` (UUID, HttpOnly, 365 дней) идентифицирует браузер; не-пароли сохраняются в `~/zerocreds-saved/{uid}.json` и предзаполняются при следующем визите; checkbox "Запомнить для следующего раза" на форме (предвыбран если данные уже есть); show/hide toggle (👁) и кнопка Paste для полей type=password

- [реализовано] `http_post` destination type — после сабмита формы zerocreds делает POST на указанный URL агента; поддержка http:// и https://; опциональный body template с подстановкой `{field_name}` и `{fields_json}`; разблокирует cross-server сетап (Issue #14)
- [реализовано] Детерминированные URL + идемпотентное создание сессий — при передаче `uid` + `service` в /api/session/create URL становится `/{integrator_id}/{service}/{user_hash}?gen={token}`; повторный вызов с теми же uid/service возвращает ту же ссылку пока сессия активна; HMAC-SHA256 user_hash (Issue #14)
- [реализовано] Pretty URL route `/{slug}/{service}/{hash}` — GET отдаёт форму; без `gen` делает redirect на полный URL с gen; форма всегда постит на `/f/{token}` (Issue #14)

## Планируется

- [планируется] Landing page zerocreds.ru — на русском, с объяснением концепции
- [планируется] DNS: переключить NS на Hostland, A-запись → 178.212.14.192 (сделать вручную в panel.hostland.ru)
- [планируется] SSL сертификат (Let's Encrypt через certbot)
- [планируется] Заменить формы в trained-assist-agent на ссылки на zerocreds-server
- [планируется] Chrome extension сниппет для Tilda HTML-блоков

## Отклонено

- [отклонено] Cloudflare Pages — заблокирован в РФ
- [отклонено] Cloud Run для nalog — Playwright stateful, нужна постоянная память сессий
- [отклонено] Яндекс Cloud Functions — nalog требует настоящего процесса с браузером
