# Requirements Log — zerocreds.ru

## Реализовано

- [реализовано] zerocreds-server v0.1.0 — самохостируемый сервер форм авторизации на Node.js (порт 3456)
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

## Планируется

- [планируется] Landing page zerocreds.ru — на русском, с объяснением концепции
- [планируется] DNS: переключить NS на Hostland, A-запись → 178.212.14.192 (сделать вручную в panel.hostland.ru)
- [планируется] SSL сертификат (Let's Encrypt через certbot)
- [планируется] Заменить формы в trained-assist-agent на ссылки на zerocreds-server
- [планируется] Chrome extension сниппет для Tilda HTML-блоков

## Отклонено

- [отклонено] Cloudflare Pages — заблокирован в РФ
- [отклонено] /connect/nalog (Playwright headless login) — удалён из репозитория, т.к. Playwright не нужен для концепции ZeroCreds и вызывал вопросы безопасности
