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
- [реализовано] ZEROCREDS_ADMIN_TOKEN — обязателен (#50): без него сервер не стартует; создание сессий только с admin/активным integrator токеном
- [реализовано] GCP Secret Manager write-only auth — JWT без SDK, roles/secretmanager.secretVersionAdder
- [реализовано] AWS Secrets Manager write-only — AWS4 HMAC подпись, PutSecretValue без GetSecretValue

- [отклонено] Remember me (cookie `zc_uid` + `~/zerocreds-saved/`) — удалено в #50: значения шарились между интеграторами и сохраняли secret-поля открытым текстом; UI никогда не отправлял `save`. Остались show/hide toggle (👁) и кнопка Paste для password-полей

- [реализовано] #50 security hardening: реестр интеграторов в Map по sha256 токена + constant-time сравнение admin; /api/register создаёт pending-интегратора (активация POST /admin/integrators/approve); rate limit по X-Real-IP от nginx
- [реализовано] #50 никакой запрос не роняет процесс: глобальный try/catch → 500, 413 на большое тело, строгая типизация входа
- [реализовано] #50 экранирование всех строк сессии (включая description), t= только 32 hex, CSP с nonce, frame-ancestors 'none', no-referrer, no-store
- [реализовано] #50 destinations: по умолчанию только именованные (inline — ZEROCREDS_ALLOW_INLINE_DESTINATIONS=1); http_post только https и хосты из ZEROCREDS_HTTP_POST_ALLOWED_HOSTS; приватные/loopback/link-local адреса блокируются при коннекте (ZEROCREDS_ALLOW_PRIVATE_DESTINATIONS=1 для dev); тело ответа upstream не возвращается
- [реализовано] #50 форма всегда показывает над Submit кто запросил и точный destination; без "write-only" для читаемых destinations
- [реализовано] #50 local_file сессий интеграторов → ~/agent-tokens/_integrators/{id}/...; одноразовые ссылки захватываются атомарно (rename); sweeper чистит просроченные pending/.done; каталоги 0700; статус виден только владельцу
- [реализовано] #50 nalog: убраны скриншоты в /tmp и логирование текста страниц
- [планируется] Rate limit на создание/сабмит сессий; индекс вместо полного скана pending для pretty URL (#50 audit, medium — вне scope)

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
