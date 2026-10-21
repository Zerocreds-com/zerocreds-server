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

- [реализовано] Z0 CI/CD guard (#51) — удалён auto-merge.yml; deploy через GitHub Environment `production` (required reviewer) только с `main` после `test` на том же sha; `npm ci` + lockfile для server и mcp; Node 22; `npm audit --omit=dev`; gitleaks; syntax lint; actions запинены по SHA; README: исправлены утверждения про telemetry и /version
- [реализовано] Z8 (#59) Дизайн формы /f/: светлая/тёмная тема (по умолчанию prefers-color-scheme, переключатель, выбор в localStorage, без вспышки), mobile-first (16px инпуты, крупные тап-таргеты, sticky Submit), без inline-обработчиков и style-атрибутов (готово к строгому CSP); скриншоты — `server/scripts/form-screenshots.js` → docs/screenshots/. Всегда видимый блок «Where this goes» — в рамках #50

- [реализовано] #114 discovery: уникальный `ref` на каждого кандидата (Keychain `service`/`server` участвует в хеше как нехранимый discriminator) + дедупликация в preview; эндпоинт каталога сверяет *множество* ref'ов, а не их количество (раньше дубль ref давал HTTP 400 навсегда); legacy-записи Keychain без `service` вычищаются при записи
- [реализовано] #114 discovery: классификация кандидатов (`credential`, `wifi`, `bluetooth`, `apple-system`, `browser`, `vpn`, `other`) + `category_counts` и опциональный фильтр `categories` в preview; по умолчанию ничего не скрывается
- [реализовано] #114 verify: `zerocreds_connection_verify` принимает любой provider-slug и честно возвращает `unsupported_provider` вместо ошибки схемы; provider и account_alias валидируются по формату на сервере
- [реализовано] #114 документация: README — полный контракт discovery-потока (TTL превью 6ч, одноразовость превью для каталога, scope поиска, матрица провайдеров); MCP-описания preview/catalog/search/verify приведены в соответствие
- [реализовано] #114 setup-local-mac.sh пишет V2-форму `mcp.servers.zerocreds` и мигрирует legacy flat-записи (смешивание форм в одном `mcp` ломало весь блок)
- [реализовано] #116 ref'ы для провайдеров без `service` не меняются (`github`/`cloudflare`/`google_cloud`): discriminator участвует в хеше только когда он непустой, иначе уже каталогизированные записи осиротевали бы и задваивались
- [реализовано] #117 диагностика замороженного деплой-пайплайна: с 2026-10-16 run 38892268033 висел на неодобренном `production`-approval и держал группу `production-deploy`; каждый следующий пуш в `main` отменял предыдущий run вместо того, чтобы пропустить его вперёд — прод отставал на 3 дня. Отменён протухший run, одобрен `production` для `df1e075`, `https://zerocreds.ru/version` → `df1e0755525c`
- [планируется] #117 монитор не видит устаревший прод: `check-public.py` сверяет коммит только при заданном `EXPECTED_COMMIT`, а плановый `Public HTTPS monitor` его не передаёт — отставший на 3 дня прод проходил мониторинг каждые 30 минут. Нужно решение по семантике (ложные срабатывания при незавершённом деплое vs. порог «прод старше N часов»)
- [реализовано] #119 имена MCP-тулов больше не повторяют имя провайдера: `zerocreds_discovery_sources` → `discovery_sources`, `zerocreds_create_session` → `form_create`, `zerocreds_connection_verify` → `connection_verify` и т.д.; в code-mode агент видит `zerocreds.discovery_sources`, в обычном режиме — короткое имя. Алиасов-дубликатов нет: они раздували бы список тулов
- [реализовано] #119 локальный адрес: `http://localhost/zerocreds` вместо `http://127.0.0.1:3456`. Сервер сам снимает префикс монтирования с пути, поэтому `/zerocreds/api/...` и `/api/...` ведут в один обработчик; все генерируемые ссылки (включая `broker_url`) собираются из полного base URL, а не из origin
- [реализовано] #119 `scripts/local-proxy.js` — reverse proxy на :80 без зависимостей: root LaunchDaemon, слушает только loopback (127.0.0.1 и ::1), путь проксирует без изменений, `Host` переписывается в `localhost` (иначе сервер отклоняет запрос своей проверкой хоста)
- [реализовано] #119 `/about` показывает фактический адрес развёртывания вместо захардкоженного `localhost:3456`
- [реализовано] #119 setup-local-mac.sh ставит прокси, если `sudo` доступен без пароля, иначе печатает три команды для ручного запуска и остаётся на прямом адресе; `ZEROCREDS_PROXY_MODE=off` отключает прокси полностью
- [реализовано] #123 экран подтверждения после сохранения называет, куда именно сохранено: «Saved to macOS Keychain on this Mac — `zerocreds/<provider>-<account-alias>`». Раньше блок «Where this goes» жил внутри формы и исчезал ровно в тот момент, когда человек спрашивал «куда оно легло». Локальное хранилище теперь называется конкретно («macOS Keychain on this Mac»), а не обезличенно «OS keychain on the ZeroCreds server»

- [реализовано] #158 исследование транспортов для peer-шаринга за CGNAT: `docs/research/2026-10-21-cgnat-peer-sharing-transports.md` — сетевое ограничение (RFC 4787/6598/5780), модель угроз и контракт транспорта (8 инвариантов), сравнение Cloudflare Tunnel / WebRTC+TURN / Tor / Tailscale-Headscale / mailbox / Magic Wormhole, граница API для `share_create` и план тестов только на синтетических значениях

- [реализовано] #158 транспорт `tunnel` — релей отправителя публикуется через исходящий туннель, который запускает сам пользователь (`cloudflared`, `ssh -R`, `frp`, `ngrok`, любой свой VPS). Формат конверта, claim proof, одноразовость, TTL и формат ссылки не меняются — меняется только хост. Новый эндпоинт `POST /api/local/shares/tunnel/setup` поднимает loopback-слушатель на 3458 и спрашивает сам туннель, доходит ли он до этой машины (проба несёт случайный токен и никаких данных креды). `share_options` теперь отдаёт transport-реестр с `can_read_credential: false` у каждого варианта. Получатель видит хост и его класс доверия до claim; незнакомый хост отклоняется с `origin_confirmation_required`, пока пользователь не подтвердит его один раз — дальше хост запоминается для этой машины. Слушатель остаётся поднятым, пока настроен туннель: туннель, потерявший локальную цель, обычно не переподключается, а отказывает новым соединениям. Сайт zerocreds.ru в этом пути не участвует вовсе

## Планируется

- [планируется] Landing page zerocreds.ru — на русском, с объяснением концепции
- [планируется] DNS: переключить NS на Hostland, A-запись → 178.212.14.192 (сделать вручную в panel.hostland.ru)
- [планируется] SSL сертификат (Let's Encrypt через certbot)
- [планируется] Заменить формы в trained-assist-agent на ссылки на zerocreds-server
- [планируется] Chrome extension сниппет для Tilda HTML-блоков
- [планируется] #158 без кода: `ZEROCREDS_SHARE_RELAY_URL` может указывать на собственный инстанс ZeroCreds — сайт zerocreds.ru полностью уходит из пути; показать это в `share_options` как отдельный вариант
- [планируется] #158 отложено (с обоснованием в исследовании): WebRTC+STUN/TURN, Tor onion service, Tailscale/Headscale как транспорт шаринга, mailbox-поллинг, интероп с Magic Wormhole

## Отклонено

- [отклонено] Cloudflare Pages — заблокирован в РФ
- [отклонено] Cloud Run для nalog — Playwright stateful, нужна постоянная память сессий
- [отклонено] Яндекс Cloud Functions — nalog требует настоящего процесса с браузером
