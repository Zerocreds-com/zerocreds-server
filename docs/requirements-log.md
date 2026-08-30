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
