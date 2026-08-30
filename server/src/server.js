'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { startNalogLogin, confirmNalogCode } = require('./nalog-login');

const PORT = process.env.PORT || 3456;
const CONNECT_PENDING_DIR = path.join(os.homedir(), 'connect-pending');
const AGENT_TOKENS_DIR = path.join(os.homedir(), 'agent-tokens');

// Read git commit at startup for /version endpoint
function readCommit() {
  try {
    const headPath = path.join(__dirname, '../../.git/HEAD');
    const head = fs.readFileSync(headPath, 'utf8').trim();
    if (head.startsWith('ref: ')) {
      const refPath = path.join(__dirname, '../../.git', head.slice(5));
      return fs.readFileSync(refPath, 'utf8').trim().slice(0, 12);
    }
    return head.slice(0, 12);
  } catch {
    return 'unknown';
  }
}

const COMMIT = readCommit();
const VERSION = '0.1.0';

const SERVICE_META = {
  github: {
    name: 'GitHub',
    placeholder: 'ghp_xxxxxxxxxxxxxxxxxxxx',
    hint: 'github.com/settings/tokens → Generate new token (classic) → scopes: <b>repo</b>, <b>read:org</b>',
  },
  weeek: {
    name: 'Weeek CRM',
    placeholder: 'Вставьте API токен',
    hint: 'Weeek → Settings → Integrations → API → Generate token',
  },
  tilda: {
    name: 'Tilda',
    placeholder: 'Вставьте cookie строку',
    hint: 'Откройте tilda.ru в браузере → F12 → Application → Cookies → скопируйте всю строку',
  },
};

function tgNotify(botToken, chatId, text) {
  if (!botToken || !chatId) return;
  const tgBase = (process.env.TELEGRAM_API_URL || 'https://api.telegram.org').replace(/\/$/, '');
  fetch(`${tgBase}/bot${botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text }),
  }).catch(e => console.error('[tg] notify failed:', e.message));
}

function readBody(req, maxBytes = 1_048_576) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', c => {
      total += c.length;
      if (total > maxBytes) { req.destroy(); return reject(new Error('body too large')); }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readPending(token) {
  const file = path.join(CONNECT_PENDING_DIR, `${token}.json`);
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

function deletePending(token) {
  try { fs.unlinkSync(path.join(CONNECT_PENDING_DIR, `${token}.json`)); } catch {}
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // GET / — redirect to landing
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(301, { Location: 'https://zerocreds.ru' }).end();
    return;
  }

  // GET /health
  if (req.method === 'GET' && url.pathname === '/health') {
    return json(res, 200, { ok: true, version: { commit: COMMIT, version: VERSION } });
  }

  // GET /version — for security audits
  if (req.method === 'GET' && url.pathname === '/version') {
    return json(res, 200, {
      commit: COMMIT,
      version: VERSION,
      source: 'https://github.com/Zerocreds-com/zerocreds-server',
    });
  }

  // POST /connect/nalog/code — confirm 2FA (must be before connectMatch)
  if (req.method === 'POST' && url.pathname === '/connect/nalog/code') {
    const body = await readBody(req);
    let payload;
    try { payload = JSON.parse(body); } catch { return json(res, 400, { error: 'bad json' }); }
    const { session, code } = payload;
    if (!session || !code) return json(res, 400, { error: 'missing session or code' });
    if (!/^[a-f0-9]{32}$/.test(session)) return json(res, 400, { error: 'invalid session' });
    if (!/^\d{4,8}$/.test(code.trim())) return json(res, 400, { error: 'invalid code format' });

    const result = await confirmNalogCode(session, code.trim());
    if (result.error) return json(res, 400, { error: result.error });

    json(res, 200, { ok: true, expires: result.expires });
    if (result.userId && result.tgBotToken) {
      const expiresStr = result.expires
        ? new Date(result.expires).toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' })
        : '~1 час';
      tgNotify(result.tgBotToken, result.userId,
        `✅ Налог.ру подключён! Токен действует до ${expiresStr} (МСК).`);
    }
    return;
  }

  // /connect/:service
  const connectMatch = url.pathname.match(/^\/connect\/([a-z0-9_-]+)$/);
  if (connectMatch) {
    const service = connectMatch[1];

    // ── nalog ──────────────────────────────────────────────────────────────────
    if (service === 'nalog') {
      if (req.method === 'GET') {
        const t = url.searchParams.get('t') || '';
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(nalogFormHtml(t));
        return;
      }

      if (req.method === 'POST') {
        const body = await readBody(req);
        let payload;
        try { payload = JSON.parse(body); } catch { return json(res, 400, { error: 'bad json' }); }
        const { t, login, password } = payload;
        if (!t || !login || !password) return json(res, 400, { error: 'missing fields' });
        if (!/^[a-f0-9]{32}$/.test(t)) return json(res, 400, { error: 'invalid token' });

        const pending = readPending(t);
        if (!pending) return json(res, 403, { error: 'invalid or expired token' });
        if (pending.expires < Date.now()) { deletePending(t); return json(res, 403, { error: 'link expired' }); }
        if (pending.service !== 'nalog') return json(res, 403, { error: 'service mismatch' });
        if (!/^-?\d{1,20}$/.test(pending.uid)) return json(res, 403, { error: 'invalid uid' });

        deletePending(t);

        const result = await startNalogLogin(pending.uid, login, password, {
          tgBotToken: pending.tg_bot_token,
          tgChatId: pending.tg_chat_id,
        });

        if (result.error) return json(res, 400, { error: result.error });

        if (result.status === 'ok') {
          json(res, 200, { status: 'ok', expires: result.expires });
          if (pending.tg_bot_token) {
            const expiresStr = result.expires
              ? new Date(result.expires).toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' })
              : '~1 час';
            tgNotify(pending.tg_bot_token, pending.tg_chat_id || pending.uid,
              `✅ Налог.ру подключён! Токен действует до ${expiresStr} (МСК).`);
          }
          return;
        }

        if (result.status === 'need_code') {
          return json(res, 200, { status: 'need_code', sessionId: result.sessionId });
        }

        return json(res, 500, { error: 'unexpected result' });
      }

      res.writeHead(405).end(); return;
    }

    // ── generic token services ─────────────────────────────────────────────────
    const meta = SERVICE_META[service];
    if (!meta) { res.writeHead(404).end('Unknown service'); return; }

    if (req.method === 'GET') {
      const t = url.searchParams.get('t') || '';
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(connectFormHtml(service, meta, t));
      return;
    }

    if (req.method === 'POST') {
      const body = await readBody(req);
      let payload;
      try { payload = JSON.parse(body); } catch { return json(res, 400, { error: 'bad json' }); }
      const { t, value } = payload;
      if (!t || !value) return json(res, 400, { error: 'missing t or value' });
      if (!/^[a-f0-9]{32}$/.test(t)) return json(res, 400, { error: 'invalid token' });

      const pending = readPending(t);
      if (!pending) return json(res, 403, { error: 'invalid or expired token' });
      if (pending.expires < Date.now()) { deletePending(t); return json(res, 403, { error: 'link expired' }); }
      if (pending.service !== service) return json(res, 403, { error: 'service mismatch' });
      if (!/^-?\d{1,20}$/.test(pending.uid)) return json(res, 403, { error: 'invalid uid' });

      const tokensDir = path.join(AGENT_TOKENS_DIR, pending.uid);
      fs.mkdirSync(tokensDir, { recursive: true });
      fs.writeFileSync(path.join(tokensDir, service), String(value).trim(), { mode: 0o600 });
      deletePending(t);

      console.log(`[connect] saved ${service} token for uid=${pending.uid}`);
      json(res, 200, { ok: true });

      if (pending.tg_bot_token) {
        const name = meta.name;
        tgNotify(pending.tg_bot_token, pending.tg_chat_id || pending.uid,
          `✅ ${name} подключён! Токен сохранён.`);
      }
      return;
    }

    res.writeHead(405).end(); return;
  }

  json(res, 404, { error: 'not found' });
});

server.listen(PORT, () => console.log(`zerocreds-server v${VERSION} (${COMMIT}) listening on :${PORT}`));

const shutdown = () => {
  server.close(() => process.exit(0));
  try { require('./nalog-login').closeAll(); } catch {}
  setTimeout(() => process.exit(0), 10_000).unref();
};
process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);

// ── HTML forms ────────────────────────────────────────────────────────────────

function nalogFormHtml(token) {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Подключить Налог.ру</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f5f7;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
  .card{background:#fff;border-radius:16px;padding:32px;max-width:480px;width:100%;box-shadow:0 2px 20px rgba(0,0,0,.08)}
  h1{font-size:20px;font-weight:600;margin-bottom:8px}
  .sub{color:#666;font-size:14px;margin-bottom:24px;line-height:1.5}
  label{display:block;font-size:13px;font-weight:500;color:#333;margin-bottom:6px;margin-top:16px}
  label:first-of-type{margin-top:0}
  input{width:100%;border:1.5px solid #e0e0e0;border-radius:10px;padding:12px 14px;font-size:15px;outline:none;transition:border .15s}
  input:focus{border-color:#007aff}
  button{margin-top:20px;width:100%;background:#007aff;color:#fff;border:none;border-radius:10px;padding:13px;font-size:16px;font-weight:600;cursor:pointer;transition:opacity .15s}
  button:hover{opacity:.88}
  button:disabled{opacity:.5;cursor:default}
  .msg{margin-top:16px;padding:12px 14px;border-radius:10px;font-size:14px;display:none}
  .msg.ok{background:#e8f5e9;color:#2e7d32}
  .msg.err{background:#fdecea;color:#c62828}
  .msg.info{background:#e3f2fd;color:#1565c0}
  .lock{font-size:13px;color:#999;margin-top:20px;text-align:center}
  #step2{display:none}
  #step3{display:none;text-align:center}
  #step3 .icon{font-size:48px;margin-bottom:12px}
</style>
</head>
<body>
<div class="card">
  <div id="step1">
    <h1>Подключить Налог.ру</h1>
    <p class="sub">Введите данные для входа в Госуслуги. Они поступают напрямую на сервер — в чат с ботом <b>не попадают</b>.</p>
    <label for="login">Логин Госуслуг (телефон, email или СНИЛС)</label>
    <input id="login" type="text" autocomplete="username" inputmode="email" placeholder="+7 999 123-45-67">
    <label for="password">Пароль Госуслуг</label>
    <input id="password" type="password" autocomplete="current-password" placeholder="Пароль">
    <button id="btn1" onclick="submitCreds()">Войти через Госуслуги</button>
    <div id="msg1" class="msg"></div>
  </div>
  <div id="step2">
    <h1>Код подтверждения</h1>
    <p class="sub">На ваш телефон или в приложение Госуслуги отправлен код. Введите его ниже.</p>
    <label for="code">Код из SMS / приложения</label>
    <input id="code" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" maxlength="8">
    <button id="btn2" onclick="submitCode()">Подтвердить</button>
    <div id="msg2" class="msg"></div>
  </div>
  <div id="step3">
    <div class="icon">✅</div>
    <h1>Налог.ру подключён!</h1>
    <p class="sub" id="expiresText">Данные авторизации сохранены. Можете закрыть эту страницу и вернуться в бот.</p>
  </div>
  <p class="lock">🔒 Данные не попадают в LLM · Ссылка одноразовая · <a href="/version" style="color:#999">v${VERSION}</a></p>
</div>
<script>
const T = '${token.replace(/'/g, "\\'")}';
let sessionId = '';
function show(stepId) {
  ['step1','step2','step3'].forEach(id => document.getElementById(id).style.display = id === stepId ? '' : 'none');
}
function showMsg(n, cls, text) {
  const el = document.getElementById('msg' + n);
  el.className = 'msg ' + cls; el.textContent = text; el.style.display = 'block';
}
async function submitCreds() {
  const login = document.getElementById('login').value.trim();
  const password = document.getElementById('password').value;
  if (!login || !password) { showMsg(1, 'err', 'Введите логин и пароль'); return; }
  const btn = document.getElementById('btn1');
  btn.disabled = true; btn.textContent = 'Подключаюсь… (30–60 сек)';
  showMsg(1, 'info', '⏳ Открываю браузер и вхожу через Госуслуги…');
  try {
    const r = await fetch('/connect/nalog', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ t: T, login, password }),
      signal: AbortSignal.timeout(95000),
    });
    const d = await r.json();
    if (d.error) { showMsg(1, 'err', d.error); btn.disabled = false; btn.textContent = 'Войти через Госуслуги'; return; }
    if (d.status === 'ok') {
      document.getElementById('expiresText').textContent =
        d.expires ? 'Токен действует до ' + new Date(d.expires).toLocaleString('ru-RU') + '. Можете закрыть страницу.' : 'Токен сохранён. Можете закрыть страницу.';
      show('step3'); return;
    }
    if (d.status === 'need_code') {
      sessionId = d.sessionId; show('step2'); document.getElementById('code').focus(); return;
    }
    showMsg(1, 'err', 'Неожиданный ответ сервера'); btn.disabled = false; btn.textContent = 'Войти через Госуслуги';
  } catch(e) {
    showMsg(1, 'err', e.name === 'TimeoutError' ? 'Превышено время ожидания (90 сек) — попробуйте ещё раз' : 'Сетевая ошибка: ' + e.message);
    btn.disabled = false; btn.textContent = 'Войти через Госуслуги';
  }
}
async function submitCode() {
  const code = document.getElementById('code').value.trim();
  if (!code) { showMsg(2, 'err', 'Введите код'); return; }
  const btn = document.getElementById('btn2');
  btn.disabled = true; btn.textContent = 'Проверяю…';
  showMsg(2, 'info', '⏳ Завершаю вход…');
  try {
    const r = await fetch('/connect/nalog/code', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ session: sessionId, code }),
      signal: AbortSignal.timeout(40000),
    });
    const d = await r.json();
    if (d.error) { showMsg(2, 'err', d.error); btn.disabled = false; btn.textContent = 'Подтвердить'; return; }
    if (d.ok) {
      document.getElementById('expiresText').textContent =
        d.expires ? 'Токен действует до ' + new Date(d.expires).toLocaleString('ru-RU') + '. Можете закрыть страницу.' : 'Токен сохранён. Можете закрыть страницу.';
      show('step3'); return;
    }
    showMsg(2, 'err', 'Неожиданный ответ'); btn.disabled = false; btn.textContent = 'Подтвердить';
  } catch(e) {
    showMsg(2, 'err', 'Ошибка: ' + e.message);
    btn.disabled = false; btn.textContent = 'Подтвердить';
  }
}
document.getElementById('password').addEventListener('keydown', e => { if (e.key === 'Enter') submitCreds(); });
document.getElementById('code').addEventListener('keydown', e => { if (e.key === 'Enter') submitCode(); });
</script>
</body>
</html>`;
}

function connectFormHtml(service, meta, token) {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Подключить ${meta.name}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f5f7;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
  .card{background:#fff;border-radius:16px;padding:32px;max-width:480px;width:100%;box-shadow:0 2px 20px rgba(0,0,0,.08)}
  h1{font-size:20px;font-weight:600;margin-bottom:8px}
  .sub{color:#666;font-size:14px;margin-bottom:24px;line-height:1.5}
  .sub a{color:#007aff;text-decoration:none}
  label{display:block;font-size:13px;font-weight:500;color:#333;margin-bottom:6px}
  input{width:100%;border:1.5px solid #e0e0e0;border-radius:10px;padding:12px 14px;font-size:15px;font-family:monospace;outline:none;transition:border .15s}
  input:focus{border-color:#007aff}
  button{margin-top:16px;width:100%;background:#007aff;color:#fff;border:none;border-radius:10px;padding:13px;font-size:16px;font-weight:600;cursor:pointer;transition:opacity .15s}
  button:hover{opacity:.88}
  button:disabled{opacity:.5;cursor:default}
  .msg{margin-top:16px;padding:12px 14px;border-radius:10px;font-size:14px;display:none}
  .msg.ok{background:#e8f5e9;color:#2e7d32}
  .msg.err{background:#fdecea;color:#c62828}
  .lock{font-size:13px;color:#999;margin-top:20px;text-align:center}
</style>
</head>
<body>
<div class="card">
  <h1>Подключить ${meta.name}</h1>
  <p class="sub">Данные для входа поступают напрямую на сервер — в чат с ботом <b>не попадают</b>.<br><br>${meta.hint}</p>
  <label for="tok">Данные для авторизации</label>
  <input id="tok" type="password" placeholder="${meta.placeholder}" autocomplete="off" spellcheck="false">
  <button id="btn" onclick="submit()">Подключить</button>
  <div id="msg" class="msg"></div>
  <p class="lock">🔒 Данные не попадают в LLM · Ссылка одноразовая · <a href="/version" style="color:#999">v${VERSION}</a></p>
</div>
<script>
const T = '${token.replace(/'/g, "\\'")}';
async function submit() {
  const v = document.getElementById('tok').value.trim();
  if (!v) { show('err', 'Введите данные для входа'); return; }
  const btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = 'Подключаю…';
  try {
    const r = await fetch(location.pathname, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ t: T, value: v }),
    });
    const d = await r.json();
    if (d.ok) {
      show('ok', '✅ Готово! Можете закрыть страницу и вернуться в бот.');
      btn.style.display = 'none';
      document.getElementById('tok').disabled = true;
    } else {
      show('err', d.error || 'Ошибка');
      btn.disabled = false; btn.textContent = 'Подключить';
    }
  } catch(e) {
    show('err', 'Сетевая ошибка: ' + e.message);
    btn.disabled = false; btn.textContent = 'Подключить';
  }
}
function show(cls, text) {
  const el = document.getElementById('msg');
  el.className = 'msg ' + cls; el.textContent = text; el.style.display = 'block';
}
document.getElementById('tok').addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
</script>
</body>
</html>`;
}
