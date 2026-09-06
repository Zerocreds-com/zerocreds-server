'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { startNalogLogin, confirmNalogCode } = require('./nalog-login');
const { saveToDestination } = require('./destinations');

// ── Module-level pure helpers ──────────────────────────────────────────────────

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
    placeholder: 'Paste API token',
    hint: 'Weeek → Settings → Integrations → API → Generate token',
  },
  tilda: {
    name: 'Tilda',
    placeholder: 'Paste cookie string',
    hint: 'Open tilda.ru in your browser → F12 → Application → Cookies → copy the entire string',
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

function json(res, status, data, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...extraHeaders });
  res.end(JSON.stringify(data));
}

function parseCookieUid(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)zc_uid=([0-9a-f-]{36})/);
  return m ? m[1] : null;
}

function getOrCreateUid(req) {
  const existing = parseCookieUid(req);
  return { uid: existing || crypto.randomUUID(), hadCookie: !!existing };
}

function cookieSetHeader(uid, req) {
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `zc_uid=${uid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${secure}`;
}

// ── HTML templates (pure) ─────────────────────────────────────────────────────

function nalogFormHtml(token) {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Подключить Налог.ру</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d0f17;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;color:#c8cdd8}
  .card{background:#161924;border:1px solid #232635;border-radius:6px;padding:32px;max-width:460px;width:100%}
  h1{font-size:18px;font-weight:600;color:#e8eaf0;margin-bottom:6px;letter-spacing:-.2px}
  .sub{color:#6b7280;font-size:13.5px;margin-bottom:24px;line-height:1.55}
  .sub b{color:#a0aab8}
  label{display:block;font-size:12px;font-weight:500;color:#8892a4;margin-bottom:6px;margin-top:18px;letter-spacing:.03em}
  label:first-of-type{margin-top:0}
  input{width:100%;background:#0d0f17;border:1px solid #232635;border-radius:4px;padding:10px 12px;font-size:14px;color:#e8eaf0;outline:none;transition:border-color .15s}
  input:focus{border-color:#4068e8}
  input::placeholder{color:#3a3f52}
  button{margin-top:20px;width:100%;background:#4068e8;color:#fff;border:none;border-radius:4px;padding:11px;font-size:14px;font-weight:600;cursor:pointer;letter-spacing:.01em;transition:background .15s}
  button:hover{background:#3055cc}
  button:disabled{opacity:.35;cursor:default}
  .msg{margin-top:12px;padding:10px 12px;border-radius:4px;font-size:13px;display:none;border-left:2px solid}
  .msg.ok{background:#0a1f15;color:#4ade80;border-color:#16a34a}
  .msg.err{background:#1f0a0a;color:#f87171;border-color:#dc2626}
  .msg.info{background:#0a1220;color:#60a5fa;border-color:#3b82f6}
  .lock{font-size:11px;color:#2e3348;margin-top:20px;text-align:center;letter-spacing:.02em}
  .lock a{color:#2e3348;text-decoration:none}
  .lock a:hover{color:#6b7280}
  #step2{display:none}
  #step3{display:none;text-align:center;padding:12px 0}
  #step3 .check-icon{width:48px;height:48px;background:#0a1f15;border:1px solid #166534;border-radius:4px;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;color:#4ade80;font-size:22px}
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
    <div class="check-icon">✓</div>
    <h1>Налог.ру подключён</h1>
    <p class="sub" id="expiresText">Данные авторизации сохранены. Можете закрыть эту страницу и вернуться в бот.</p>
  </div>
  <p class="lock">Данные не попадают в LLM &middot; Ссылка одноразовая &middot; <a href="/version">v${VERSION}</a></p>
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

function aboutHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>How it works — ZeroCreds</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f5f7;color:#1d1d1f;padding:40px 20px;line-height:1.6}
  .wrap{max-width:680px;margin:0 auto}
  .brand{display:flex;align-items:center;gap:10px;margin-bottom:40px}
  .brand-icon{width:36px;height:36px;background:#007aff;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
  .brand-name{font-size:22px;font-weight:700;letter-spacing:-.5px}
  .brand-tag{font-size:13px;color:#666;margin-top:1px}
  h1{font-size:28px;font-weight:700;letter-spacing:-.5px;margin-bottom:10px}
  .lead{font-size:16px;color:#444;margin-bottom:40px;max-width:520px}
  h2{font-size:17px;font-weight:600;margin-bottom:16px;margin-top:40px}
  .diagram{background:#fff;border-radius:16px;padding:28px 24px;box-shadow:0 2px 16px rgba(0,0,0,.07);margin-bottom:40px;overflow-x:auto}
  .flow{display:flex;flex-direction:column;gap:0}
  .row{display:flex;align-items:center;gap:12px;min-height:48px}
  .row.indent{padding-left:32px}
  .box{border-radius:10px;padding:8px 14px;font-size:13px;font-weight:500;white-space:nowrap;flex-shrink:0}
  .box.ai{background:#e8f0fe;color:#1a56db;border:1.5px solid #c5d5fb}
  .box.zc{background:#f0fdf4;color:#15803d;border:1.5px solid #bbf7d0}
  .box.usr{background:#fff7ed;color:#c2410c;border:1.5px solid #fed7aa}
  .box.store{background:#f5f3ff;color:#6d28d9;border:1.5px solid #ddd6fe}
  .arr{color:#999;font-size:13px;flex-shrink:0}
  .label{font-size:12px;color:#666;flex:1}
  .connector{width:2px;height:20px;background:#e5e7eb;margin-left:22px}
  .highlight{background:#f0fdf4;border:1.5px solid #86efac;border-radius:12px;padding:16px 20px;margin:24px 0;font-size:14px;color:#166534}
  .highlight strong{display:block;font-size:15px;margin-bottom:4px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
  @media(max-width:500px){.grid{grid-template-columns:1fr}}
  .cell{background:#fff;border-radius:12px;padding:18px;box-shadow:0 1px 8px rgba(0,0,0,.06)}
  .cell h3{font-size:14px;font-weight:600;margin-bottom:6px}
  .cell p{font-size:13px;color:#555}
  .tag{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:20px;margin-bottom:8px}
  .tag.local{background:#dcfce7;color:#166534}
  .tag.remote{background:#fef3c7;color:#92400e}
  footer{margin-top:48px;font-size:12px;color:#aaa;text-align:center}
  a{color:#007aff;text-decoration:none}
  a:hover{text-decoration:underline}
  .never{color:#dc2626;font-weight:600}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand">
    <div class="brand-icon">🔐</div>
    <div>
      <div class="brand-name">ZeroCreds</div>
      <div class="brand-tag">Credentials never reach the AI</div>
    </div>
  </div>

  <h1>Credentials never leave your machine</h1>
  <p class="lead">When ZeroCreds runs on localhost, your passwords and API tokens go straight into your local secret store — they never touch the internet or the AI model.</p>

  <h2>How it works</h2>
  <div class="diagram">
    <div class="flow">
      <div class="row">
        <div class="box ai">AI Agent</div>
        <div class="arr">──1──▶</div>
        <div class="box zc">ZeroCreds (localhost)</div>
        <div class="label">create_session() — no credentials here</div>
      </div>
      <div class="connector"></div>
      <div class="row">
        <div class="box zc">ZeroCreds (localhost)</div>
        <div class="arr">──2──▶</div>
        <div class="box ai">AI Agent</div>
        <div class="label">returns one-time URL</div>
      </div>
      <div class="connector"></div>
      <div class="row">
        <div class="box ai">AI Agent</div>
        <div class="arr">──3──▶</div>
        <div class="box usr">User</div>
        <div class="label">sends URL (in chat, Telegram, etc.)</div>
      </div>
      <div class="connector"></div>
      <div class="row">
        <div class="box usr">User</div>
        <div class="arr">──4──▶</div>
        <div class="box zc">ZeroCreds (localhost)</div>
        <div class="label">opens form, enters credentials, clicks Submit</div>
      </div>
      <div class="connector"></div>
      <div class="row">
        <div class="box zc">ZeroCreds (localhost)</div>
        <div class="arr">──5──▶</div>
        <div class="box store">~/agent-tokens/ · Keychain</div>
        <div class="label">saves to local secret store</div>
      </div>
      <div class="connector"></div>
      <div class="row">
        <div class="box ai">AI Agent</div>
        <div class="arr">←─6──</div>
        <div class="box zc">ZeroCreds (localhost)</div>
        <div class="label">polls status → gets <code style="background:#f3f4f6;padding:1px 5px;border-radius:4px">{ status: "done" }</code></div>
      </div>
    </div>

    <div class="highlight" style="margin-top:24px;margin-bottom:0">
      <strong>🔒 The AI never sees your credentials</strong>
      Steps 1, 2, 6 carry no sensitive data. Step 4 goes directly from your browser to localhost — it never leaves your computer. The AI only learns that the operation succeeded.
    </div>
  </div>

  <h2>Local vs. remote deployment</h2>
  <div class="grid">
    <div class="cell">
      <div class="tag local">✓ localhost</div>
      <h3>Credentials stay on your machine</h3>
      <p>ZeroCreds runs at <code>localhost:3456</code>. Your browser POSTs credentials to localhost. They are saved to <code>~/agent-tokens/</code> or your OS Keychain. Nothing leaves the computer.</p>
    </div>
    <div class="cell">
      <div class="tag remote">⚠ remote server</div>
      <h3>You trust the ZeroCreds server</h3>
      <p>When ZeroCreds runs on a remote host (e.g. your own VPS), credentials travel over HTTPS to that server. The AI still never sees them — but you are trusting the server, not only your own machine.</p>
    </div>
  </div>

  <h2>What the AI sees at each step</h2>
  <div class="diagram" style="padding:20px 24px">
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead>
        <tr style="border-bottom:2px solid #e5e7eb">
          <th style="text-align:left;padding:8px 0;color:#666;font-weight:500">Step</th>
          <th style="text-align:left;padding:8px 0;color:#666;font-weight:500">AI agent sends / receives</th>
          <th style="text-align:left;padding:8px 0;color:#666;font-weight:500">Credentials visible to AI?</th>
        </tr>
      </thead>
      <tbody>
        <tr style="border-bottom:1px solid #f3f4f6">
          <td style="padding:10px 0;font-weight:500">Session create</td>
          <td style="padding:10px 0;color:#555">form title, field names, destination config</td>
          <td style="padding:10px 0"><span class="never">No</span></td>
        </tr>
        <tr style="border-bottom:1px solid #f3f4f6">
          <td style="padding:10px 0;font-weight:500">URL returned</td>
          <td style="padding:10px 0;color:#555">one-time link, expiry timestamp</td>
          <td style="padding:10px 0"><span class="never">No</span></td>
        </tr>
        <tr style="border-bottom:1px solid #f3f4f6">
          <td style="padding:10px 0;font-weight:500">User fills form</td>
          <td style="padding:10px 0;color:#555"><em>AI is not involved at all</em></td>
          <td style="padding:10px 0"><span class="never">No</span></td>
        </tr>
        <tr>
          <td style="padding:10px 0;font-weight:500">Status poll</td>
          <td style="padding:10px 0;color:#555"><code style="background:#f3f4f6;padding:1px 5px;border-radius:4px">{ status: "done" }</code></td>
          <td style="padding:10px 0"><span class="never">No</span></td>
        </tr>
      </tbody>
    </table>
  </div>

  <footer>
    ZeroCreds is open source &mdash; <a href="https://github.com/Zerocreds-com/zerocreds-server" target="_blank">github.com/Zerocreds-com/zerocreds-server</a>
  </footer>
</div>
</body>
</html>`;
}

function expiredHtml() {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Link expired — ZeroCreds</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d0f17;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;color:#c8cdd8}.card{background:#161924;border:1px solid #232635;border-radius:6px;padding:32px;max-width:460px;width:100%;text-align:center}.exp-icon{width:48px;height:48px;background:#1a1400;border:1px solid #3a2800;border-radius:4px;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;color:#f59e0b;font-size:20px}h1{font-size:18px;font-weight:600;color:#e8eaf0;margin-bottom:8px;letter-spacing:-.2px}.sub{color:#6b7280;font-size:13.5px;line-height:1.55}</style>
</head><body><div class="card"><div class="exp-icon">⏱</div><h1>Link expired</h1><p class="sub">This link has expired or has already been used. Request a new one.</p></div></body></html>`;
}

const LEVEL_META = {
  secret:     { tag: 'SECRET',   color: '#6b3535', bg: '#160d0d', border: '#2a1818', label: 'Secret store',       aiSees: 'Never',          logs: 'Never logged', desc: 'Data goes directly to a secret store. The AI assistant never sees it.' },
  pii:        { tag: 'PII DATA', color: '#6b5530', bg: '#151000', border: '#2a2010', label: 'Personal data',      aiSees: 'For tasks only', logs: 'Anonymised',   desc: 'The AI can use this for tasks. Not stored in logs in plain form.' },
  attribute:  { tag: 'CONFIG',   color: '#3d4f6a', bg: '#0c1018', border: '#1a2030', label: 'Configuration',      aiSees: 'Openly',         logs: 'Yes',          desc: 'Open configuration. The AI uses this in every request.' },
  credential: { tag: 'SESSION',  color: '#4a3a6a', bg: '#0f0c18', border: '#221838', label: 'Session credential', aiSees: 'This session',   logs: 'Never logged', desc: 'Used only in the current session. Not saved to logs.' },
};

function dynamicFormHtml(token, pending, savedValues = {}) {
  const fields = pending.fields || [];
  const title = pending.title || 'Enter your credentials';
  const description = pending.description || 'Credentials go straight into your secret store — the AI assistant <b>never sees them</b>.';

  function escAttr(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  }
  function escHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }


  function levelBadge(f) {
    const lm = LEVEL_META[f.level];
    if (!lm) return '';
    return `<div class="level-tag"><span class="level-chip" style="color:${lm.color};background:${lm.bg};border-color:${lm.border}">${lm.tag}</span><button type="button" class="level-btn" onclick="toggleInfo('${f.name}')" title="What happens to this data?">ⓘ</button></div>`;
  }

  function levelInfoCard(f) {
    const lm = LEVEL_META[f.level];
    if (!lm) return '';
    return `<div id="info_${f.name}" class="level-info" style="display:none;border-left-color:${lm.border};background:${lm.bg}">
  <div class="level-info-title" style="color:${lm.color}">${lm.tag} — ${lm.label}</div>
  <table class="level-table">
    <tr><td>ZeroCreds server</td><td>Receives</td></tr>
    <tr><td>AI assistant</td><td>${lm.aiSees}</td></tr>
    <tr><td>Logs</td><td>${lm.logs}</td></tr>
  </table>
  <div class="level-desc">${lm.desc}</div>
</div>`;
  }

  const fieldHtml = fields.map(f => {
    const type = f.type || 'text';
    const ph = escAttr(f.placeholder || '');
    const req = f.required !== false ? 'required' : '';
    const labelHtml = `<label for="f_${f.name}" class="field-label">${escHtml(f.label)}${levelBadge(f)}</label>${levelInfoCard(f)}`;
    if (type === 'textarea') {
      const val = escAttr(savedValues[f.name] || '');
      return `${labelHtml}<textarea id="f_${f.name}" name="${f.name}" placeholder="${ph}" ${req} rows="4">${val}</textarea>`;
    }
    if (type === 'password') {
      return `${labelHtml}<div class="pw-wrap"><input id="f_${f.name}" name="${f.name}" type="password" placeholder="${ph}" autocomplete="current-password" spellcheck="false" ${req}><button type="button" class="pw-btn eye" onclick="togglePw('f_${f.name}')" title="Show/hide">👁</button><button type="button" class="pw-btn paste" onclick="pastePw('f_${f.name}')">Paste</button></div>`;
    }
    const val = savedValues[f.name] ? ` value="${escAttr(savedValues[f.name])}"` : '';
    return `${labelHtml}<input id="f_${f.name}" name="${f.name}" type="${type}" placeholder="${ph}" autocomplete="off" spellcheck="false" ${req}${val}>`;
  }).join('\n  ');

  const fieldNames = JSON.stringify(fields.map(f => f.name));

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escHtml(title)}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#111316;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;color:#9aa0b0}
  .card{background:#18191f;border:1px solid #26282f;border-radius:5px;padding:32px;max-width:460px;width:100%}
  h1{font-size:18px;font-weight:600;color:#dde0e8;margin-bottom:6px;letter-spacing:-.2px}
  .sub{color:#5a606f;font-size:13.5px;margin-bottom:24px;line-height:1.55}
  .sub b{color:#8a909f}
  label{display:block;font-size:12px;font-weight:500;color:#6a707f;margin-bottom:6px;margin-top:18px;letter-spacing:.03em}
  label:first-of-type{margin-top:0}
  input,textarea{width:100%;background:#111316;border:1px solid #26282f;border-radius:4px;padding:10px 12px;font-size:14px;font-family:inherit;color:#dde0e8;outline:none;transition:border-color .15s;resize:vertical}
  input:focus,textarea:focus{border-color:#4a505e}
  input::placeholder,textarea::placeholder{color:#32353d}
  .pw-wrap{position:relative}
  .pw-wrap input{padding-right:108px;font-family:'SF Mono',Monaco,Consolas,monospace;font-size:13px;letter-spacing:.02em}
  .pw-btn{position:absolute;top:50%;transform:translateY(-50%);border:none;cursor:pointer;background:none;color:#505560;margin:0;width:auto;line-height:1;padding:4px 6px;border-radius:3px;font-size:13px;transition:color .15s}
  .pw-btn:hover{color:#9aa0b0;background:#22242c}
  .pw-btn.eye{right:62px}
  .pw-btn.paste{right:8px;background:#22242c;color:#7a8090;font-weight:600;font-size:11px;padding:3px 9px;border:1px solid #2e3038;border-radius:3px;letter-spacing:.03em}
  .pw-btn.paste:hover{background:#2a2c35;color:#9aa0b0}
  button#btn{margin-top:20px;width:100%;background:#dde0e8;color:#111316;border:none;border-radius:4px;padding:11px;font-size:14px;font-weight:600;cursor:pointer;letter-spacing:.01em;transition:background .15s}
  button#btn:hover{background:#eef0f5}
  button#btn:disabled{opacity:.3;cursor:default}
  .msg{margin-top:12px;padding:10px 12px;border-radius:4px;font-size:13px;display:none;border-left:2px solid}
  .msg.ok{background:#0d1a12;color:#6bcf8a;border-color:#2a5c3a}
  .msg.err{background:#1a0e0e;color:#cf6b6b;border-color:#5c2a2a}
  .zc-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;padding-bottom:18px;border-bottom:1px solid #22242c}
  .zc-brand{display:flex;align-items:center;gap:8px}
  .zc-wordmark{font-size:14px;font-weight:700;color:#dde0e8;letter-spacing:-.2px}
  .zc-badge{font-size:10px;font-weight:600;letter-spacing:.08em;color:#3d4050;background:#16171c;border:1px solid #22242c;padding:3px 8px;border-radius:3px;text-transform:uppercase}
  #done{display:none;text-align:center;padding:12px 0}
  #done .check-icon{width:48px;height:48px;background:#0d1a12;border:1px solid #2a5c3a;border-radius:4px;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;color:#6bcf8a;font-size:22px}
  .lock{font-size:11px;color:#2a2d35;margin-top:20px;text-align:center;letter-spacing:.02em}
  .lock a{color:#2a2d35;text-decoration:none}
  .lock a:hover{color:#5a606f}
  .field-label{display:flex;align-items:center;justify-content:space-between;font-size:12px;font-weight:500;color:#6a707f;margin-bottom:6px;margin-top:18px;letter-spacing:.03em}
  .field-label:first-of-type{margin-top:0}
  .level-tag{display:flex;align-items:center;gap:5px;flex-shrink:0}
  .level-chip{font-size:9px;font-weight:700;letter-spacing:.1em;padding:2px 6px;border-radius:3px;border:1px solid;text-transform:uppercase;white-space:nowrap}
  .level-btn{background:none;border:none;cursor:pointer;padding:0 2px;margin:0;width:auto;font-size:12px;line-height:1;color:#30333c;transition:color .15s}
  .level-btn:hover{color:#6a707f}
  .level-info{margin-top:6px;margin-bottom:10px;padding:12px 14px;border-radius:4px;font-size:12px;line-height:1.5;border-left:2px solid}
  .level-info-title{font-weight:700;margin-bottom:8px;font-size:11px;letter-spacing:.08em;text-transform:uppercase}
  .level-table{border-collapse:collapse;width:100%;margin-bottom:8px}
  .level-table td{padding:3px 0;font-size:11px}
  .level-table td:first-child{color:#505560;width:55%}
  .level-table td:last-child{font-weight:600;color:#9aa0b0}
  .level-desc{color:#505560;font-size:11px;line-height:1.5}
</style>
</head>
<body>
<div class="card">
  <div class="zc-header">
    <div class="zc-brand">
      <div class="zc-dot"></div>
      <span class="zc-wordmark">ZeroCreds</span>
    </div>
    <span class="zc-badge">Secure Form</span>
  </div>
  <div id="form-view">
    <h1>${escHtml(title)}</h1>
    <p class="sub">${description}</p>
    ${fieldHtml}
    <button id="btn" onclick="submit()">Submit</button>
    <div id="msg" class="msg"></div>
  </div>
  <div id="done">
    <div class="check-icon">✓</div>
    <h1>Done</h1>
    <p class="sub">Credentials saved. You can close this page.</p>
  </div>
  <p class="lock">Credentials never reach the AI &middot; One-time link &middot; <a href="/about">How it works</a> &middot; <a href="/version">v${VERSION}</a></p>
</div>
<script>
const T = '${token}';
const FIELD_NAMES = ${fieldNames};
function togglePw(id) {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
}
function toggleInfo(name) {
  const el = document.getElementById('info_' + name);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
async function pastePw(id) {
  try {
    const text = await navigator.clipboard.readText();
    document.getElementById(id).value = text.trim();
  } catch {
    showMsg('err', 'Allow clipboard access or paste manually (Ctrl+V / ⌘V)');
  }
}
async function submit() {
  const fields = {};
  for (const name of FIELD_NAMES) {
    const el = document.getElementById('f_' + name);
    if (el) fields[name] = el.value.trim();
  }
  const empty = FIELD_NAMES.find(n => {
    const el = document.getElementById('f_' + n);
    return el && el.required && !fields[n];
  });
  if (empty) { showMsg('err', 'Please fill in all required fields'); return; }
  const btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = 'Saving…';
  try {
    const r = await fetch(location.pathname, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ t: T, fields }),
    });
    const d = await r.json();
    if (d.ok) {
      document.getElementById('form-view').style.display = 'none';
      document.getElementById('done').style.display = '';
    } else {
      showMsg('err', d.detail ? (d.error + ': ' + d.detail) : (d.error || 'Server error'));
      btn.disabled = false; btn.textContent = 'Submit';
    }
  } catch(e) {
    showMsg('err', 'Network error: ' + e.message);
    btn.disabled = false; btn.textContent = 'Submit';
  }
}
function showMsg(cls, text) {
  const el = document.getElementById('msg');
  el.className = 'msg ' + cls; el.textContent = text; el.style.display = 'block';
}
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target.tagName === 'INPUT') submit();
});
</script>
</body>
</html>`;
}

function connectFormHtml(service, meta, token) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect ${meta.name} — ZeroCreds</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d0f17;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;color:#c8cdd8}
  .card{background:#161924;border:1px solid #232635;border-radius:6px;padding:32px;max-width:460px;width:100%}
  h1{font-size:18px;font-weight:600;color:#e8eaf0;margin-bottom:6px;letter-spacing:-.2px}
  .sub{color:#6b7280;font-size:13.5px;margin-bottom:24px;line-height:1.55}
  .sub a{color:#4068e8;text-decoration:none}
  .sub b{color:#a0aab8}
  label{display:block;font-size:12px;font-weight:500;color:#8892a4;margin-bottom:6px;letter-spacing:.03em}
  input{width:100%;background:#0d0f17;border:1px solid #232635;border-radius:4px;padding:10px 12px;font-size:13px;font-family:'SF Mono',Monaco,Consolas,monospace;color:#e8eaf0;outline:none;transition:border-color .15s;letter-spacing:.02em}
  input:focus{border-color:#4068e8}
  input::placeholder{color:#3a3f52}
  button{margin-top:16px;width:100%;background:#4068e8;color:#fff;border:none;border-radius:4px;padding:11px;font-size:14px;font-weight:600;cursor:pointer;letter-spacing:.01em;transition:background .15s}
  button:hover{background:#3055cc}
  button:disabled{opacity:.35;cursor:default}
  .msg{margin-top:12px;padding:10px 12px;border-radius:4px;font-size:13px;display:none;border-left:2px solid}
  .msg.ok{background:#0a1f15;color:#4ade80;border-color:#16a34a}
  .msg.err{background:#1f0a0a;color:#f87171;border-color:#dc2626}
  .lock{font-size:11px;color:#2e3348;margin-top:20px;text-align:center;letter-spacing:.02em}
  .lock a{color:#2e3348;text-decoration:none}
  .lock a:hover{color:#6b7280}
</style>
</head>
<body>
<div class="card">
  <h1>Connect ${meta.name}</h1>
  <p class="sub">Credentials go directly to the server — your AI assistant <b>never sees them</b>.<br><br>${meta.hint}</p>
  <label for="tok">Authorization data</label>
  <input id="tok" type="password" placeholder="${meta.placeholder}" autocomplete="off" spellcheck="false">
  <button id="btn" onclick="submit()">Connect</button>
  <div id="msg" class="msg"></div>
  <p class="lock">Credentials never reach the AI &middot; One-time link &middot; <a href="/version">v${VERSION}</a></p>
</div>
<script>
const T = '${token.replace(/'/g, "\\'")}';
async function submit() {
  const v = document.getElementById('tok').value.trim();
  if (!v) { show('err', 'Please enter credentials'); return; }
  const btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = 'Connecting…';
  try {
    const r = await fetch(location.pathname, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ t: T, value: v }),
    });
    const d = await r.json();
    if (d.ok) {
      show('ok', '✅ Done! You can close this page.');
      btn.style.display = 'none';
      document.getElementById('tok').disabled = true;
    } else {
      show('err', d.error || 'Error');
      btn.disabled = false; btn.textContent = 'Connect';
    }
  } catch(e) {
    show('err', 'Network error: ' + e.message);
    btn.disabled = false; btn.textContent = 'Connect';
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

// ── App factory ───────────────────────────────────────────────────────────────

function createApp(config = {}) {
  const ADMIN_TOKEN = config.adminToken ?? process.env.ZEROCREDS_ADMIN_TOKEN ?? '';
  const CONNECT_PENDING_DIR = config.pendingDir ?? process.env.ZEROCREDS_PENDING_DIR ?? path.join(os.homedir(), 'connect-pending');
  const AGENT_TOKENS_DIR = config.tokensDir ?? process.env.ZEROCREDS_TOKENS_DIR ?? path.join(os.homedir(), 'agent-tokens');
  const SAVED_DIR = config.savedDir ?? process.env.ZEROCREDS_SAVED_DIR ?? path.join(os.homedir(), 'zerocreds-saved');
  const DESTINATIONS_FILE = config.destinationsFile ?? process.env.ZEROCREDS_DESTINATIONS_FILE ?? path.join(os.homedir(), 'zerocreds-destinations.json');
  const INTEGRATORS_FILE = config.integratorsFile ?? process.env.ZEROCREDS_INTEGRATORS_FILE ?? path.join(os.homedir(), 'zerocreds-integrators.json');
  const BASE_URL = config.baseUrl ?? process.env.ZEROCREDS_BASE_URL ?? 'https://zerocreds.ru';

  try { fs.mkdirSync(SAVED_DIR, { recursive: true, mode: 0o700 }); } catch {}

  // Named destinations (admin-configured, SA keys never travel in API requests)
  let NAMED_DESTINATIONS = {};
  function loadNamedDestinations() {
    try {
      NAMED_DESTINATIONS = JSON.parse(fs.readFileSync(DESTINATIONS_FILE, 'utf8'));
      console.log(`[config] loaded ${Object.keys(NAMED_DESTINATIONS).length} named destination(s)`);
    } catch (e) {
      if (e.code !== 'ENOENT') console.warn('[config] destinations file error:', e.message);
    }
  }
  loadNamedDestinations();

  // Integrators registry
  let INTEGRATORS = {};
  function loadIntegrators() {
    try {
      INTEGRATORS = JSON.parse(fs.readFileSync(INTEGRATORS_FILE, 'utf8'));
      console.log(`[config] loaded ${Object.keys(INTEGRATORS).length} integrator(s)`);
    } catch (e) {
      if (e.code !== 'ENOENT') console.warn('[config] integrators file error:', e.message);
    }
  }
  loadIntegrators();

  function saveIntegrators() {
    fs.writeFileSync(INTEGRATORS_FILE, JSON.stringify(INTEGRATORS, null, 2), { mode: 0o600 });
  }

  // Rate limit for self-serve registration: max 3 tokens per IP per hour
  const registerRateLimit = new Map();
  function checkRegisterLimit(ip) {
    const now = Date.now();
    const window = 60 * 60 * 1000;
    const hits = (registerRateLimit.get(ip) || []).filter(t => now - t < window);
    if (hits.length >= 3) return false;
    hits.push(now);
    registerRateLimit.set(ip, hits);
    return true;
  }

  // Resolve auth: returns { isAdmin, integrator|null }
  function resolveAuth(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) return { isAdmin: false, integrator: null };
    const token = authHeader.slice(7);
    if (ADMIN_TOKEN && token === ADMIN_TOKEN) return { isAdmin: true, integrator: null };
    if (INTEGRATORS[token]) return { isAdmin: false, integrator: { token, ...INTEGRATORS[token] } };
    return { isAdmin: false, integrator: null };
  }

  // Resolve destination: name → config, checking integrator's destinations first
  function resolveDestination(destination, integrator) {
    if (typeof destination !== 'string') return destination; // inline object, use as-is
    if (integrator?.destinations?.[destination]) return integrator.destinations[destination];
    if (NAMED_DESTINATIONS[destination]) return NAMED_DESTINATIONS[destination];
    return null;
  }

  function readPending(token) {
    const file = path.join(CONNECT_PENDING_DIR, `${token}.json`);
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
  }

  function deletePending(token) {
    try { fs.unlinkSync(path.join(CONNECT_PENDING_DIR, `${token}.json`)); } catch {}
  }

  // Scan for an active (not expired, not done) session matching integrator+service+user_hash.
  function findActiveSession(integrator_id, service_slug, user_hash) {
    let files;
    try { files = fs.readdirSync(CONNECT_PENDING_DIR).filter(f => f.endsWith('.json')); }
    catch { return null; }
    for (const file of files) {
      const token = file.slice(0, -5);
      if (fs.existsSync(path.join(CONNECT_PENDING_DIR, `${token}.done`))) continue;
      try {
        const s = JSON.parse(fs.readFileSync(path.join(CONNECT_PENDING_DIR, file), 'utf8'));
        if (s.integrator_id === integrator_id &&
            s.service_slug === service_slug &&
            s.user_hash === user_hash &&
            s.expires > Date.now()) return s;
      } catch {}
    }
    return null;
  }

  function readSaved(uid) {
    if (!uid) return {};
    try { return JSON.parse(fs.readFileSync(path.join(SAVED_DIR, `${uid}.json`), 'utf8')); }
    catch { return {}; }
  }

  function writeSaved(uid, submittedFields, fieldDefs) {
    if (!uid) return;
    const existing = readSaved(uid);
    for (const f of fieldDefs) {
      if (f.type !== 'password' && submittedFields[f.name] !== undefined && submittedFields[f.name] !== '') {
        existing[f.name] = submittedFields[f.name];
      }
    }
    try { fs.writeFileSync(path.join(SAVED_DIR, `${uid}.json`), JSON.stringify(existing), { mode: 0o600 }); }
    catch (e) { console.error('[saved] write failed:', e.message); }
  }

  function writeSavedRef(uid, pending, secretId) {
    if (!uid || !secretId) return;
    const existing = readSaved(uid);
    const fp = `__ref__${pending.title}`;
    existing[fp] = secretId;
    try { fs.writeFileSync(path.join(SAVED_DIR, `${uid}.json`), JSON.stringify(existing), { mode: 0o600 }); }
    catch (e) { console.error('[saved-ref] write failed:', e.message); }
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');

    // CORS preflight for API
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type,Authorization', 'Access-Control-Allow-Methods': 'GET,POST' }).end();
      return;
    }

    // GET / — redirect to landing
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(301, { Location: 'https://zerocreds.ru' }).end();
      return;
    }

    // GET /about
    if (req.method === 'GET' && url.pathname === '/about') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(aboutHtml());
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
          if (!/^-?[a-zA-Z0-9_-]{1,128}$/.test(pending.uid)) return json(res, 403, { error: 'invalid uid' });

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
        if (t && /^[a-f0-9]{32}$/.test(t)) {
          const p = readPending(t);
          if (!p || p.expires < Date.now()) {
            res.writeHead(410, { 'Content-Type': 'text/html; charset=utf-8' }).end(expiredHtml());
            return;
          }
        }
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
        if (!/^-?[a-zA-Z0-9_-]{1,128}$/.test(pending.uid)) return json(res, 403, { error: 'invalid uid' });

        const tokensDir = path.join(AGENT_TOKENS_DIR, pending.uid);
        fs.mkdirSync(tokensDir, { recursive: true });
        fs.writeFileSync(path.join(tokensDir, service), String(value).trim(), { mode: 0o600 });
        deletePending(t);

        console.log(`[connect] saved ${service} token for uid=${pending.uid}`);
        json(res, 200, { ok: true });

        if (pending.tg_bot_token) {
          const name = meta.name;
          tgNotify(pending.tg_bot_token, pending.tg_chat_id || pending.uid,
            `✅ ${name} connected! Token saved.`);
        }
        return;
      }

      res.writeHead(405).end(); return;
    }

    // ── POST /api/register ────────────────────────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/api/register') {
      const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
      if (!checkRegisterLimit(ip)) return json(res, 429, { error: 'Too many registrations from this IP. Try again in an hour.' });
      const body = await readBody(req);
      let payload = {};
      try { payload = JSON.parse(body); } catch {}
      const { email, website, category } = payload;
      if (!email || !email.includes('@')) return json(res, 400, { error: 'Valid email is required' });
      const VALID_CATEGORIES = ['ai_agent', 'saas', 'internal', 'personal', 'other'];
      if (!category || !VALID_CATEGORIES.includes(category)) return json(res, 400, { error: 'Category is required' });
      const token = 'tok_' + crypto.randomBytes(20).toString('hex');
      const id = 'u_' + crypto.randomBytes(6).toString('hex');
      INTEGRATORS[token] = { id, name: id, email, website: website || '', category, destinations: {}, created: new Date().toISOString() };
      saveIntegrators();
      console.log(`[register] new integrator: ${id} email=${email} category=${category} from ${ip}`);
      return json(res, 200, { token, base_url: BASE_URL });
    }

    // ── POST /admin/integrators/create ────────────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/admin/integrators/create') {
      const { isAdmin } = resolveAuth(req.headers['authorization']);
      if (!isAdmin) return json(res, 401, { error: 'admin token required' });
      const body = await readBody(req);
      let payload;
      try { payload = JSON.parse(body); } catch { return json(res, 400, { error: 'bad json' }); }
      const { id, name } = payload;
      if (!id || !name) return json(res, 400, { error: 'missing id or name' });
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) return json(res, 400, { error: 'invalid id' });
      const token = 'tok_' + crypto.randomBytes(20).toString('hex');
      INTEGRATORS[token] = { id, name, destinations: {}, created: new Date().toISOString() };
      saveIntegrators();
      console.log(`[admin] created integrator: ${id} (${name})`);
      return json(res, 200, { token, id, name });
    }

    // ── POST /api/destinations ─────────────────────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/api/destinations') {
      const { isAdmin, integrator } = resolveAuth(req.headers['authorization']);
      if (!isAdmin && !integrator) return json(res, 401, { error: 'unauthorized' });
      const body = await readBody(req);
      let payload;
      try { payload = JSON.parse(body); } catch { return json(res, 400, { error: 'bad json' }); }
      const { name, destination } = payload;
      if (!name || !destination?.type) return json(res, 400, { error: 'missing name or destination.type' });
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) return json(res, 400, { error: 'invalid name' });

      if (isAdmin) {
        NAMED_DESTINATIONS[name] = destination;
        fs.writeFileSync(DESTINATIONS_FILE, JSON.stringify(NAMED_DESTINATIONS, null, 2), { mode: 0o600 });
      } else {
        INTEGRATORS[integrator.token].destinations[name] = destination;
        saveIntegrators();
      }
      return json(res, 200, { ok: true, name });
    }

    // ── POST /api/session/create ───────────────────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/api/session/create') {
      const { isAdmin, integrator } = resolveAuth(req.headers['authorization']);
      if (ADMIN_TOKEN && !isAdmin && !integrator) return json(res, 401, { error: 'unauthorized' });
      const body = await readBody(req);
      let payload;
      try { payload = JSON.parse(body); } catch { return json(res, 400, { error: 'bad json' }); }

      let { title, description, fields, destination, destinations_by_level, ttl_minutes = 30, notify, allow_save, uid, service } = payload;
      if (!title || !Array.isArray(fields) || fields.length === 0) {
        return json(res, 400, { error: 'missing title or fields' });
      }
      if (!destination && !destinations_by_level) {
        return json(res, 400, { error: 'missing destination or destinations_by_level' });
      }

      // Resolve destinations_by_level if provided
      let resolvedByLevel = null;
      if (destinations_by_level) {
        if (typeof destinations_by_level !== 'object' || Array.isArray(destinations_by_level)) {
          return json(res, 400, { error: 'destinations_by_level must be an object' });
        }
        resolvedByLevel = {};
        for (const [level, dest] of Object.entries(destinations_by_level)) {
          const r = resolveDestination(dest, integrator);
          if (r === null) {
            return json(res, 400, { error: typeof dest === 'string'
              ? `unknown named destination for level "${level}": ${dest}`
              : `destination.type required for level "${level}"` });
          }
          if (!r?.type) return json(res, 400, { error: `destination.type required for level "${level}"` });
          resolvedByLevel[level] = r;
        }
      }

      // Resolve single destination if provided
      if (destination) {
        const resolved = resolveDestination(destination, integrator);
        if (resolved === null) {
          return json(res, 400, { error: typeof destination === 'string'
            ? `unknown named destination: ${destination}`
            : 'destination.type is required' });
        }
        destination = resolved;
        if (!destination?.type) {
          return json(res, 400, { error: 'destination.type is required' });
        }
      }

      // Validate fields
      const VALID_TYPES = ['text', 'password', 'email', 'number', 'tel', 'textarea', 'url'];
      const VALID_LEVELS = ['secret', 'pii', 'attribute', 'credential'];
      for (const f of fields) {
        if (!f.name || !f.label) return json(res, 400, { error: `field missing name or label: ${JSON.stringify(f)}` });
        if (!/^[a-zA-Z0-9_]{1,64}$/.test(f.name)) return json(res, 400, { error: `invalid field name: ${f.name}` });
        if (f.type && !VALID_TYPES.includes(f.type)) return json(res, 400, { error: `invalid field type: ${f.type}` });
        if (f.level && !VALID_LEVELS.includes(f.level)) return json(res, 400, { error: `invalid field level: ${f.level}` });
      }

      const integrator_id = integrator?.id || 'admin';

      // Deterministic URL: integrators may pass uid + service for idempotent sessions
      const useDeterministic = integrator && uid && service;
      if (useDeterministic && !/^[a-zA-Z0-9_-]{1,64}$/.test(service)) {
        return json(res, 400, { error: 'invalid service: must match [a-zA-Z0-9_-]{1,64}' });
      }

      let user_hash, service_slug;
      if (useDeterministic) {
        service_slug = service;
        // HMAC keyed on integrator token — not reversible without the key
        user_hash = crypto.createHmac('sha256', integrator.token).update(String(uid)).digest('hex').slice(0, 10);

        // Idempotency: return existing active session for same integrator+service+user
        const existing = findActiveSession(integrator_id, service_slug, user_hash);
        if (existing) {
          return json(res, 200, {
            token: existing.token,
            url: `${BASE_URL}/${integrator_id}/${service_slug}/${user_hash}?gen=${existing.token}`,
            expires_at: new Date(existing.expires).toISOString(),
            reused: true,
          });
        }
      }

      const token = crypto.randomBytes(16).toString('hex');
      const expires = Date.now() + Math.min(Math.max(ttl_minutes, 1), 1440) * 60 * 1000;

      const pending = { token, title, description, fields,
        destination: destination || null,
        destinations_by_level: resolvedByLevel || null,
        expires, notify,
        integrator_id,
        uid: uid || null,
        allowSave: allow_save !== false,
        ...(useDeterministic ? { service_slug, user_hash, integrator_slug: integrator_id } : {}),
      };
      fs.mkdirSync(CONNECT_PENDING_DIR, { recursive: true });
      fs.writeFileSync(path.join(CONNECT_PENDING_DIR, `${token}.json`), JSON.stringify(pending), { mode: 0o600 });

      const url_out = useDeterministic
        ? `${BASE_URL}/${integrator_id}/${service_slug}/${user_hash}?gen=${token}`
        : `${BASE_URL}/f/${token}`;
      return json(res, 200, {
        token,
        url: url_out,
        expires_at: new Date(expires).toISOString(),
      });
    }

    // ── GET /api/session/:token/status ─────────────────────────────────────────
    const statusMatch = url.pathname.match(/^\/api\/session\/([a-f0-9]{32})\/status$/);
    if (statusMatch && req.method === 'GET') {
      const { isAdmin, integrator } = resolveAuth(req.headers['authorization']);
      if (ADMIN_TOKEN && !isAdmin && !integrator) return json(res, 401, { error: 'unauthorized' });
      const token = statusMatch[1];
      const pendingFile = path.join(CONNECT_PENDING_DIR, `${token}.json`);
      const doneFile = path.join(CONNECT_PENDING_DIR, `${token}.done`);

      if (fs.existsSync(doneFile)) {
        let doneData = {};
        try { doneData = JSON.parse(fs.readFileSync(doneFile, 'utf8')); } catch {}
        return json(res, 200, { status: 'done', ...doneData });
      }
      if (!fs.existsSync(pendingFile)) return json(res, 200, { status: 'expired' });
      try {
        const p = JSON.parse(fs.readFileSync(pendingFile, 'utf8'));
        if (p.expires < Date.now()) return json(res, 200, { status: 'expired' });
      } catch {}
      return json(res, 200, { status: 'pending' });
    }

    // ── GET /api/destinations ──────────────────────────────────────────────────
    if (url.pathname === '/api/destinations' && req.method === 'GET') {
      const { isAdmin, integrator } = resolveAuth(req.headers['authorization']);
      if (!isAdmin && !integrator) return json(res, 401, { error: 'unauthorized' });
      // Build destinations map: only expose type (no credentials)
      const adminDests = {};
      for (const [name, dest] of Object.entries(NAMED_DESTINATIONS)) {
        adminDests[name] = { type: dest.type };
      }
      if (isAdmin) {
        return json(res, 200, { destinations: adminDests });
      }
      // Integrator: merge admin destinations with integrator's own (integrator overrides)
      const merged = { ...adminDests };
      for (const [name, dest] of Object.entries(integrator.destinations || {})) {
        merged[name] = { type: dest.type };
      }
      return json(res, 200, { destinations: merged });
    }

    // ── /f/:token — dynamic form ───────────────────────────────────────────────
    const dynMatch = url.pathname.match(/^\/f\/([a-f0-9]{32})$/);
    if (dynMatch) {
      const token = dynMatch[1];

      if (req.method === 'GET') {
        const pending = readPending(token);
        if (!pending || !pending.fields) {
          res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' }).end(expiredHtml());
          return;
        }
        if (pending.expires < Date.now()) {
          res.writeHead(410, { 'Content-Type': 'text/html; charset=utf-8' }).end(expiredHtml());
          return;
        }
        const { uid } = getOrCreateUid(req);
        const savedValues = readSaved(uid);
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Set-Cookie': cookieSetHeader(uid, req),
        }).end(dynamicFormHtml(token, pending, savedValues));
        return;
      }

      if (req.method === 'POST') {
        const body = await readBody(req);
        let payload;
        try { payload = JSON.parse(body); } catch { return json(res, 400, { error: 'bad json' }); }
        const { t, fields: submitted, save } = payload;
        if (!t || !submitted || typeof submitted !== 'object') return json(res, 400, { error: 'missing t or fields' });
        if (t !== token) return json(res, 400, { error: 'token mismatch' });

        const pending = readPending(token);
        if (!pending || !pending.fields) return json(res, 403, { error: 'invalid or expired token' });
        if (pending.expires < Date.now()) { deletePending(token); return json(res, 403, { error: 'link expired' }); }

        // Validate all required fields are present
        for (const f of pending.fields) {
          if (f.required !== false && !submitted[f.name]) {
            return json(res, 400, { error: `missing required field: ${f.name}` });
          }
        }

        // Only keep declared field names — strip anything extra
        const clean = {};
        for (const f of pending.fields) {
          if (submitted[f.name] !== undefined) clean[f.name] = String(submitted[f.name]);
        }

        // Validate url fields
        for (const f of pending.fields) {
          if (f.type === 'url' && clean[f.name]) {
            try {
              const u = new URL(clean[f.name]);
              if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
            } catch { return json(res, 400, { error: `invalid URL for field: ${f.name}` }); }
          }
        }

        let saveResult;
        try {
          if (pending.destinations_by_level) {
            // Group fields by level, route each group to its destination
            const groups = {};
            for (const f of pending.fields) {
              const level = f.level || 'default';
              if (!groups[level]) groups[level] = {};
              if (clean[f.name] !== undefined) groups[level][f.name] = clean[f.name];
            }
            const secretIds = {};
            for (const [level, groupFields] of Object.entries(groups)) {
              if (Object.keys(groupFields).length === 0) continue;
              const dest = pending.destinations_by_level[level]
                || pending.destinations_by_level['default']
                || pending.destination;
              if (!dest) {
                console.warn(`[dynamic] no destination for level "${level}", skipping:`, Object.keys(groupFields));
                continue;
              }
              const r = await saveToDestination(dest, groupFields, { tokensDir: AGENT_TOKENS_DIR, context: { uid: pending.uid, service: pending.service_slug } });
              if (r?.secret_id) secretIds[level] = r.secret_id;
            }
            saveResult = { secret_ids: secretIds };
          } else {
            saveResult = await saveToDestination(pending.destination, clean, { tokensDir: AGENT_TOKENS_DIR, context: { uid: pending.uid, service: pending.service_slug } });
          }
        } catch (e) {
          console.error('[dynamic] save failed:', e.message);
          return json(res, 500, { error: 'failed to save credentials', detail: e.message.slice(0, 200) });
        }

        deletePending(token);
        // .done file stores destination references — never the credentials themselves
        try {
          fs.writeFileSync(
            path.join(CONNECT_PENDING_DIR, `${token}.done`),
            JSON.stringify(saveResult || {}),
            { mode: 0o600 },
          );
        } catch {}

        const { uid, hadCookie } = getOrCreateUid(req);
        const primarySecretId = saveResult?.secret_id
          || (saveResult?.secret_ids ? Object.values(saveResult.secret_ids)[0] : undefined);
        if (save && pending.allowSave && primarySecretId) {
          writeSavedRef(uid, pending, primarySecretId);
        } else if (save && pending.allowSave) {
          writeSaved(uid, clean, pending.fields);
        }

        const respHeaders = (save || hadCookie) ? { 'Set-Cookie': cookieSetHeader(uid, req) } : {};
        json(res, 200, { ok: true }, respHeaders);

        if (pending.notify?.tg_bot_token) {
          tgNotify(pending.notify.tg_bot_token, pending.notify.tg_chat_id,
            `✅ ${pending.title}: credentials received and saved.`);
        }
        return;
      }

      res.writeHead(405).end(); return;
    }

    // ── /{integrator_slug}/{service_slug}/{user_hash} — pretty deterministic URL ──
    // Only GET is needed here; form submissions always go to POST /f/{token}.
    const prettyMatch = url.pathname.match(/^\/([a-zA-Z0-9_-]{1,64})\/([a-zA-Z0-9_-]{1,64})\/([a-f0-9]{10})$/);
    if (prettyMatch && req.method === 'GET') {
      const [, slug, svc, hash] = prettyMatch;
      const gen = url.searchParams.get('gen');

      let pending;
      if (gen && /^[a-f0-9]{32}$/.test(gen)) {
        pending = readPending(gen);
        if (!pending || pending.integrator_slug !== slug || pending.service_slug !== svc || pending.user_hash !== hash) {
          res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' }).end(expiredHtml());
          return;
        }
      } else {
        pending = findActiveSession(slug, svc, hash);
        if (pending) {
          res.writeHead(302, { Location: `${BASE_URL}/${slug}/${svc}/${hash}?gen=${pending.token}` }).end();
          return;
        }
      }

      if (!pending || !pending.fields) {
        res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' }).end(expiredHtml());
        return;
      }
      if (pending.expires < Date.now()) {
        res.writeHead(410, { 'Content-Type': 'text/html; charset=utf-8' }).end(expiredHtml());
        return;
      }

      const { uid: cookieUid } = getOrCreateUid(req);
      const savedValues = readSaved(cookieUid);
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Set-Cookie': cookieSetHeader(cookieUid, req),
      }).end(dynamicFormHtml(pending.token, pending, savedValues));
      return;
    }

    json(res, 404, { error: 'not found' });
  });

  return server;
}

// ── Entry point ───────────────────────────────────────────────────────────────

if (require.main === module) {
  const PORT = process.env.PORT || 3456;
  const server = createApp();
  server.listen(PORT, () => {
    const addr = server.address();
    console.log(`zerocreds-server v${VERSION} (${COMMIT}) listening on :${addr.port}`);
  });
  const shutdown = () => {
    server.close(() => process.exit(0));
    try { require('./nalog-login').closeAll(); } catch {}
    setTimeout(() => process.exit(0), 10_000).unref();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

module.exports = { createApp };
