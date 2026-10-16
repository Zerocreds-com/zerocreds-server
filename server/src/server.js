'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const { verifyLocalCredential } = require('./local-verification');
const path = require('path');
const crypto = require('crypto');
const { startNalogLogin, confirmNalogCode } = require('./nalog-login');
const { saveToDestination, testDestination, validateDestination, resolveTemplate } = require('./destinations');
const { canonicalJson, sha256Hex, loadSigningKey, signPayload } = require('./receipts');

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

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function readBody(req, maxBytes = 1_048_576) {
  return new Promise((resolve, reject) => {
    if (Number(req.headers['content-length']) > maxBytes) return reject(new HttpError(413, 'body too large'));
    const chunks = [];
    let total = 0;
    let done = false;
    req.on('data', c => {
      if (done) return;
      total += c.length;
      if (total > maxBytes) { done = true; return reject(new HttpError(413, 'body too large')); }
      chunks.push(c);
    });
    req.on('end', () => { if (!done) { done = true; resolve(Buffer.concat(chunks).toString()); } });
    req.on('error', e => { if (!done) { done = true; reject(e); } });
  });
}

// Reads a JSON object body. Returns null for invalid JSON or a non-object top level.
async function readJson(req) {
  const body = await readBody(req);
  try {
    const v = JSON.parse(body);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch { return null; }
}

const BASE_SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

function json(res, status, data, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...BASE_SECURITY_HEADERS, ...extraHeaders });
  res.end(JSON.stringify(data));
}

// Every HTML page gets a strict CSP: scripts only with the per-response nonce,
// network only back to this origin, and no framing.
function sendHtml(res, status, body, nonce) {
  const scriptSrc = nonce ? `'nonce-${nonce}'` : `'none'`;
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    ...BASE_SECURITY_HEADERS,
    'Content-Security-Policy': `default-src 'none'; script-src ${scriptSrc}; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
    'X-Frame-Options': 'DENY',
  }).end(body);
}

function newNonce() {
  return crypto.randomBytes(16).toString('base64');
}

function escHtml(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Serialises a value for embedding inside an inline <script>.
function jsValue(v) {
  return JSON.stringify(v).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

const TOKEN_RE = /^[a-f0-9]{32}$/;
const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
// Names used as object keys (field names, destination names) — no prototype keys.
function isSafeKey(k, max = 64) {
  return typeof k === 'string' && new RegExp(`^[a-zA-Z0-9_-]{1,${max}}$`).test(k) && !RESERVED_KEYS.has(k);
}

function isLoopback(addr) {
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}

// Client IP for rate limiting: X-Real-IP is only trusted from the local reverse
// proxy (nginx overwrites it); X-Forwarded-For is client-controlled and ignored.
function clientIp(req) {
  const remote = req.socket.remoteAddress || '';
  const realIp = req.headers['x-real-ip'];
  if (isLoopback(remote) && typeof realIp === 'string' && realIp) return realIp.trim();
  return remote;
}

// ── HTML templates (pure) ─────────────────────────────────────────────────────

function nalogFormHtml(token, nonce) {
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
    <button id="btn1" type="button">Войти через Госуслуги</button>
    <div id="msg1" class="msg"></div>
  </div>
  <div id="step2">
    <h1>Код подтверждения</h1>
    <p class="sub">На ваш телефон или в приложение Госуслуги отправлен код. Введите его ниже.</p>
    <label for="code">Код из SMS / приложения</label>
    <input id="code" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" maxlength="8">
    <button id="btn2" type="button">Подтвердить</button>
    <div id="msg2" class="msg"></div>
  </div>
  <div id="step3">
    <div class="check-icon">✓</div>
    <h1>Налог.ру подключён</h1>
    <p class="sub" id="expiresText">Данные авторизации сохранены. Можете закрыть эту страницу и вернуться в бот.</p>
  </div>
  <p class="lock">Данные не попадают в LLM &middot; Ссылка одноразовая &middot; <a href="/version">v${VERSION}</a></p>
</div>
<script nonce="${nonce}">
const T = ${jsValue(token)};
let sessionId = '';
function show(stepId) {
  ['step1','step2','step3'].forEach(id => document.getElementById(id).style.display = id === stepId ? 'block' : 'none');
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
document.getElementById('btn1').addEventListener('click', submitCreds);
document.getElementById('btn2').addEventListener('click', submitCode);
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
  secret:     { tag: 'SECRET',   label: 'Secret',             aiSees: 'Not via ZeroCreds', logs: 'Never logged', desc: 'Treated as a secret. See "Sent to" above for exactly who receives it.' },
  pii:        { tag: 'PII DATA', label: 'Personal data',      aiSees: 'For tasks only', logs: 'Anonymised',   desc: 'The AI can use this for tasks. Not stored in logs in plain form.' },
  attribute:  { tag: 'CONFIG',   label: 'Configuration',      aiSees: 'Openly',         logs: 'Yes',          desc: 'Open configuration. The AI uses this in every request.' },
  credential: { tag: 'SESSION',  label: 'Session credential', aiSees: 'Not via ZeroCreds', logs: 'Never logged', desc: 'Used only in the current session. Not saved to logs.' },
};

// Design tokens for the dynamic form (/f/:token). Light is the default; dark applies via
// prefers-color-scheme or an explicit data-theme="dark" on <html> (user toggle, persisted).
const FORM_THEME_LIGHT = [
  'color-scheme:light',
  '--bg:#eef2f9', '--glow:radial-gradient(1100px 520px at 50% -12%,rgba(99,102,241,.20),transparent 62%)',
  '--card:#ffffff', '--border:#dde3ee', '--shadow:0 1px 2px rgba(16,24,40,.05),0 18px 40px -12px rgba(30,41,90,.18)',
  '--text:#141b2d', '--muted:#4f5a70', '--faint:#626c82', '--link:#4338ca',
  '--input-bg:#f7f9fc', '--input-border:#c9d2e1', '--placeholder:#8d97aa',
  '--chip-bg:#eef1f7', '--chip-hover:#e2e7f0',
  '--accent:#4f46e5', '--accent-2:#0ea5e9', '--accent-hover:#4338ca', '--accent-text:#ffffff',
  '--ring:rgba(79,70,229,.28)', '--ring-strong:rgba(79,70,229,.6)', '--sticky-shadow:rgba(30,41,90,.25)',
  '--ok:#067647', '--ok-bg:#ecfdf3', '--ok-border:#abefc6',
  '--err:#b42318', '--err-bg:#fef3f2', '--err-border:#fecdca',
  '--secret-fg:#b42318', '--secret-bg:#fef3f2', '--secret-border:#fda29b',
  '--pii-fg:#a15c07', '--pii-bg:#fffaeb', '--pii-border:#fec84b',
  '--attr-fg:#175cd3', '--attr-bg:#eff8ff', '--attr-border:#84caff',
  '--cred-fg:#6941c6', '--cred-bg:#f9f5ff', '--cred-border:#d6bbfb',
  '--show-sun:none', '--show-moon:block',
].join(';');
const FORM_THEME_DARK = [
  'color-scheme:dark',
  '--bg:#0a0d16', '--glow:radial-gradient(1100px 520px at 50% -12%,rgba(129,140,248,.16),transparent 62%)',
  '--card:#131826', '--border:#262e42', '--shadow:0 1px 2px rgba(0,0,0,.4),0 18px 40px -12px rgba(0,0,0,.6)',
  '--text:#e9edf5', '--muted:#a6afc2', '--faint:#8d96ab', '--link:#a5b4fc',
  '--input-bg:#0e1320', '--input-border:#313a52', '--placeholder:#5f6880',
  '--chip-bg:#1c2233', '--chip-hover:#252c40',
  '--accent:#818cf8', '--accent-2:#22d3ee', '--accent-hover:#a5b4fc', '--accent-text:#0a0d16',
  '--ring:rgba(129,140,248,.30)', '--ring-strong:rgba(165,180,252,.7)', '--sticky-shadow:rgba(0,0,0,.6)',
  '--ok:#75e0a7', '--ok-bg:#0b2419', '--ok-border:#17553a',
  '--err:#fda29b', '--err-bg:#2a1215', '--err-border:#6a2424',
  '--secret-fg:#fda29b', '--secret-bg:#2a1215', '--secret-border:#6a2424',
  '--pii-fg:#fec84b', '--pii-bg:#261c08', '--pii-border:#5c4412',
  '--attr-fg:#84caff', '--attr-bg:#0c1c31', '--attr-border:#1f4470',
  '--cred-fg:#d6bbfb', '--cred-bg:#1d1431', '--cred-border:#47307a',
  '--show-sun:block', '--show-moon:none',
].join(';');

const FIELD_TYPES = ['text', 'password', 'email', 'number', 'tel', 'textarea', 'url'];

// Form specs (POST /api/forms): the credential kind picks the default fields.
const FORM_KINDS = {
  token: [{ name: 'token', label: 'Token', type: 'password' }],
  ssh: [{ name: 'private_key', label: 'SSH private key', type: 'textarea' }],
  login: [{ name: 'username', label: 'Username' }, { name: 'password', label: 'Password', type: 'password' }],
};
// The handle is not a secret: cred:<name> in the owner's space.
const HANDLE_NAME_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const SUBMIT_TOKEN_RE = /^zcs_[a-f0-9]{48}$/;

// Values for {{placeholders}} in destination configs.
function templateContext(pending) {
  return { uid: pending.uid, service: pending.service_slug ?? pending.form?.name, name: pending.form?.name };
}

function envVarName(formName, fieldName) {
  return `${formName}_${fieldName}`.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
}

// "Copy as API request": the machine equivalent of a form, with placeholders instead of
// values. Everything interpolated here is validated (hex ids, [a-z0-9_.-] names).
function formApiSnippets(formId, pending, baseUrl) {
  const { form, fields } = pending;
  const args = fields.map(f => `--arg ${f.name} "$${envVarName(form.name, f.name)}"`).join(' ');
  const obj = fields.map(f => `${f.name}: $${f.name}`).join(', ');
  const curl = [
    `curl -sS -X POST '${baseUrl}/api/forms/${formId}/submit' \\`,
    `  -H "Authorization: Bearer $ZEROCREDS_SUBMIT_TOKEN" \\`,
    `  -H 'Content-Type: application/json' \\`,
    `  -d "$(jq -n ${args} '{manifest_id: "${form.manifest_id}", fields: {${obj}}}')"`,
  ].join('\n');
  const sar = fields.length === 1
    ? `sar cred put ${form.name} --kind ${form.kind} --from-env ${envVarName(form.name, fields[0].name)}`
    : `sar cred put ${form.name} --kind ${form.kind} --from-file ./${form.name}.json   # {${fields.map(f => `"${f.name}": "…"`).join(', ')}}`;
  return { curl, sar };
}

// Sessions created by an integrator write local files under their own subtree.
function integratorSubdir(integratorId) {
  return !integratorId || integratorId === 'admin' ? '' : path.join('_integrators', integratorId);
}

function urlHostPath(u) {
  try {
    const x = new URL(String(u));
    return `${x.protocol}//${x.host}${x.pathname === '/' ? '' : x.pathname}`;
  } catch { return String(u || '').slice(0, 200); }
}

const SERVER_READABLE_NOTE = 'Stored on the ZeroCreds server; programs run by the server operator can read it.';
const WRITE_ONLY_NOTE = 'ZeroCreds is only given write access to this store (when configured as documented).';

// Plain-text summary of where values go: { kind, target, note }. Callers escape it.
function describeDestination(dest, pending) {
  if (!dest || typeof dest !== 'object') return { kind: 'Not stored', target: '', note: '' };
  const ctx = templateContext(pending);
  switch (dest.type) {
    case 'local_file': {
      const sub = integratorSubdir(pending.integrator_id);
      const file = path.posix.join('~/agent-tokens', sub.split(path.sep).join('/'),
        String(resolveTemplate(String(dest.uid ?? ''), ctx)), String(resolveTemplate(String(dest.filename ?? ''), ctx)));
      return { kind: 'File on the ZeroCreds server', target: file, note: SERVER_READABLE_NOTE };
    }
    case 'gcp_secret_manager': return { kind: 'Google Cloud Secret Manager', target: String(dest.secret || ''), note: WRITE_ONLY_NOTE };
    case 'aws_secrets_manager': return { kind: 'AWS Secrets Manager', target: `${dest.secret_id || ''} (${dest.region || ''})`, note: WRITE_ONLY_NOTE };
    case 'vault': return { kind: dest.preflight_path_prefix ? 'OpenBao KV v2' : 'Vault-compatible secret store',
      target: `${urlHostPath(dest.address)}/v1/${String(dest.path || '').replace(/^\//, '')}`, note: WRITE_ONLY_NOTE };
    case 'http_post': return { kind: 'Web endpoint of the requester', target: urlHostPath(dest.url), note: 'Whoever runs this endpoint receives the values in readable form.' };
    case 'macos_keychain':
    case 'windows_credential_manager':
    case 'os_keychain': return { kind: 'OS keychain on the ZeroCreds server', target: `${resolveTemplate(String(dest.service || 'zerocreds'), ctx)}/${resolveTemplate(String(dest.account || 'default'), ctx)}`, note: SERVER_READABLE_NOTE };
    default: return { kind: String(dest.type), target: '', note: '' };
  }
}

// Mirrors the routing in POST /f/:token.
function destinationForField(pending, f) {
  const byLevel = pending.destinations_by_level;
  if (byLevel) {
    const lvl = f.level || 'default';
    return (Object.hasOwn(byLevel, lvl) && byLevel[lvl]) || byLevel.default || pending.destination || null;
  }
  return pending.destination || null;
}

function requesterLabel(pending) {
  if (!pending.integrator_id || pending.integrator_id === 'admin') return 'Operator of this ZeroCreds server';
  return pending.requester ? `${pending.requester} (integrator ${pending.integrator_id})` : `Integrator ${pending.integrator_id}`;
}

function dynamicFormHtml(token, pending, host, nonce, api = null) {
  const fields = Array.isArray(pending.fields) ? pending.fields : [];
  const title = pending.title || 'Enter your credentials';
  const description = pending.description || 'Values go directly from this page to ZeroCreds, not through the AI chat.';

  function levelBadge(f) {
    const lm = LEVEL_META[f.level];
    if (!lm) return '';
    return `<div class="level-tag"><span class="level-chip lvl-${f.level}">${lm.tag}</span><button type="button" class="level-btn" data-action="toggle-info" data-target="info_${escHtml(f.name)}" aria-controls="info_${escHtml(f.name)}" aria-expanded="false" title="What happens to this data?" aria-label="What happens to this data?">ⓘ</button></div>`;
  }

  function levelInfoCard(f) {
    const lm = LEVEL_META[f.level];
    if (!lm) return '';
    return `<div id="info_${escHtml(f.name)}" class="level-info lvl-${f.level}" hidden>
  <div class="level-info-title">${lm.tag} — ${lm.label}</div>
  <table class="level-table">
    <tr><td>ZeroCreds server</td><td>Receives</td></tr>
    <tr><td>AI assistant</td><td>${lm.aiSees}</td></tr>
    <tr><td>Logs</td><td>${lm.logs}</td></tr>
  </table>
  <div class="level-desc">${lm.desc}</div>
</div>`;
  }

  const fieldHtml = fields.map(f => {
    const type = FIELD_TYPES.includes(f.type) ? f.type : 'text';
    const id = `f_${escHtml(f.name)}`;
    const name = escHtml(f.name);
    const ph = escHtml(f.placeholder || '');
    const req = f.required !== false ? 'required' : '';
    const labelHtml = `<label for="${id}" class="field-label">${escHtml(f.label)}${levelBadge(f)}</label>${levelInfoCard(f)}`;
    if (type === 'textarea') {
      return `${labelHtml}<textarea id="${id}" name="${name}" placeholder="${ph}" ${req} rows="4"></textarea>`;
    }
    if (type === 'password') {
      return `${labelHtml}<div class="pw-wrap"><input id="${id}" name="${name}" type="password" placeholder="${ph}" autocomplete="current-password" spellcheck="false" ${req}><button type="button" class="pw-btn eye" data-action="toggle-pw" data-target="${id}" title="Show/hide" aria-label="Show or hide">👁</button><button type="button" class="pw-btn paste" data-action="paste" data-target="${id}">Paste</button></div>`;
    }
    return `${labelHtml}<input id="${id}" name="${name}" type="${type}" placeholder="${ph}" autocomplete="off" spellcheck="false" ${req}>`;
  }).join('\n  ');

  const isLocal = /^(localhost|127\.0\.0\.1)(:\d+)?$/.test(host);
  const hostBadge = isLocal
    ? `You are on <a href="https://www.google.com/search?q=what+is+localhost" target="_blank" rel="noopener">localhost</a>`
    : escHtml(host || '');

  // Always-visible: who asked, and exactly where each group of fields is sent.
  const destGroups = [];
  for (const f of fields) {
    const d = describeDestination(destinationForField(pending, f), pending);
    const key = `${d.kind}\n${d.target}`;
    let g = destGroups.find(x => x.key === key);
    if (!g) { g = { key, ...d, labels: [] }; destGroups.push(g); }
    g.labels.push(f.label);

  }
  const destRows = destGroups.map(g => {
    const k = destGroups.length > 1 ? `${escHtml(g.labels.join(', '))} →` : 'Sent to';
    return `<div class="dest-row"><span class="dest-k">${k}</span><span class="dest-v">${escHtml(g.kind)}${g.target ? `<code class="dest-target">${escHtml(g.target)}</code>` : ''}${g.note ? `<span class="dest-note">${escHtml(g.note)}</span>` : ''}</span></div>`;
  }).join('');
  const handleRow = pending.form ? `<div class="dest-row"><span class="dest-k">Saved as</span><span class="dest-v"><code class="dest-target">${escHtml(pending.form.handle)}</code></span></div>` : '';
  const destBox = `<div class="dest-box" id="zc-destination">
      <div class="dest-row"><span class="dest-k">Requested by</span><span class="dest-v">${escHtml(requesterLabel(pending))}</span></div>
      ${destRows}
      ${handleRow}
    </div>`;

  const apiHtml = api && !pending.wallet ? `<div class="where-wrap">
  <button type="button" class="where-btn" data-action="toggle-where" data-target="api-info" aria-controls="api-info" aria-expanded="false">Copy as API request ▾</button>
  <div id="api-info" class="where-info" hidden>
    <div class="wb"><div class="wb-note">Same form from a script: values come from env variables, never from this page. Use the owner key or the one-time submit token as <code>ZEROCREDS_SUBMIT_TOKEN</code>.</div></div>
    <div class="wb"><div class="api-head"><span class="wb-fields">curl</span><button type="button" class="copy-btn" data-action="copy" data-target="api-curl">Copy</button></div><pre class="api-code"><code id="api-curl">${escHtml(api.curl)}</code></pre></div>
    <div class="wb-sep"></div>
    <div class="wb"><div class="api-head"><span class="wb-fields">sar CLI</span><button type="button" class="copy-btn" data-action="copy" data-target="api-sar">Copy</button></div><pre class="api-code"><code id="api-sar">${escHtml(api.sar)}</code></pre></div>
  </div>
</div>` : '';

  const LEVEL_BEHAVIOR = {
    secret:     { note: 'Handled as a secret: ZeroCreds does not log submitted values.' },
    pii:        { note: 'Agent receives this for task context. Not stored in conversation logs in plain form.' },
    attribute:  { note: 'Agent uses this openly in every request.' },
    credential: { note: 'Used in the current session only. Not written to persistent logs.' },
  };

  // Group fields by level
  const levelGroups = {};
  for (const f of fields) {
    const lvl = f.level || '_none';
    if (!levelGroups[lvl]) levelGroups[lvl] = [];
    levelGroups[lvl].push(f);
  }

  let whereBlocks = [];
  for (const [lvl, group] of Object.entries(levelGroups)) {
    const lm = LEVEL_META[lvl];
    const behavior = LEVEL_BEHAVIOR[lvl];
    const fieldNames_ = group.map(f => escHtml(f.label)).join(', ');

    let html = `<div class="wb">`;
    if (lm) html += `<div class="wb-head"><span class="wl-chip lvl-${lvl}">${lm.tag}</span><span class="wb-fields">${fieldNames_}</span></div>`;
    else     html += `<div class="wb-head"><span class="wb-fields">${fieldNames_}</span></div>`;
    if (behavior) html += `<div class="wb-note">${behavior.note}</div>`;
    html += `</div>`;
    whereBlocks.push(html);
  }

  const whereHtml = whereBlocks.length ? `<div class="where-wrap">
  <button type="button" class="where-btn" data-action="toggle-where" data-target="where-info" aria-controls="where-info" aria-expanded="false">How is this data handled? ▾</button>
  <div id="where-info" class="where-info" hidden>${whereBlocks.join('<div class="wb-sep"></div>')}</div>
</div>` : '';
  const storageSummary = pending.preflight?.checked && pending.destination?.type === 'vault'
    ? `<div class="storage-summary"><strong>Storage: OpenBao KV v2</strong><br>
       Path: <code>${escHtml(pending.destination.path)}</code><br>
       Storage checked: ${escHtml(pending.preflight.at)}<br>
       Credential version: not created yet.<br>
       ${pending.wallet ? `Wallet owner: <code>${escHtml(pending.wallet.owner_id)}</code><br>
       Profile: <code>${escHtml(pending.wallet.profile_id)}</code><br>
       Connection: <code>${escHtml(pending.wallet.connection_id)}</code><br>
       ZeroCreds operates this wallet; its infrastructure administrators can technically access stored values.`
         : 'Wallet owner and profile: not verified by this form version.'}</div>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<title>${escHtml(title)}</title>
<style>
  :root{${FORM_THEME_LIGHT}}
  @media (prefers-color-scheme:dark){:root:not([data-theme="light"]){${FORM_THEME_DARK}}}
  :root[data-theme="dark"]{${FORM_THEME_DARK}}
  .lvl-secret{--lvl-fg:var(--secret-fg);--lvl-bg:var(--secret-bg);--lvl-border:var(--secret-border)}
  .lvl-pii{--lvl-fg:var(--pii-fg);--lvl-bg:var(--pii-bg);--lvl-border:var(--pii-border)}
  .lvl-attribute{--lvl-fg:var(--attr-fg);--lvl-bg:var(--attr-bg);--lvl-border:var(--attr-border)}
  .lvl-credential{--lvl-fg:var(--cred-fg);--lvl-bg:var(--cred-bg);--lvl-border:var(--cred-border)}
  *{box-sizing:border-box;margin:0;padding:0}
  [hidden]{display:none!important}
  html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
  body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:16px;line-height:1.5;background:var(--glow),var(--bg);background-attachment:fixed;color:var(--text);display:flex;align-items:center;justify-content:center;min-height:100vh;min-height:100dvh;padding:40px 16px}
  a{color:var(--link)}
  .card{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:28px 32px 24px;max-width:480px;width:100%;box-shadow:var(--shadow)}
  .storage-summary{border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin:0 0 18px;color:var(--muted);font-size:13px;overflow-wrap:anywhere}
  .storage-summary strong{color:var(--text)}
  .zc-header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:24px;padding-bottom:18px;border-bottom:1px solid var(--border)}
  .zc-brand{display:flex;align-items:center;gap:10px;min-width:0}
  .zc-dot{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent-2));display:grid;place-items:center;flex-shrink:0;box-shadow:0 2px 8px -2px var(--ring)}
  .zc-dot svg{width:16px;height:16px;color:#fff}
  .zc-wordmark{font-size:16px;font-weight:700;color:var(--text);letter-spacing:-.2px}
  .zc-tools{display:flex;align-items:center;gap:10px;min-width:0}
  .zc-badge{font-size:12px;color:var(--faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
  .zc-badge a{color:var(--faint);text-decoration-color:var(--border)}
  .theme-btn{width:40px;height:40px;flex-shrink:0;border-radius:10px;border:1px solid var(--border);background:var(--input-bg);color:var(--muted);display:grid;place-items:center;cursor:pointer;transition:background .15s,color .15s}
  .theme-btn:hover{color:var(--text);background:var(--chip-bg)}
  .theme-btn svg{width:18px;height:18px}
  .theme-btn .i-sun{display:var(--show-sun)}
  .theme-btn .i-moon{display:var(--show-moon)}
  h1{font-size:22px;line-height:1.3;font-weight:700;color:var(--text);margin-bottom:6px;letter-spacing:-.3px}
  .sub{color:var(--muted);font-size:15px;margin-bottom:24px;line-height:1.55}
  .sub b{color:var(--text)}
  label,.field-label{display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:14px;font-weight:600;color:var(--text);margin-bottom:8px;margin-top:20px}
  #form-view > label:first-of-type{margin-top:0}
  input,textarea{width:100%;min-height:48px;background:var(--input-bg);border:1px solid var(--input-border);border-radius:10px;padding:12px 14px;font-size:16px;font-family:inherit;color:var(--text);outline:none;transition:border-color .15s,box-shadow .15s;resize:vertical}
  input:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--ring)}
  input::placeholder,textarea::placeholder{color:var(--placeholder)}
  .pw-wrap{position:relative}
  .pw-wrap input{padding-right:128px;font-family:ui-monospace,'SF Mono',Monaco,Consolas,monospace;letter-spacing:.02em}
  .pw-btn{position:absolute;top:50%;transform:translateY(-50%);height:36px;min-width:36px;border:1px solid transparent;cursor:pointer;background:none;color:var(--muted);line-height:1;padding:0 8px;border-radius:8px;font-size:15px;font-family:inherit;transition:color .15s,background .15s}
  .pw-btn:hover{color:var(--text);background:var(--chip-bg)}
  .pw-btn.eye{right:74px}
  .pw-btn.paste{right:6px;background:var(--chip-bg);border-color:var(--border);color:var(--text);font-weight:600;font-size:13px;padding:0 12px}
  .pw-btn.paste:hover{background:var(--chip-hover)}
  .sub{white-space:pre-line}
  .dest-box{margin-top:24px;padding:12px 14px;border:1px solid var(--border);border-radius:12px;background:var(--input-bg);font-size:13px;line-height:1.5}
  .dest-row{display:flex;gap:12px;padding:3px 0}
  .dest-k{flex:0 0 32%;color:var(--muted)}
  .dest-v{flex:1;min-width:0;color:var(--text);font-weight:600;overflow-wrap:anywhere}
  .dest-target{display:block;font-family:ui-monospace,'SF Mono',Monaco,Consolas,monospace;font-size:12px;font-weight:400;margin-top:2px}
  .dest-note{display:block;color:var(--muted);font-weight:400;font-size:12px;margin-top:2px}
  .actions{margin-top:24px}
  button#btn{width:100%;min-height:52px;background:var(--accent);color:var(--accent-text);border:none;border-radius:12px;padding:12px;font-size:16px;font-weight:700;font-family:inherit;cursor:pointer;letter-spacing:.01em;box-shadow:0 6px 16px -6px var(--ring);transition:background .15s,transform .05s}
  button#btn:hover{background:var(--accent-hover)}
  button#btn:active{transform:translateY(1px)}
  button#btn:disabled{opacity:.55;cursor:default}
  button:focus-visible,a:focus-visible{outline:3px solid var(--ring-strong);outline-offset:2px}
  .msg{margin-top:12px;padding:10px 14px;border-radius:10px;font-size:14px;border:1px solid;border-left-width:4px}
  .msg.ok{background:var(--ok-bg);color:var(--ok);border-color:var(--ok-border)}
  .msg.err{background:var(--err-bg);color:var(--err);border-color:var(--err-border)}
  #done{text-align:center;padding:12px 0}
  #done .check-icon{width:56px;height:56px;background:var(--ok-bg);border:1px solid var(--ok-border);border-radius:50%;display:grid;place-items:center;margin:0 auto 16px;color:var(--ok);font-size:26px;font-weight:700}
  .lock{font-size:12px;color:var(--faint);margin-top:20px;text-align:center;letter-spacing:.01em}
  .lock a{color:var(--faint)}
  .lock a:hover,.zc-badge a:hover{color:var(--text)}
  #zc-timer{font-variant-numeric:tabular-nums}
  #zc-timer.expired{color:var(--err);font-weight:600}
  .where-wrap{margin-top:16px;padding-top:12px;border-top:1px solid var(--border)}
  .where-btn{background:none;border:none;cursor:pointer;font-size:13px;font-family:inherit;color:var(--muted);padding:10px 8px;text-decoration:underline;text-underline-offset:3px;text-decoration-color:var(--border);display:block;margin:0 auto;border-radius:8px}
  .where-btn:hover{color:var(--text)}
  .where-info{margin-top:8px;padding:4px 14px;font-size:13px;background:var(--input-bg);border:1px solid var(--border);border-radius:12px}
  .wb{padding:10px 0}
  .wb-sep{border-top:1px solid var(--border)}
  .wb-head{display:flex;align-items:center;gap:8px;margin-bottom:4px}
  .wb-fields{font-size:14px;font-weight:600;color:var(--text)}
  .wb-dest{font-family:ui-monospace,'SF Mono',Monaco,Consolas,monospace;font-size:12px;color:var(--muted);margin-bottom:4px;overflow-wrap:anywhere}
  .wb-note{font-size:13px;color:var(--muted);line-height:1.5}
  .level-tag{display:flex;align-items:center;gap:4px;flex-shrink:0}
  .level-chip,.wl-chip{font-size:10px;font-weight:700;letter-spacing:.08em;padding:3px 7px;border-radius:6px;text-transform:uppercase;white-space:nowrap;flex-shrink:0;color:var(--lvl-fg);background:var(--lvl-bg);border:1px solid var(--lvl-border)}
  .level-btn{background:none;border:none;cursor:pointer;width:32px;height:32px;border-radius:8px;font-size:15px;line-height:1;color:var(--faint);transition:color .15s,background .15s}
  .level-btn:hover{color:var(--text);background:var(--chip-bg)}
  .level-info{margin-top:-2px;margin-bottom:10px;padding:12px 14px;border-radius:10px;font-size:13px;line-height:1.5;background:var(--lvl-bg);border:1px solid var(--lvl-border);border-left-width:4px}
  .level-info-title{font-weight:700;margin-bottom:8px;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--lvl-fg)}
  .level-table{border-collapse:collapse;width:100%;margin-bottom:8px}
  .level-table td{padding:3px 0;font-size:13px}
  .level-table td:first-child{color:var(--muted);width:55%}
  .level-table td:last-child{font-weight:600;color:var(--text)}
  .level-desc{color:var(--muted);font-size:13px;line-height:1.5}
  .api-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px}
  .copy-btn{min-height:36px;padding:0 12px;border-radius:8px;border:1px solid var(--border);background:var(--chip-bg);color:var(--text);font-size:13px;font-weight:600;font-family:inherit;cursor:pointer}
  .copy-btn:hover{background:var(--chip-hover)}
  .api-code{margin:0;padding:10px 12px;border-radius:8px;border:1px solid var(--border);background:var(--card);font-family:ui-monospace,'SF Mono',Monaco,Consolas,monospace;font-size:12px;line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere}
  @media (max-width:560px){
    body{padding:0;align-items:stretch}
    .card{max-width:none;min-height:100vh;min-height:100dvh;border:none;border-radius:0;box-shadow:none;padding:16px 16px 24px}
    .zc-header{margin-bottom:20px;padding-bottom:14px}
    input,textarea{min-height:52px}
    .pw-btn{height:40px;min-width:40px}
    .pw-btn.eye{right:78px}
    .actions{position:sticky;bottom:0;z-index:5;margin:20px -16px 0;padding:12px 16px calc(12px + env(safe-area-inset-bottom));background:var(--card);border-top:1px solid var(--border);box-shadow:0 -8px 24px -12px var(--sticky-shadow)}
    .level-btn{width:40px;height:40px}
  }
</style>
<script nonce="${nonce}">
(function(){try{var t=localStorage.getItem('zc-theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);}catch(e){}})();
const T = ${jsValue(token)};
const FIELD_NAMES = ${jsValue(fields.map(f => f.name))};
const EXPIRES = ${Number(pending.expires) || 0};
function currentTheme() {
  const t = document.documentElement.getAttribute('data-theme');
  if (t) return t;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function syncThemeBtn() {
  const b = document.getElementById('theme-btn');
  if (!b) return;
  const dark = currentTheme() === 'dark';
  const label = dark ? 'Switch to light theme' : 'Switch to dark theme';
  b.setAttribute('aria-pressed', String(dark));
  b.setAttribute('aria-label', label);
  b.title = label;
}
function toggleTheme() {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('zc-theme', next); } catch {}
  syncThemeBtn();
}
function togglePw(id) {
  const el = document.getElementById(id);
  if (el) el.type = el.type === 'password' ? 'text' : 'password';
}
function toggleHidden(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  el.hidden = !el.hidden;
  btn.setAttribute('aria-expanded', String(!el.hidden));
}
async function pastePw(id) {
  try {
    const text = await navigator.clipboard.readText();
    document.getElementById(id).value = text.trim();
  } catch {
    showMsg('err', 'Allow clipboard access or paste manually (Ctrl+V / ⌘V)');
  }
}
async function copyText(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  try {
    await navigator.clipboard.writeText(el.textContent);
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  } catch {
    showMsg('err', 'Allow clipboard access or select the text and copy it manually');
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
    const r = await fetch('/f/' + T, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ t: T, fields }),
    });
    const d = await r.json();
    if (d.ok) {
      document.getElementById('form-view').hidden = true;
      document.getElementById('done').hidden = false;
    } else {
      showMsg('err', d.error || 'Server error');
      btn.disabled = false; btn.textContent = 'Submit';
    }
  } catch(e) {
    showMsg('err', 'Network error: ' + e.message);
    btn.disabled = false; btn.textContent = 'Submit';
  }
}
function showMsg(cls, text) {
  const el = document.getElementById('msg');
  el.className = 'msg ' + cls; el.textContent = text; el.hidden = false;
}
document.addEventListener('click', e => {
  const b = e.target.closest && e.target.closest('[data-action]');
  if (!b) return;
  const target = b.getAttribute('data-target');
  switch (b.getAttribute('data-action')) {
    case 'theme': toggleTheme(); break;
    case 'toggle-pw': togglePw(target); break;
    case 'paste': pastePw(target); break;
    case 'toggle-info':
    case 'toggle-where': toggleHidden(target, b); break;
    case 'copy': copyText(target, b); break;
    case 'submit': submit(); break;
  }
});
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target.tagName === 'INPUT') submit();
});
document.addEventListener('DOMContentLoaded', () => {
  syncThemeBtn();
  const el = document.getElementById('zc-timer');
  if (!el) return;
  function tick() {
    const left = Math.max(0, EXPIRES - Date.now());
    const m = Math.floor(left / 60000);
    const s = Math.floor((left % 60000) / 1000);
    el.textContent = m + ':' + String(s).padStart(2, '0') + ' remaining';
    if (left > 0) setTimeout(tick, 1000);
    else { el.textContent = 'link expired'; el.classList.add('expired'); }
  }
  tick();
});
</script>
</head>
<body>
<main class="card">
  <div class="zc-header">
    <div class="zc-brand">
      <div class="zc-dot" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg></div>
      <span class="zc-wordmark">ZeroCreds</span>
    </div>
    <div class="zc-tools">
      <span class="zc-badge">${hostBadge}</span>
      <button type="button" id="theme-btn" class="theme-btn" data-action="theme" aria-label="Toggle color theme" title="Toggle color theme">
        <svg class="i-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
        <svg class="i-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
      </button>
    </div>
  </div>
  <div id="form-view">
    <h1>${escHtml(title)}</h1>
    <p class="sub">${escHtml(description)}</p>
    ${storageSummary}

    ${fieldHtml}
    ${destBox}
    <div class="actions">
      <button id="btn" type="button" data-action="submit">Submit</button>
      <div id="msg" class="msg" role="alert" hidden></div>
    </div>
  </div>
  <div id="done" hidden>
    <div class="check-icon" aria-hidden="true">✓</div>
    <h1>Done</h1>
    <p class="sub">Credentials saved. You can close this page.</p>
  </div>
  <p class="lock"><span id="zc-timer"></span> &middot; One-time link &middot; <a href="https://github.com/Zerocreds-com/zerocreds-server" target="_blank" rel="noopener">v${VERSION}</a></p>
  ${apiHtml}
  ${whereHtml}
</main>
</body>
</html>`;
}

function connectFormHtml(service, meta, token, nonce) {
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
  <button id="btn" type="button">Connect</button>
  <div id="msg" class="msg"></div>
  <p class="lock">Credentials never reach the AI &middot; One-time link &middot; <a href="/version">v${VERSION}</a></p>
</div>
<script nonce="${nonce}">
const T = ${jsValue(token)};
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
document.getElementById('btn').addEventListener('click', submit);
document.getElementById('tok').addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
</script>
</body>
</html>`;
}

// ── App factory ───────────────────────────────────────────────────────────────

function envFlag(name) {
  return /^(1|true|yes)$/i.test(process.env[name] || '');
}

function envList(name) {
  return (process.env[name] || '').split(',').map(s => s.trim()).filter(Boolean);
}

const FIELD_NAME_RE = /^[a-zA-Z0-9_]{1,64}$/;
const FIELD_LEVELS = ['secret', 'pii', 'attribute', 'credential'];
const MAX_FIELDS = 50;

// Validates and normalises the fields array of a session. Returns { fields } or { error }.
function validateFields(fields) {
  if (!Array.isArray(fields) || fields.length === 0) return { error: 'missing title or fields' };
  if (fields.length > MAX_FIELDS) return { error: `too many fields (max ${MAX_FIELDS})` };
  const out = [];
  const seen = new Set();
  for (const f of fields) {
    if (!f || typeof f !== 'object' || Array.isArray(f)) return { error: 'each field must be an object' };
    if (typeof f.name !== 'string' || typeof f.label !== 'string' || !f.name || !f.label) {
      return { error: 'field missing name or label' };
    }
    if (!FIELD_NAME_RE.test(f.name) || RESERVED_KEYS.has(f.name)) return { error: `invalid field name: ${f.name.slice(0, 64)}` };
    if (seen.has(f.name)) return { error: `duplicate field name: ${f.name}` };
    seen.add(f.name);
    if (f.label.length > 200) return { error: `field label too long: ${f.name}` };
    if (f.type !== undefined && !FIELD_TYPES.includes(f.type)) return { error: `invalid field type: ${String(f.type).slice(0, 32)}` };
    if (f.level !== undefined && !FIELD_LEVELS.includes(f.level)) return { error: `invalid field level: ${String(f.level).slice(0, 32)}` };
    if (f.placeholder !== undefined && (typeof f.placeholder !== 'string' || f.placeholder.length > 200)) {
      return { error: `invalid placeholder for field: ${f.name}` };
    }
    if (f.required !== undefined && typeof f.required !== 'boolean') return { error: `required must be a boolean: ${f.name}` };
    const clean = { name: f.name, label: f.label };
    if (f.type !== undefined) clean.type = f.type;
    if (f.level !== undefined) clean.level = f.level;
    if (f.placeholder !== undefined) clean.placeholder = f.placeholder;
    if (f.required !== undefined) clean.required = f.required;
    out.push(clean);
  }
  return { fields: out };
}

// Destination types that act on the ZeroCreds host itself.
const SERVER_LOCAL_TYPES = new Set(['local_file', 'macos_keychain', 'windows_credential_manager', 'os_keychain']);

function readAdminTokenFile(file) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid())) {
      throw new Error('admin token file must be a private regular file owned by the service user');
    }
    if (stat.size > 256) throw new Error('admin token file is too large');
    const token = fs.readFileSync(fd, 'utf8').trim();
    if (token.length < 32 || /\s/.test(token)) throw new Error('admin token file must contain one token of at least 32 characters');
    return token;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function createApp(config = {}) {
  const LOCAL_MODE = config.localMode ?? envFlag('ZEROCREDS_LOCAL_MODE');
  let ADMIN_TOKEN = config.adminToken ?? process.env.ZEROCREDS_ADMIN_TOKEN ?? '';
  const ADMIN_TOKEN_FILE = config.adminTokenFile ?? process.env.ZEROCREDS_ADMIN_TOKEN_FILE ?? path.join(os.homedir(), '.config/zerocreds/admin-token');
  if (!ADMIN_TOKEN) {
    try { ADMIN_TOKEN = readAdminTokenFile(ADMIN_TOKEN_FILE); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  if (typeof ADMIN_TOKEN !== 'string' || !ADMIN_TOKEN) {
    throw new Error('ZEROCREDS_ADMIN_TOKEN or a private admin token file is required — refusing to start without an admin token');
  }
  const CONNECT_PENDING_DIR = config.pendingDir ?? process.env.ZEROCREDS_PENDING_DIR ?? path.join(os.homedir(), 'connect-pending');
  const AGENT_TOKENS_DIR = config.tokensDir ?? process.env.ZEROCREDS_TOKENS_DIR ?? path.join(os.homedir(), 'agent-tokens');
  const LOCAL_CATALOG_FILE = config.localCatalogFile ?? process.env.ZEROCREDS_LOCAL_CATALOG_FILE ?? path.join(os.homedir(), '.config/zerocreds/local/connections.json');
  const DESTINATIONS_FILE = config.destinationsFile ?? process.env.ZEROCREDS_DESTINATIONS_FILE ?? path.join(os.homedir(), 'zerocreds-destinations.json');
  const INTEGRATORS_FILE = config.integratorsFile ?? process.env.ZEROCREDS_INTEGRATORS_FILE ?? path.join(os.homedir(), 'zerocreds-integrators.json');
  const BASE_URL = config.baseUrl ?? process.env.ZEROCREDS_BASE_URL ?? (LOCAL_MODE ? 'http://127.0.0.1:3456' : 'https://zerocreds.ru');
  const LOCAL_ORIGIN = new URL(BASE_URL).origin;
  if (LOCAL_MODE && (!['127.0.0.1', 'localhost', '[::1]'].includes(new URL(BASE_URL).hostname)
      || new URL(BASE_URL).protocol !== 'http:')) {
    throw new Error('local mode requires an http loopback base URL');
  }
  const SIGNING_KEY_FILE = config.signingKeyFile ?? process.env.ZEROCREDS_SIGNING_KEY_FILE ?? path.join(os.homedir(), 'zerocreds-signing-key.pem');
  const WALLET_WORKER_URL = config.walletWorkerUrl ?? process.env.ZEROCREDS_WALLET_WORKER_URL ?? '';
  const WALLET_SERVICE_TOKEN = config.walletServiceToken ?? process.env.ZEROCREDS_WALLET_SERVICE_TOKEN ?? '';
  const WALLET_CLIENTS_FILE = config.walletClientsFile ?? process.env.ZEROCREDS_WALLET_CLIENTS_FILE ?? '';
  const WALLET_ASSERTION_ISSUERS_FILE = config.walletAssertionIssuersFile ?? process.env.ZEROCREDS_WALLET_ASSERTION_ISSUERS_FILE ?? '';
  // Unsafe-by-design conveniences for local/dev setups — all off unless explicitly enabled.
  const ALLOW_INLINE_DESTINATIONS = config.allowInlineDestinations ?? envFlag('ZEROCREDS_ALLOW_INLINE_DESTINATIONS');
  const DEST_OPTS = {
    allowPrivate: config.allowPrivateDestinations ?? envFlag('ZEROCREDS_ALLOW_PRIVATE_DESTINATIONS'),
    httpPostAllowedHosts: config.httpPostAllowedHosts ?? envList('ZEROCREDS_HTTP_POST_ALLOWED_HOSTS'),
  };
  const DONE_TTL_MS = 24 * 60 * 60 * 1000;
  const CLAIM_STALE_MS = 60 * 60 * 1000;
  const SWEEP_INTERVAL_MS = 10 * 60 * 1000;

  for (const dir of [CONNECT_PENDING_DIR, AGENT_TOKENS_DIR]) {
    try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch {}
  }

  // Named destinations (admin-configured, SA keys never travel in API requests)
  let NAMED_DESTINATIONS = Object.create(null);
  function loadNamedDestinations() {
    try {
      const raw = JSON.parse(fs.readFileSync(DESTINATIONS_FILE, 'utf8'));
      if (raw && typeof raw === 'object' && !Array.isArray(raw)) NAMED_DESTINATIONS = Object.assign(Object.create(null), raw);
      console.log(`[config] loaded ${Object.keys(NAMED_DESTINATIONS).length} named destination(s)`);
    } catch (e) {
      if (e.code !== 'ENOENT') console.warn('[config] destinations file error:', e.message);
    }
  }
  loadNamedDestinations();

  function readLocalCatalog() {
    try {
      const raw = JSON.parse(fs.readFileSync(LOCAL_CATALOG_FILE, 'utf8'));
      return Array.isArray(raw) ? raw.filter((item) => item && typeof item === 'object') : [];
    } catch (error) {
      if (error.code === 'ENOENT') return [];
      throw error;
    }
  }

  function writeLocalCatalog(entries) {
    fs.mkdirSync(path.dirname(LOCAL_CATALOG_FILE), { recursive: true, mode: 0o700 });
    const temp = `${LOCAL_CATALOG_FILE}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    fs.writeFileSync(temp, JSON.stringify(entries, null, 2), { mode: 0o600, flag: 'wx' });
    fs.renameSync(temp, LOCAL_CATALOG_FILE);
  }

  function checkLocalKeychainEntry(storage) {
    if (typeof storage !== 'string') return Promise.resolve('unavailable');
    const match = storage.match(/^keychain:([a-zA-Z0-9_@.-]{1,128})\/([a-zA-Z0-9_@.-]{1,128})$/);
    if (!match || process.platform !== 'darwin') return Promise.resolve('unavailable');
    const { spawn } = require('child_process');
    const helper = process.env.ZEROCREDS_KEYCHAIN_HELPER || path.join(__dirname, '../bin/zerocreds-keychain');
    return new Promise((resolve) => {
      let settled = false;
      const finish = (status) => { if (!settled) { settled = true; clearTimeout(timer); resolve(status); } };
      const child = spawn(helper, ['exists', match[1], match[2]], { stdio: ['ignore', 'ignore', 'ignore'] });
      const timer = setTimeout(() => { child.kill('SIGKILL'); finish('unavailable'); }, 5000);
      child.once('error', () => finish('unavailable'));
      child.once('close', (code) => finish(code === 0 ? 'present' : code === 3 ? 'missing' : code === 4 ? 'locked' : 'unavailable'));
    });
  }

  function readLocalKeychainEntry(storage) {
    if (typeof storage !== 'string') return Promise.reject(new Error('unavailable'));
    const match = storage.match(/^keychain:([a-zA-Z0-9_@.-]{1,128})\/([a-zA-Z0-9_@.-]{1,128})$/);
    if (!match || process.platform !== 'darwin') return Promise.reject(new Error('unavailable'));
    const { spawn } = require('child_process');
    const helper = process.env.ZEROCREDS_KEYCHAIN_HELPER || path.join(__dirname, '../bin/zerocreds-keychain');
    return new Promise((resolve, reject) => {
      const child = spawn(helper, ['get', match[1], match[2]], { stdio: ['ignore', 'pipe', 'ignore'] });
      let output = Buffer.alloc(0);
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        error ? reject(error) : resolve(value);
      };
      const timer = setTimeout(() => { child.kill('SIGKILL'); finish(new Error('unavailable')); }, 5000);
      child.stdout.on('data', (chunk) => {
        if (output.length + chunk.length > 65536) {
          child.kill('SIGKILL');
          finish(new Error('invalid credential record'));
        } else output = Buffer.concat([output, chunk]);
      });
      child.once('error', () => finish(new Error('unavailable')));
      child.once('close', (code) => {
        if (code !== 0 || !output.length) return finish(new Error(code === 4 ? 'keychain_locked' : 'unavailable'));
        try {
          const fields = JSON.parse(output.toString('utf8'));
          if (!fields || typeof fields !== 'object' || Array.isArray(fields)) throw new Error('bad record');
          finish(null, fields);
        } catch { finish(new Error('invalid credential record')); }
      });
    });
  }

  // Ed25519 key for form manifests and submission receipts (created on first start).
  const SIGNING_KEY = loadSigningKey(SIGNING_KEY_FILE);

  // Integrators registry: sha256(token) → record. A Map, so no prototype keys can match.
  const INTEGRATORS = new Map();
  function tokenHash(t) {
    return crypto.createHash('sha256').update(String(t)).digest();
  }
  function loadIntegrators() {
    let raw;
    try {
      raw = JSON.parse(fs.readFileSync(INTEGRATORS_FILE, 'utf8'));
    } catch (e) {
      if (e.code !== 'ENOENT') console.warn('[config] integrators file error:', e.message);
      return;
    }
    if (!raw || typeof raw !== 'object') return;
    for (const [token, rec] of Object.entries(raw)) {
      if (!token || !rec || typeof rec !== 'object') continue;
      INTEGRATORS.set(tokenHash(token).toString('hex'),
        { ...rec, token, destinations: Object.assign(Object.create(null), rec.destinations || {}) });
    }
    console.log(`[config] loaded ${INTEGRATORS.size} integrator(s)`);
  }
  loadIntegrators();

  // Wallet API tokens are issued by the trusted host and bound to an owner,
  // profile and admin-configured OpenBao destination. The model cannot supply
  // any of these values in a tool call.
  const WALLET_CLIENTS = new Map();
  let walletClients = config.walletClients;
  if (!walletClients && WALLET_CLIENTS_FILE) {
    if (process.platform !== 'win32' && (fs.statSync(WALLET_CLIENTS_FILE).mode & 0o077)) {
      throw new Error('wallet clients file must be private (mode 0600)');
    }
    walletClients = JSON.parse(fs.readFileSync(WALLET_CLIENTS_FILE, 'utf8'));
  }
  for (const [token, scope] of Object.entries(walletClients || {})) {
    if (token.length < 32 || token === ADMIN_TOKEN || !scope || !/^[a-zA-Z0-9_-]{1,100}$/.test(scope.owner_id || '')
      || !/^[a-zA-Z0-9_-]{1,100}$/.test(scope.profile_id || '')
      || !isSafeKey(scope.destination || '')) throw new Error('invalid wallet client configuration');
    WALLET_CLIENTS.set(tokenHash(token).toString('hex'), scope);
  }

  // Host assertions are short-lived Ed25519 JWTs. Public keys and owner/profile
  // mappings are operator-owned; claims can select only a preconfigured scope.
  let walletAssertionIssuers = config.walletAssertionIssuers;
  if (!walletAssertionIssuers && WALLET_ASSERTION_ISSUERS_FILE) {
    const stat = fs.statSync(WALLET_ASSERTION_ISSUERS_FILE);
    if (process.platform !== 'win32' && (stat.mode & 0o077)) {
      throw new Error('wallet assertion issuers file must be private (mode 0600)');
    }
    walletAssertionIssuers = JSON.parse(fs.readFileSync(WALLET_ASSERTION_ISSUERS_FILE, 'utf8'));
  }
  const WALLET_ASSERTION_ISSUERS = new Map();
  const walletOperations = new Set(['wallet.forms.create', 'wallet.forms.status', 'wallet.connections.status', 'wallet.connections.revoke']);
  for (const [issuer, record] of Object.entries(walletAssertionIssuers || {})) {
    if (!issuer || !record || typeof record !== 'object' || !record.keys || !record.profiles) {
      throw new Error('invalid wallet assertion issuer configuration');
    }
    const keys = new Map();
    for (const [kid, publicKey] of Object.entries(record.keys)) {
      if (!/^[A-Za-z0-9._-]{1,100}$/.test(kid) || typeof publicKey !== 'string') {
        throw new Error('invalid wallet assertion public key');
      }
      try {
        const parsedKey = crypto.createPublicKey(publicKey);
        if (parsedKey.asymmetricKeyType !== 'ed25519' || /PRIVATE KEY/.test(publicKey)) throw new Error();
        keys.set(kid, parsedKey);
      }
      catch { throw new Error('invalid wallet assertion public key'); }
    }
    const profiles = new Map();
    for (const [profileId, scope] of Object.entries(record.profiles)) {
      if (!/^[A-Za-z0-9_-]{1,100}$/.test(profileId) || !scope || typeof scope !== 'object'
        || !/^[a-zA-Z0-9_-]{1,100}$/.test(scope.owner_id || '') || scope.profile_id !== profileId
        || !isSafeKey(scope.destination || '') || !Object.hasOwn(NAMED_DESTINATIONS, scope.destination)
        || !Array.isArray(scope.callers) || !scope.callers.length
        || scope.callers.some(caller => !['human', 'machine'].includes(caller))) {
        throw new Error('invalid wallet assertion profile configuration');
      }
      profiles.set(profileId, Object.freeze({ owner_id: scope.owner_id, profile_id: profileId,
        destination: scope.destination, callers: new Set(scope.callers) }));
    }
    WALLET_ASSERTION_ISSUERS.set(issuer, { keys, profiles });
  }
  function parseWalletAssertion(token, operation) {
    try {
      if (typeof token !== 'string' || token.length > 4096) return null;
      const parts = token.split('.');
      if (parts.length !== 3 || parts.some(part => !part)) return null;
      const decode = part => Buffer.from(part, 'base64url').toString('utf8');
      const header = JSON.parse(decode(parts[0]));
      const claims = JSON.parse(decode(parts[1]));
      if (!header || header.alg !== 'EdDSA' || header.typ !== 'JWT' || typeof header.kid !== 'string'
        || !claims || typeof claims !== 'object' || Array.isArray(claims)) return null;
      const issuer = WALLET_ASSERTION_ISSUERS.get(claims.iss);
      const publicKey = issuer?.keys.get(header.kid);
      if (!issuer || !publicKey || !crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), publicKey,
        Buffer.from(parts[2], 'base64url'))) return null;
      const allowedClaimNames = new Set(['iss', 'aud', 'owner_id', 'profile_id', 'caller_class', 'operations', 'iat', 'exp', 'jti', 'run_id']);
      if (Object.keys(claims).some(name => !allowedClaimNames.has(name))
        || !['human', 'machine'].includes(claims.caller_class)
        || claims.aud !== `zerocreds-wallet:${claims.caller_class}` || !Array.isArray(claims.operations)
        || !claims.operations.length || claims.operations.some(value => !walletOperations.has(value))
        || new Set(claims.operations).size !== claims.operations.length || !claims.operations.includes(operation)
        || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)
        || claims.iat > Math.floor(Date.now() / 1000) + 30 || claims.exp <= Math.floor(Date.now() / 1000)
        || claims.exp > Math.floor(Date.now() / 1000) + 300
        || claims.exp <= claims.iat || claims.exp - claims.iat > 300
        || !/^[A-Za-z0-9_-]{16,128}$/.test(claims.jti || '')) return null;
      if (claims.caller_class === 'machine') {
        if (!/^[A-Za-z0-9_.:-]{1,200}$/.test(claims.run_id || '')) return null;
      } else if (claims.run_id !== undefined) return null;
      const profile = issuer.profiles.get(claims.profile_id);
      if (!profile || !profile.callers.has(claims.caller_class) || profile.owner_id !== claims.owner_id
        || claims.owner_id !== claims.owner_id.trim()) return null;
      return { issuer: claims.iss, profile, jti: claims.jti, exp: claims.exp };
    } catch { return null; }
  }

  async function walletCall(method, route, body, scope) {
    if (!WALLET_WORKER_URL || WALLET_SERVICE_TOKEN.length < 32) throw new Error('wallet unavailable');
    const base = new URL(WALLET_WORKER_URL);
    if (base.protocol !== 'https:' && !(base.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(base.hostname))) {
      throw new Error('wallet worker URL must use HTTPS');
    }
    const response = await fetch(new URL(route, base), {
      method, signal: AbortSignal.timeout(10000),
      headers: { Authorization: `Bearer ${WALLET_SERVICE_TOKEN}`, 'Content-Type': 'application/json',
        ...(scope ? { 'X-Wallet-Owner': scope.owner_id, 'X-Wallet-Profile': scope.profile_id } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}), redirect: 'error',
    });
    const result = await response.json();
    if (!response.ok) {
      const error = new Error(result?.error || 'wallet unavailable');
      error.status = response.status;
      throw error;
    }
    return result;
  }

  async function walletScope(authHeader, operation) {
    if (typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.slice(7).trim();
    const legacyScope = WALLET_CLIENTS.get(tokenHash(token).toString('hex'));
    if (legacyScope) return legacyScope;
    const assertion = parseWalletAssertion(token, operation);
    if (!assertion) return null;
    try {
      await walletCall('POST', '/internal/assertions/claim', {
        jti_hash: crypto.createHash('sha256').update(assertion.jti).digest('hex'),
        expires_at: assertion.exp * 1000,
      });
    } catch { return null; }
    return { ...assertion.profile, requester: assertion.issuer };
  }

  function saveIntegrators() {
    const out = {};
    for (const { token, ...rest } of INTEGRATORS.values()) out[token] = rest;
    fs.writeFileSync(INTEGRATORS_FILE, JSON.stringify(out, null, 2), { mode: 0o600 });
  }

  function findIntegratorById(id) {
    for (const rec of INTEGRATORS.values()) if (rec.id === id) return rec;
    return null;
  }

  // New self-registrations have an explicit pending status. Records created before
  // approval existed have no status and must retain their previously issued access.
  function isLegacyIntegrator(rec) { return !!rec && !Object.hasOwn(rec, 'status'); }
  function isActiveIntegrator(rec) { return isLegacyIntegrator(rec) || rec.status === 'active'; }

  // Rate limit for self-serve registration: max 3 per client IP per hour
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

  const ADMIN_HASH = tokenHash(ADMIN_TOKEN);
  const NO_AUTH = { isAdmin: false, integrator: null };

  // Resolve auth: returns { isAdmin, integrator|null }
  function resolveAuth(authHeader) {
    if (typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) return NO_AUTH;
    const token = authHeader.slice(7).trim();
    if (!token) return NO_AUTH;
    const hash = tokenHash(token);
    if (crypto.timingSafeEqual(hash, ADMIN_HASH)) return { isAdmin: true, integrator: null };
    const rec = INTEGRATORS.get(hash.toString('hex'));
    if (rec && isActiveIntegrator(rec)) return { isAdmin: false, integrator: rec };
    return NO_AUTH;
  }

  // Resolve destination: name → config (integrator's own first), or an inline object
  // when the server allows it. Returns { dest } or { error }.
  function resolveDestination(destination, integrator, isAdmin, legacySession = false) {
    if (typeof destination === 'string') {
      if (integrator && Object.hasOwn(integrator.destinations, destination)) return { dest: integrator.destinations[destination] };
      if (Object.hasOwn(NAMED_DESTINATIONS, destination)) return { dest: NAMED_DESTINATIONS[destination] };
      return { error: `unknown named destination: ${destination.slice(0, 64)}` };
    }
    const legacyInline = legacySession && isLegacyIntegrator(integrator);
    if (!ALLOW_INLINE_DESTINATIONS && !legacyInline) {
      return { error: 'inline destinations are disabled on this server — use a named destination configured by the admin' };
    }
    if (!destination || typeof destination !== 'object' || Array.isArray(destination)) return { error: 'destination.type is required' };
    if (!isAdmin && !legacyInline && SERVER_LOCAL_TYPES.has(destination.type)) {
      return { error: `inline ${destination.type} destinations are only available to the admin` };
    }
    return { dest: destination };
  }

  function pendingPath(token, ext = 'json') {
    return path.join(CONNECT_PENDING_DIR, `${token}.${ext}`);
  }

  function resolvePendingNamedDestination(name, integratorId) {
    if (integratorId === 'admin') return NAMED_DESTINATIONS[name] || null;
    const integrator = findIntegratorById(integratorId);
    if (integrator?.destinations?.[name]) return integrator.destinations[name];
    return NAMED_DESTINATIONS[name] || null;
  }

  function destinationFingerprint(destination) {
    return crypto.createHash('sha256').update(JSON.stringify(destination)).digest('hex');
  }

  function readPending(token) {
    try { return JSON.parse(fs.readFileSync(pendingPath(token), 'utf8')); } catch { return null; }
  }

  function deletePending(token) {
    try { fs.unlinkSync(pendingPath(token)); } catch {}
  }

  // Atomically take ownership of a one-time link: only one request can rename the file.
  function claimPending(token) {
    try { fs.renameSync(pendingPath(token), pendingPath(token, 'claimed')); return true; }
    catch { return false; }
  }

  function releaseClaim(token) {
    try { fs.renameSync(pendingPath(token, 'claimed'), pendingPath(token)); } catch {}
  }

  function dropClaim(token) {
    try { fs.unlinkSync(pendingPath(token, 'claimed')); } catch {}
  }

  // Removes expired pending files, stale claims and old .done markers. Pending files may
  // embed destination credentials, so they must not outlive their session.
  function sweepPending(now = Date.now()) {
    let files;
    try { files = fs.readdirSync(CONNECT_PENDING_DIR); } catch { return 0; }
    let removed = 0;
    for (const file of files) {
      const full = path.join(CONNECT_PENDING_DIR, file);
      try {
        let stale = false;
        if (file.endsWith('.json')) {
          const p = JSON.parse(fs.readFileSync(full, 'utf8'));
          stale = typeof p?.expires === 'number' && p.expires < now;
        } else if (file.endsWith('.claimed')) {
          stale = fs.statSync(full).mtimeMs < now - CLAIM_STALE_MS;
          if (stale) {
            let p;
            try { p = JSON.parse(fs.readFileSync(full, 'utf8')); } catch {}
            if (p?.wallet && p.expires > now && !fs.existsSync(pendingPath(p.token))) {
              fs.renameSync(full, pendingPath(p.token));
              continue;
            }
          }
        } else if (file.endsWith('.done') || file.endsWith('.written')) {
          stale = fs.statSync(full).mtimeMs < now - DONE_TTL_MS;
        }
        if (stale) { fs.unlinkSync(full); removed++; }
      } catch {}
    }
    return removed;
  }

  // Scan for an active (not expired, not done) session matching integrator+service+user_hash.
  function findActiveSession(integrator_id, service_slug, user_hash) {
    let files;
    try { files = fs.readdirSync(CONNECT_PENDING_DIR).filter(f => f.endsWith('.json')); }
    catch { return null; }
    for (const file of files) {
      const token = file.slice(0, -5);
      if (fs.existsSync(pendingPath(token, 'done'))) continue;
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

  function saveOptsFor(pending) {
    const sub = integratorSubdir(pending.integrator_id);
    if (sub && !/^[a-zA-Z0-9_-]{1,64}$/.test(pending.integrator_id)) throw new Error('invalid integrator id');
    return {
      ...DEST_OPTS,
      tokensDir: path.join(AGENT_TOKENS_DIR, sub),
      context: templateContext(pending),
    };
  }

  function renderDynamicForm(res, req, token, pending) {
    const nonce = newNonce();
    const api = pending.form ? formApiSnippets(token, pending, BASE_URL) : null;
    sendHtml(res, 200, dynamicFormHtml(token, pending, String(req.headers.host || ''), nonce, api), nonce);
  }

  // Probes an http_post destination before a session/form is created. Returns an error
  // response body, or null. The upstream response body is never returned — only the status.
  async function preflightDestination(dest, payload, fields) {
    const openbao = dest?.type === 'vault' && !!dest.preflight_path_prefix;
    if (openbao && payload.test_destination === false) return { error: 'openbao_preflight_required' };
    if (!openbao && (payload.test_destination === false || dest?.type !== 'http_post')) return null;
    try {
      const receipt = await testDestination(dest, DEST_OPTS, fields);
      return openbao ? { preflight: { checked: receipt?.checked === true, at: new Date().toISOString() } } : null;
    } catch (e) {
      const detail = openbao ? e.message : /^HTTP \d{3}$/.test(e.message) ? e.message
        : e.code === 'EDESTBLOCKED' ? 'destination address is not allowed'
        : 'request failed';
      return {
        error: 'destination_unreachable',
        detail,
        hint: openbao ? 'Check the configured OpenBao writer, owner probe path and metadata/cleanup policy.'
          : 'Check destination URL and Authorization header. Pass test_destination: false to skip this check.',
      };
    }
  }

  function walletDestination(scope, openbaoPath) {
    const base = NAMED_DESTINATIONS[scope.destination];
    if (!base || base.type !== 'vault' || !base.preflight_path_prefix) throw new Error('wallet destination unavailable');
    const mount = openbaoPath.split('/')[0];
    const expectedPrefix = `${mount}/data/owners/${scope.owner_id}/connections/`;
    if (!openbaoPath.startsWith(expectedPrefix) || !/^[a-zA-Z0-9_-]{1,100}$/.test(openbaoPath.slice(expectedPrefix.length))) {
      throw new Error('wallet path mismatch');
    }
    return { ...base, path: openbaoPath,
      preflight_path_prefix: `${mount}/data/owners/${scope.owner_id}/probes`, create_only: true };
  }

  function walletWritePath(formId) { return pendingPath(formId, 'written'); }

  function signedManifest(formId, pending) {
    const { form } = pending;
    const manifest = {
      v: 1,
      type: 'zerocreds.form_manifest',
      form_id: formId,
      handle: form.handle,
      kind: form.kind,
      owner: pending.integrator_id,
      requester: requesterLabel(pending),
      fields: pending.fields.map(f => ({ name: f.name, label: f.label, type: f.type || 'text', required: f.required !== false })),
      destination: describeDestination(pending.destination, pending),
      ...(pending.wallet ? { wallet: {
        owner_id: pending.wallet.owner_id, profile_id: pending.wallet.profile_id,
        connection_id: pending.wallet.connection_id,
      } } : {}),
      submit: {
        method: 'POST',
        url: `${BASE_URL}/api/forms/${formId}/submit`,
        auth: 'Bearer <owner key> or Bearer <one-time submit token>',
        body: { manifest_id: '<manifest_id>', fields: Object.fromEntries(pending.fields.map(f => [f.name, `<${f.name}>`])) },
      },
      human_url: `${BASE_URL}/f/${formId}`,
      expires_at: new Date(pending.expires).toISOString(),
      server: { version: VERSION, commit: COMMIT },
    };
    return { manifest_id: sha256Hex(canonicalJson(manifest)), ...signPayload(SIGNING_KEY, manifest) };
  }

  // Validates submitted values against the session, saves them and marks the link used.
  // Shared by the human form (POST /f/:token) and machine submit (POST /api/forms/:id/submit).
  // Returns { status, body }.
  async function submitPending(token, pending, submitted, via) {
    if (!submitted || typeof submitted !== 'object' || Array.isArray(submitted)) {
      return { status: 400, body: { error: 'missing fields' } };
    }
    // Only keep declared field names — strip anything extra
    const clean = Object.create(null);
    for (const f of pending.fields) {
      if (!Object.hasOwn(submitted, f.name)) continue;
      const v = submitted[f.name];
      if (!['string', 'number', 'boolean'].includes(typeof v)) return { status: 400, body: { error: `invalid value for field: ${f.name}` } };
      clean[f.name] = String(v);
    }

    // Validate all required fields are present
    for (const f of pending.fields) {
      if (f.required !== false && !clean[f.name]) {
        return { status: 400, body: { error: `missing required field: ${f.name}` } };
      }
    }

    // Validate url fields
    for (const f of pending.fields) {
      if (f.type === 'url' && clean[f.name]) {
        try {
          const u = new URL(clean[f.name]);
          if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
        } catch { return { status: 400, body: { error: `invalid URL for field: ${f.name}` } }; }
      }
    }

    // One-time link: claim it before saving so concurrent submissions cannot both succeed.
    if (!claimPending(token)) return { status: 403, body: { error: 'invalid or expired token' } };

    if (pending.wallet) {
      const wallet = pending.wallet;
      const scope = { owner_id: wallet.owner_id, profile_id: wallet.profile_id };
      const digest = crypto.createHmac('sha256', token).update(canonicalJson(clean)).digest('hex');
      try {
        const connection = await walletCall('GET', `/internal/connections/${wallet.connection_id}`, null, scope);
        if (connection.state === 'revoked' || connection.openbao_path !== wallet.openbao_path) {
          releaseClaim(token);
          return { status: 409, body: { error: 'wallet connection unavailable' } };
        }
        let written;
        try { written = JSON.parse(fs.readFileSync(walletWritePath(token), 'utf8')); } catch {}
        if (written && written.digest !== digest) {
          releaseClaim(token);
          return { status: 409, body: { error: 'submission differs from saved write' } };
        }
        if (!written) {
          const base = NAMED_DESTINATIONS[wallet.destination];
          if (!base || destinationFingerprint(base) !== wallet.destination_sha256) {
            releaseClaim(token);
            return { status: 409, body: { error: 'destination_changed' } };
          }
          const destination = walletDestination({ ...scope, destination: wallet.destination }, wallet.openbao_path);
          const result = await saveToDestination(destination, { ...clean }, saveOptsFor(pending));
          if (!Number.isInteger(result?.version) || result.version < 1) throw new Error('openbao_write_receipt_missing');
          const receipt = signPayload(SIGNING_KEY, {
            v: 1, type: 'zerocreds.receipt', form_id: token,
            handle: pending.form.handle, kind: pending.form.kind,
            owner: pending.integrator_id, manifest_id: pending.form.manifest_id,
            fields: pending.fields.map(f => f.name).filter(n => clean[n] !== undefined),
            destination: describeDestination(pending.destination, pending),
            destination_ref: wallet.connection_id,
            wallet: { owner_id: scope.owner_id, profile_id: scope.profile_id,
              connection_id: wallet.connection_id, kv_version: result.version },
            submitted_via: via, submitted_at: new Date().toISOString(),
            server: { version: VERSION, commit: COMMIT },
          });
          written = { digest, version: result.version, receipt,
            receipt_ref: sha256Hex(canonicalJson(receipt)) };
          const temp = `${walletWritePath(token)}.${crypto.randomBytes(6).toString('hex')}`;
          fs.writeFileSync(temp, JSON.stringify(written), { mode: 0o600, flag: 'wx' });
          fs.renameSync(temp, walletWritePath(token));
        }
        await walletCall('POST', `/internal/forms/${token}/complete`, {
          owner_id: scope.owner_id, profile_id: scope.profile_id,
          manifest_id: pending.form.manifest_id, kv_version: written.version,
          receipt_ref: written.receipt_ref,
        });
        fs.writeFileSync(pendingPath(token, 'done'), JSON.stringify({
          connection_id: wallet.connection_id, version: written.version,
          receipt_ref: written.receipt_ref, handle: pending.form.handle,
          receipt: written.receipt, _integrator_id: pending.integrator_id,
        }), { mode: 0o600 });
        dropClaim(token);
        try { fs.unlinkSync(walletWritePath(token)); } catch {}
        return { status: 200, body: { ok: true, connection_id: wallet.connection_id,
          handle: pending.form.handle, receipt: written.receipt } };
      } catch (e) {
        releaseClaim(token);
        console.error('[wallet] completion failed:', e.message);
        return { status: 503, body: { error: 'wallet save unavailable; retry with the same values' } };
      }
    }

    let saveResult;
    try {
      const saveOpts = saveOptsFor(pending);
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
          const dest = destinationForField(pending, { level });
          if (!dest) {
            console.warn(`[dynamic] no destination for level "${level}", skipping:`, Object.keys(groupFields));
            continue;
          }
          const r = await saveToDestination(dest, groupFields, saveOpts);
          if (r?.secret_id) secretIds[level] = r.secret_id;
        }
        saveResult = { secret_ids: secretIds };
      } else {
        let destinationForWrite = pending.destination;
        if (pending.destination_ref) {
          destinationForWrite = resolvePendingNamedDestination(pending.destination_ref, pending.integrator_id);
          if (!destinationForWrite || destinationFingerprint(destinationForWrite) !== pending.destination_sha256) {
            releaseClaim(token);
            return { status: 409, body: { error: 'destination_changed' } };
          }
        }
        saveResult = await saveToDestination(destinationForWrite, { ...clean }, saveOpts);
        if (pending.destination_ref && (!Number.isInteger(saveResult?.version) || saveResult.version < 1)) {
          throw new Error('openbao_write_receipt_missing');
        }
      }
    } catch (e) {
      // Let the user retry with the same link; never echo upstream details back.
      releaseClaim(token);
      console.error('[dynamic] save failed:', e.message);
      return { status: 500, body: { error: 'failed to save credentials' } };
    }

    if (LOCAL_MODE && pending.service_slug && pending.uid) {
      try {
        const entries = readLocalCatalog();
        const index = entries.findIndex((item) => item.provider === pending.service_slug && item.account_alias === pending.uid);
        const previous = index >= 0 ? entries[index] : null;
        const entry = {
          connection_id: previous?.connection_id || crypto.randomBytes(16).toString('hex'),
          provider: pending.service_slug,
          account_alias: pending.uid,
          storage: typeof saveResult?.secret_id === 'string' ? saveResult.secret_id : null,
          state: 'active',
          credential_expires_at: pending.credential_expires_at || null,
          expiry_status: pending.credential_expires_at ? 'declared' : 'unknown',
          verification_status: 'unknown',
          created_at: previous?.created_at || new Date().toISOString(),
          updated_at: new Date().toISOString(),
          last_used_at: previous?.last_used_at || null,
        };
        if (index >= 0) entries[index] = entry;
        else entries.push(entry);
        writeLocalCatalog(entries);
      } catch (error) {
        console.error('[local-catalog] metadata write failed:', error.message);
        releaseClaim(token);
        return { status: 503, body: { error: 'credential saved but local catalog update failed; retry this form' } };
      }
    }

    dropClaim(token);

    // Forms get a signed receipt with the handle: what was saved and where, never the values.
    let formResult = null;
    if (pending.form) {
      const receipt = signPayload(SIGNING_KEY, {
        v: 1,
        type: 'zerocreds.receipt',
        form_id: token,
        handle: pending.form.handle,
        kind: pending.form.kind,
        owner: pending.integrator_id,
        manifest_id: pending.form.manifest_id,
        fields: pending.fields.map(f => f.name).filter(n => clean[n] !== undefined),
        destination: describeDestination(pending.destination, pending),
        destination_ref: typeof saveResult?.secret_id === 'string' ? saveResult.secret_id : null,
        submitted_via: via,
        submitted_at: new Date().toISOString(),
        server: { version: VERSION, commit: COMMIT },
      });
      formResult = { handle: pending.form.handle, receipt };
    }

    // .done file stores destination references — never the credentials themselves
    try {
      fs.writeFileSync(
        pendingPath(token, 'done'),
        JSON.stringify({ ...(saveResult || {}), ...(formResult || {}), _integrator_id: pending.integrator_id }),
        { mode: 0o600 },
      );
    } catch {}
    console.info('[session-migration] completed auth=%s',
      ['anonymous', 'admin', 'integrator'].includes(pending._audit_auth) ? pending._audit_auth : 'unknown');

    if (pending.notify?.tg_bot_token) {
      tgNotify(pending.notify.tg_bot_token, pending.notify.tg_chat_id,
        `✅ ${pending.title}: credentials received and saved.`);
    }
    return { status: 200, body: { ok: true, ...(formResult || {}) } };
  }

  async function handle(req, res) {
    const url = new URL(req.url, 'http://localhost');

    if (LOCAL_MODE && req.headers.host !== new URL(BASE_URL).host) {
      return json(res, 403, { error: 'invalid local host' });
    }

    // CORS preflight for API
    if (req.method === 'OPTIONS') {
      const origin = req.headers.origin;
      if (LOCAL_MODE && origin && origin !== LOCAL_ORIGIN) return json(res, 403, { error: 'cross-origin request denied' });
      res.writeHead(204, { ...(LOCAL_MODE ? (origin ? { 'Access-Control-Allow-Origin': LOCAL_ORIGIN } : {}) : { 'Access-Control-Allow-Origin': '*' }), 'Access-Control-Allow-Headers': 'Content-Type,Authorization', 'Access-Control-Allow-Methods': 'GET,POST' }).end();
      return;
    }

    // GET / — redirect to landing
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(301, { Location: 'https://zerocreds.ru' }).end();
      return;
    }

    // GET /about
    if (req.method === 'GET' && url.pathname === '/about') {
      return sendHtml(res, 200, aboutHtml());
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
      const payload = await readJson(req);
      if (!payload) return json(res, 400, { error: 'bad json' });
      const { session, code } = payload;
      if (typeof session !== 'string' || typeof code !== 'string' || !session || !code) {
        return json(res, 400, { error: 'missing session or code' });
      }
      if (!TOKEN_RE.test(session)) return json(res, 400, { error: 'invalid session' });
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
          if (!TOKEN_RE.test(t)) return sendHtml(res, 400, expiredHtml());
          const nonce = newNonce();
          return sendHtml(res, 200, nalogFormHtml(t, nonce), nonce);
        }

        if (req.method === 'POST') {
          const payload = await readJson(req);
          if (!payload) return json(res, 400, { error: 'bad json' });
          const { t, login, password } = payload;
          if (typeof t !== 'string' || typeof login !== 'string' || typeof password !== 'string' || !t || !login || !password) {
            return json(res, 400, { error: 'missing fields' });
          }
          if (!TOKEN_RE.test(t)) return json(res, 400, { error: 'invalid token' });

          const pending = readPending(t);
          if (!pending) return json(res, 403, { error: 'invalid or expired token' });
          if (pending.expires < Date.now()) { deletePending(t); return json(res, 403, { error: 'link expired' }); }
          if (pending.service !== 'nalog') return json(res, 403, { error: 'service mismatch' });
          if (!/^-?[a-zA-Z0-9_-]{1,128}$/.test(pending.uid)) return json(res, 403, { error: 'invalid uid' });

          if (!claimPending(t)) return json(res, 403, { error: 'invalid or expired token' });
          dropClaim(t);

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
      const meta = Object.hasOwn(SERVICE_META, service) ? SERVICE_META[service] : null;
      if (!meta) { res.writeHead(404).end('Unknown service'); return; }

      if (req.method === 'GET') {
        const t = url.searchParams.get('t') || '';
        if (!TOKEN_RE.test(t)) return sendHtml(res, 400, expiredHtml());
        const p = readPending(t);
        if (!p || p.expires < Date.now()) return sendHtml(res, 410, expiredHtml());
        const nonce = newNonce();
        return sendHtml(res, 200, connectFormHtml(service, meta, t, nonce), nonce);
      }

      if (req.method === 'POST') {
        const payload = await readJson(req);
        if (!payload) return json(res, 400, { error: 'bad json' });
        const { t, value } = payload;
        if (typeof t !== 'string' || typeof value !== 'string' || !t || !value) return json(res, 400, { error: 'missing t or value' });
        if (!TOKEN_RE.test(t)) return json(res, 400, { error: 'invalid token' });

        const pending = readPending(t);
        if (!pending) return json(res, 403, { error: 'invalid or expired token' });
        if (pending.expires < Date.now()) { deletePending(t); return json(res, 403, { error: 'link expired' }); }
        if (pending.service !== service) return json(res, 403, { error: 'service mismatch' });
        if (!/^-?[a-zA-Z0-9_-]{1,128}$/.test(pending.uid)) return json(res, 403, { error: 'invalid uid' });

        if (!claimPending(t)) return json(res, 403, { error: 'invalid or expired token' });
        try {
          const tokensDir = path.join(AGENT_TOKENS_DIR, pending.uid);
          fs.mkdirSync(tokensDir, { recursive: true, mode: 0o700 });
          fs.writeFileSync(path.join(tokensDir, service), value.trim(), { mode: 0o600 });
        } catch (e) {
          releaseClaim(t);
          throw e;
        }
        dropClaim(t);

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
    // Self-registration only files a request: the token stays inactive until the
    // admin approves it (POST /admin/integrators/approve).
    if (req.method === 'POST' && url.pathname === '/api/register') {
      const ip = clientIp(req);
      if (!checkRegisterLimit(ip)) return json(res, 429, { error: 'Too many registrations from this IP. Try again in an hour.' });
      const payload = await readJson(req) || {};
      const { email, website, category } = payload;
      if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(email)) {
        return json(res, 400, { error: 'Valid email is required' });
      }
      if (website !== undefined && (typeof website !== 'string' || website.length > 200)) {
        return json(res, 400, { error: 'Invalid website' });
      }
      const VALID_CATEGORIES = ['ai_agent', 'saas', 'internal', 'personal', 'other'];
      if (!VALID_CATEGORIES.includes(category)) return json(res, 400, { error: 'Category is required' });
      const token = 'tok_' + crypto.randomBytes(20).toString('hex');
      const id = 'u_' + crypto.randomBytes(6).toString('hex');
      INTEGRATORS.set(tokenHash(token).toString('hex'), {
        token, id, name: id, email, website: website || '', category, status: 'pending',
        destinations: Object.create(null), created: new Date().toISOString(),
      });
      saveIntegrators();
      console.log(`[register] integrator pending approval: ${id} category=${category}`);
      return json(res, 200, { token, id, status: 'pending_approval', base_url: BASE_URL });
    }

    // ── POST /admin/integrators/create ────────────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/admin/integrators/create') {
      const { isAdmin } = resolveAuth(req.headers['authorization']);
      if (!isAdmin) return json(res, 401, { error: 'admin token required' });
      const payload = await readJson(req);
      if (!payload) return json(res, 400, { error: 'bad json' });
      const { id, name } = payload;
      if (typeof id !== 'string' || typeof name !== 'string' || !id || !name) return json(res, 400, { error: 'missing id or name' });
      if (!isSafeKey(id) || id === 'admin') return json(res, 400, { error: 'invalid id' });
      if (name.length > 100) return json(res, 400, { error: 'name too long' });
      if (findIntegratorById(id)) return json(res, 409, { error: 'integrator id already exists' });
      const token = 'tok_' + crypto.randomBytes(20).toString('hex');
      INTEGRATORS.set(tokenHash(token).toString('hex'),
        { token, id, name, status: 'active', destinations: Object.create(null), created: new Date().toISOString() });
      saveIntegrators();
      console.log(`[admin] created integrator: ${id}`);
      return json(res, 200, { token, id, name });
    }

    // ── POST /admin/integrators/approve ───────────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/admin/integrators/approve') {
      const { isAdmin } = resolveAuth(req.headers['authorization']);
      if (!isAdmin) return json(res, 401, { error: 'admin token required' });
      const payload = await readJson(req);
      if (!payload) return json(res, 400, { error: 'bad json' });
      const rec = typeof payload.id === 'string' ? findIntegratorById(payload.id) : null;
      if (!rec) return json(res, 404, { error: 'unknown integrator id' });
      rec.status = 'active';
      saveIntegrators();
      console.log(`[admin] approved integrator: ${rec.id}`);
      return json(res, 200, { ok: true, id: rec.id, status: rec.status });
    }

    // ── POST /api/destinations ─────────────────────────────────────────────────
    // Destinations are admin-managed. The admin may attach one to an integrator via
    // integrator_id. Integrators may only add their own when inline destinations are enabled.
    if (req.method === 'POST' && url.pathname === '/api/destinations') {
      const { isAdmin, integrator } = resolveAuth(req.headers['authorization']);
      if (!isAdmin && !integrator) return json(res, 401, { error: 'unauthorized' });
      if (!isAdmin && !ALLOW_INLINE_DESTINATIONS && !isLegacyIntegrator(integrator)) return json(res, 403, { error: 'destinations are managed by the server admin' });
      const payload = await readJson(req);
      if (!payload) return json(res, 400, { error: 'bad json' });
      const { name, destination, integrator_id } = payload;
      if (!name || !destination?.type) return json(res, 400, { error: 'missing name or destination.type' });
      if (!isSafeKey(name)) return json(res, 400, { error: 'invalid name' });
      if (!isAdmin && !isLegacyIntegrator(integrator) && SERVER_LOCAL_TYPES.has(destination.type)) {
        return json(res, 403, { error: `${destination.type} destinations can only be added by the admin` });
      }
      const invalid = validateDestination(destination, DEST_OPTS);
      if (invalid) return json(res, 400, { error: invalid });

      if (isAdmin && integrator_id !== undefined) {
        const rec = typeof integrator_id === 'string' ? findIntegratorById(integrator_id) : null;
        if (!rec) return json(res, 404, { error: 'unknown integrator id' });
        rec.destinations[name] = destination;
        saveIntegrators();
      } else if (isAdmin) {
        NAMED_DESTINATIONS[name] = destination;
        fs.writeFileSync(DESTINATIONS_FILE, JSON.stringify(NAMED_DESTINATIONS, null, 2), { mode: 0o600 });
      } else {
        integrator.destinations[name] = destination;
        saveIntegrators();
      }
      return json(res, 200, { ok: true, name });
    }

    if (req.method === 'GET' && url.pathname === '/api/local/connections') {
      if (!LOCAL_MODE) return json(res, 404, { error: 'not found' });
      const { isAdmin } = resolveAuth(req.headers['authorization']);
      if (!isAdmin) return json(res, 401, { error: 'unauthorized' });
      let entries;
      try { entries = readLocalCatalog(); }
      catch { return json(res, 503, { error: 'local catalog unavailable' }); }
      const provider = (url.searchParams.get('provider') || '').toLowerCase();
      const alias = (url.searchParams.get('account_alias') || '').toLowerCase();
      const matching = entries.filter((entry) =>
        (!provider || String(entry.provider).toLowerCase() === provider)
        && (!alias || String(entry.account_alias).toLowerCase() === alias));
      const safe = matching.map((entry) => ({
        connection_id: entry.connection_id,
        provider: entry.provider,
        account_alias: entry.account_alias,
        storage: entry.storage,
        state: entry.state,
        credential_expires_at: entry.credential_expires_at,
        expiry_status: entry.expiry_status,
        verification_status: entry.verification_status,
        last_verified_at: entry.last_verified_at || null,
        verified_identity: entry.verified_identity || null,
        verified_permissions: Array.isArray(entry.verified_permissions) ? entry.verified_permissions : [],
        permission_evidence: entry.permission_evidence || 'unknown',
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        last_used_at: entry.last_used_at,
      }));
      const eligible = safe.filter((entry) => entry.state === 'active'
        && (!entry.credential_expires_at || Date.parse(entry.credential_expires_at) > Date.now()));
      const expired = safe.filter((entry) => entry.state === 'active'
        && entry.credential_expires_at && Date.parse(entry.credential_expires_at) <= Date.now());
      if (url.searchParams.get('resolve') !== '1') return json(res, 200, { connections: safe, resolution: 'not_checked' });
      await Promise.all(eligible.map(async (entry) => { entry.keychain_status = await checkLocalKeychainEntry(entry.storage); }));
      const available = eligible.filter((entry) => entry.keychain_status === 'present');
      const locked = eligible.some((entry) => entry.keychain_status === 'locked');
      const unavailable = eligible.some((entry) => entry.keychain_status === 'unavailable');
      const missing = eligible.some((entry) => entry.keychain_status === 'missing');
      const resolution = available.length === 1 ? 'ready' : available.length > 1 ? 'ambiguous'
        : locked ? 'keychain_locked' : unavailable ? 'unavailable_here'
          : expired.length ? 'expired' : missing ? 'missing' : 'missing';
      return json(res, 200, { connections: safe, resolution,
        ...(resolution === 'ready' ? { connection: available[0] } : {}) });
    }

    if (req.method === 'POST' && url.pathname === '/api/local/connections/verify') {
      if (!LOCAL_MODE) return json(res, 404, { error: 'not found' });
      const { isAdmin } = resolveAuth(req.headers['authorization']);
      if (!isAdmin) return json(res, 401, { error: 'unauthorized' });
      const payload = await readJson(req);
      if (!payload || typeof payload.provider !== 'string' || typeof payload.account_alias !== 'string') {
        return json(res, 400, { error: 'provider and account_alias are required' });
      }
      let entries;
      try { entries = readLocalCatalog(); }
      catch { return json(res, 503, { error: 'local catalog unavailable' }); }
      const provider = payload.provider.toLowerCase();
      const alias = payload.account_alias.toLowerCase();
      const index = entries.findIndex((entry) => String(entry.provider).toLowerCase() === provider
        && String(entry.account_alias).toLowerCase() === alias);
      if (index < 0) return json(res, 404, { error: 'connection not found' });
      const entry = entries[index];
      if (entry.state !== 'active') return json(res, 409, { verification: 'revoked' });
      if (entry.credential_expires_at && Date.parse(entry.credential_expires_at) <= Date.now()) {
        return json(res, 200, { verification: 'expired', connection_id: entry.connection_id });
      }
      let fields;
      try { fields = await (config.localCredentialReader || readLocalKeychainEntry)(entry.storage); }
      catch (error) {
        const status = error.message === 'keychain_locked' ? 'keychain_locked' : 'unavailable_here';
        return json(res, 200, { verification: status, connection_id: entry.connection_id });
      }
      const result = await (config.localCredentialVerifier || verifyLocalCredential)(provider, fields);
      const verifiedAt = new Date().toISOString();
      entry.last_verified_at = verifiedAt;
      entry.verification_status = result.status;
      entry.verified_identity = result.identity || null;
      entry.verified_permissions = result.permissions || [];
      entry.permission_evidence = result.permission_evidence || 'unknown';
      if (result.provider_expires_at && Number.isFinite(Date.parse(result.provider_expires_at))) {
        entry.credential_expires_at = new Date(result.provider_expires_at).toISOString();
        entry.expiry_status = 'provider_verified';
      }
      entry.updated_at = verifiedAt;
      try { writeLocalCatalog(entries); }
      catch { return json(res, 503, { error: 'local catalog unavailable' }); }
      console.info('[local-verify] provider=%s alias=%s outcome=%s', provider, alias, result.status);
      return json(res, 200, {
        verification: result.status,
        connection_id: entry.connection_id,
        verified_at: verifiedAt,
        identity: entry.verified_identity,
        permissions: entry.verified_permissions,
        permission_evidence: entry.permission_evidence,
        credential_expires_at: entry.credential_expires_at,
      });
    }

    // ── POST /api/session/create ───────────────────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/api/session/create') {
      const { isAdmin, integrator } = resolveAuth(req.headers['authorization']);
      if (!isAdmin && !integrator) return json(res, 401, { error: 'unauthorized' });
      const payload = await readJson(req);
      if (!payload) return json(res, 400, { error: 'bad json' });

      const { title, description, destination, destinations_by_level, ttl_minutes = 30, notify, uid, service, credential_expires_at } = payload;
      if (typeof title !== 'string' || !title.trim() || title.length > 200) {
        return json(res, 400, { error: 'missing title or fields' });
      }
      if (description != null && (typeof description !== 'string' || description.length > 2000)) {
        return json(res, 400, { error: 'description must be a string (max 2000 chars)' });
      }
      const validated = validateFields(payload.fields);
      if (validated.error) return json(res, 400, { error: validated.error });
      const fields = validated.fields;
      if (!destination && !destinations_by_level) {
        return json(res, 400, { error: 'missing destination or destinations_by_level' });
      }
      if (typeof ttl_minutes !== 'number' || !Number.isFinite(ttl_minutes)) {
        return json(res, 400, { error: 'ttl_minutes must be a number' });
      }
      if (notify != null && (typeof notify !== 'object' || Array.isArray(notify) ||
          typeof notify.tg_bot_token !== 'string' || !['string', 'number'].includes(typeof notify.tg_chat_id))) {
        return json(res, 400, { error: 'notify must be { tg_bot_token, tg_chat_id }' });
      }
      if (uid != null && (!['string', 'number'].includes(typeof uid) || String(uid).length > 128)) {
        return json(res, 400, { error: 'invalid uid' });
      }
      if (service != null && (typeof service !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(service))) {
        return json(res, 400, { error: 'invalid service: must match [a-zA-Z0-9_-]{1,64}' });
      }
      if (credential_expires_at != null && (typeof credential_expires_at !== 'string'
          || !Number.isFinite(Date.parse(credential_expires_at)) || !/^\d{4}-\d{2}-\d{2}T/.test(credential_expires_at))) {
        return json(res, 400, { error: 'credential_expires_at must be an ISO timestamp' });
      }

      // Resolve destinations_by_level if provided
      let resolvedByLevel = null;
      if (destinations_by_level) {
        if (typeof destinations_by_level !== 'object' || Array.isArray(destinations_by_level)) {
          return json(res, 400, { error: 'destinations_by_level must be an object' });
        }
        resolvedByLevel = {};
        for (const [level, dest] of Object.entries(destinations_by_level)) {
          if (level !== 'default' && !FIELD_LEVELS.includes(level)) return json(res, 400, { error: `invalid level: ${level.slice(0, 32)}` });
          const r = resolveDestination(dest, integrator, isAdmin, true);
          const err = r.error || validateDestination(r.dest, DEST_OPTS);
          if (err) return json(res, 400, { error: `${err} (level "${level}")` });
          if (r.dest.type === 'vault' && r.dest.preflight_path_prefix) return json(res, 400, { error: 'openbao_preflight_requires_single_destination' });
          resolvedByLevel[level] = r.dest;

        }
      }

      // Resolve single destination if provided
      const destinationName = typeof destination === 'string' ? destination : null;
      let resolvedDest = null;
      if (destination) {
        if (typeof destination !== 'string' && destination.type === 'vault' && destination.preflight_path_prefix) return json(res, 400, { error: 'openbao_preflight_requires_named_destination' });
        const r = resolveDestination(destination, integrator, isAdmin, true);
        const err = r.error || validateDestination(r.dest, DEST_OPTS);
        if (err) return json(res, 400, { error: err });
        resolvedDest = r.dest;

      }

      // Preflight: test destination reachability before creating the session.
      // Default: on. Opt-out with test_destination: false in the request.
      // Only runs for http_post destinations (no external service to probe for others).
      // The upstream response body is never returned — only the HTTP status.
      const preflight = await preflightDestination(resolvedDest, payload, fields);
      if (preflight?.error) return json(res, 400, preflight);


      const integrator_id = integrator?.id || 'admin';

      // Deterministic URL: integrators may pass uid + service for idempotent sessions
      const useDeterministic = integrator && uid != null && uid !== '' && service;
      if (useDeterministic && (typeof service !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(service))) {
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

      const openbaoPreflight = !!preflight?.preflight;
      const pendingDestination = resolvedDest ? { ...resolvedDest } : null;
      if (pendingDestination && openbaoPreflight) {
        for (const key of ['token', 'role_id', 'secret_id', 'preflight_metadata_token']) delete pendingDestination[key];
      }
      const pending = { token, title, description: description || '', fields,
        destination: pendingDestination,
        ...(openbaoPreflight ? { preflight: preflight.preflight } : {}),
        ...(openbaoPreflight ? {
          destination_ref: destinationName,
          destination_sha256: destinationFingerprint(resolvedDest),
        } : {}),
        destinations_by_level: resolvedByLevel,
        expires,
        notify: notify ? { tg_bot_token: notify.tg_bot_token, tg_chat_id: notify.tg_chat_id } : null,

        integrator_id,
        _audit_auth: integrator ? 'integrator' : isAdmin ? 'admin' : 'anonymous',
        requester: integrator ? String(integrator.name || integrator.id).slice(0, 100) : null,
        uid: uid != null ? String(uid) : null,
        ...(service ? { service_slug: service } : {}),
        ...(credential_expires_at ? { credential_expires_at: new Date(credential_expires_at).toISOString() } : {}),
        ...(useDeterministic ? { service_slug, user_hash, integrator_slug: integrator_id } : {}),
      };
      fs.mkdirSync(CONNECT_PENDING_DIR, { recursive: true, mode: 0o700 });
      fs.writeFileSync(pendingPath(token), JSON.stringify(pending), { mode: 0o600 });
      console.info('[session-migration] created auth=%s destination=%s', pending._audit_auth,
        destinationName ? 'named' : 'inline');

      const url_out = useDeterministic
        ? `${BASE_URL}/${integrator_id}/${service_slug}/${user_hash}?gen=${token}`
        : `${BASE_URL}/f/${token}`;
      return json(res, 200, {
        token,
        url: url_out,
        expires_at: new Date(expires).toISOString(),
      });
    }

    // ── GET /.well-known/zerocreds-signing-key ─────────────────────────────────
    // Public key that verifies form manifests and submission receipts.
    if (req.method === 'GET' && url.pathname === '/.well-known/zerocreds-signing-key') {
      return json(res, 200, { alg: 'Ed25519', key_id: SIGNING_KEY.keyId, public_key_pem: SIGNING_KEY.publicKeyPem });
    }

    // Wallet form API: a host-issued token pins owner/profile and the OpenBao
    // writer. The agent supplies only the requested credential shape.
    if (req.method === 'POST' && url.pathname === '/api/wallet/forms') {
      const scope = await walletScope(req.headers.authorization, 'wallet.forms.create');
      if (!scope) return json(res, 401, { error: 'unauthorized' });
      const payload = await readJson(req);
      if (!payload) return json(res, 400, { error: 'bad json' });
      const { provider, kind = 'token', title, description, ttl_minutes = 30, idempotency_key } = payload;
      if (typeof provider !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(provider)
        || !Object.hasOwn(FORM_KINDS, kind) || (title !== undefined && (typeof title !== 'string' || !title.trim() || title.length > 200))
        || (description !== undefined && (typeof description !== 'string' || description.length > 2000))
        || !Number.isInteger(ttl_minutes) || ttl_minutes < 1 || ttl_minutes > 1440
        || (idempotency_key !== undefined && (typeof idempotency_key !== 'string' || !/^[a-zA-Z0-9_-]{16,128}$/.test(idempotency_key)))
      ) return json(res, 400, { error: 'invalid wallet form' });
      const validated = validateFields(payload.fields === undefined ? FORM_KINDS[kind] : payload.fields);
      if (validated.error) return json(res, 400, { error: validated.error });
      const requestFingerprint = sha256Hex(canonicalJson({ provider, kind,
        title: title || `Connect ${provider}`, description: description || '',
        fields: validated.fields, ttl_minutes }));
      let allocation, destination;
      try {
        allocation = await walletCall('POST', '/internal/connections/allocate', {
          owner_id: scope.owner_id, profile_id: scope.profile_id, provider,
          idempotency_key: idempotency_key || crypto.randomBytes(24).toString('hex'),
        });
        if (allocation.state !== 'allocated') return json(res, 409, { error: 'connection_already_used' });
        for (const file of fs.readdirSync(CONNECT_PENDING_DIR)) {
          if (!file.endsWith('.json')) continue;
          let previous;
          try { previous = JSON.parse(fs.readFileSync(path.join(CONNECT_PENDING_DIR, file), 'utf8')); } catch { continue; }
          if (previous.wallet?.connection_id !== allocation.connection_id) continue;
          if (previous.wallet.owner_id !== scope.owner_id || previous.wallet.profile_id !== scope.profile_id
            || previous.wallet.request_fingerprint !== requestFingerprint || previous.expires < Date.now()) {
            return json(res, 409, { error: 'wallet_form_conflict' });
          }
          return json(res, 200, { form_id: previous.token, connection_id: allocation.connection_id,
            url: `${BASE_URL}/f/${previous.token}`,
            status_url: `${BASE_URL}/api/wallet/forms/${previous.token}/status`,
            expires_at: new Date(previous.expires).toISOString(), state: 'pending' });
        }
        destination = walletDestination(scope, allocation.openbao_path);
        const destErr = validateDestination(destination, DEST_OPTS);
        if (destErr) return json(res, 503, { error: 'wallet destination unavailable' });
      } catch (e) {
        console.error('[wallet] allocation failed:', e.message);
        return json(res, 503, { error: 'wallet unavailable' });
      }
      const preflight = await preflightDestination(destination, payload, validated.fields);
      if (preflight?.error) return json(res, 503, { error: 'wallet destination unavailable' });
      const formId = crypto.randomBytes(16).toString('hex');
      const submitToken = 'zcs_' + crypto.randomBytes(24).toString('hex');
      const expires = Date.now() + ttl_minutes * 60_000;
      const pending = {
        token: formId, title: title || `Connect ${provider}`, description: description || '',
        fields: validated.fields, destination: Object.fromEntries(Object.entries(destination)
          .filter(([key]) => !['token', 'role_id', 'secret_id', 'preflight_metadata_token'].includes(key))),
        preflight: preflight.preflight, destinations_by_level: null, expires, notify: null,
        integrator_id: `wallet_${scope.owner_id}`, requester: String(scope.requester || 'ServerlessAgence').slice(0, 100),
        uid: null, form: { name: provider, kind, handle: `cred:${provider}`,
          submit_token_hash: tokenHash(submitToken).toString('hex') },
        wallet: { owner_id: scope.owner_id, profile_id: scope.profile_id,
          connection_id: allocation.connection_id, openbao_path: allocation.openbao_path,
          request_fingerprint: requestFingerprint,
          destination: scope.destination,
          destination_sha256: destinationFingerprint(NAMED_DESTINATIONS[scope.destination]) },
      };
      const manifest = signedManifest(formId, pending);
      pending.form.manifest_id = manifest.manifest_id;
      try {
        await walletCall('POST', '/internal/forms', {
          form_id: formId, connection_id: allocation.connection_id,
          owner_id: scope.owner_id, profile_id: scope.profile_id,
          manifest_id: manifest.manifest_id, expires_at: expires,
        });
        fs.writeFileSync(pendingPath(formId), JSON.stringify(pending), { mode: 0o600, flag: 'wx' });
      } catch (e) {
        console.error('[wallet] form registration failed:', e.message);
        return json(res, 503, { error: 'wallet unavailable' });
      }
      return json(res, 200, { form_id: formId, connection_id: allocation.connection_id,
        url: `${BASE_URL}/f/${formId}`, status_url: `${BASE_URL}/api/wallet/forms/${formId}/status`,
        expires_at: new Date(expires).toISOString(), state: 'pending' });
    }

    const walletStatus = /^\/api\/wallet\/forms\/([a-f0-9]{32})\/status$/.exec(url.pathname);
    if (walletStatus && req.method === 'GET') {
      const scope = await walletScope(req.headers.authorization, 'wallet.forms.status');
      if (!scope) return json(res, 401, { error: 'unauthorized' });
      const formId = walletStatus[1];
      let pending = readPending(formId);
      if (!pending) {
        try { pending = JSON.parse(fs.readFileSync(pendingPath(formId, 'claimed'), 'utf8')); } catch {}
      }
      let done;
      try { done = JSON.parse(fs.readFileSync(pendingPath(formId, 'done'), 'utf8')); } catch {}
      const wallet = pending?.wallet;
      if (wallet && (wallet.owner_id !== scope.owner_id || wallet.profile_id !== scope.profile_id)) {
        return json(res, 404, { error: 'form_unavailable' });
      }
      const connectionId = wallet?.connection_id || done?.connection_id;
      if (!connectionId) return json(res, 404, { error: 'form_unavailable' });
      try {
        const connection = await walletCall('GET', `/internal/connections/${connectionId}`, null, scope);
        return json(res, 200, { form_id: formId, connection_id: connectionId,
          status: connection.state === 'revoked' ? 'revoked' : done ? 'done'
            : pending.expires < Date.now() ? 'expired' : 'pending',
          ...(done ? { kv_version: done.version, receipt_ref: done.receipt_ref } : {}) });
      } catch { return json(res, 503, { error: 'wallet unavailable' }); }
    }

    const walletConnection = /^\/api\/wallet\/connections\/([a-zA-Z0-9_-]{1,100})(\/revoke)?$/.exec(url.pathname);
    if (walletConnection && (req.method === 'GET' && !walletConnection[2]
      || req.method === 'POST' && walletConnection[2])) {
      const scope = await walletScope(req.headers.authorization,
        req.method === 'POST' ? 'wallet.connections.revoke' : 'wallet.connections.status');
      if (!scope) return json(res, 401, { error: 'unauthorized' });
      try {
        const connectionId = walletConnection[1];
        if (req.method === 'POST') {
          const result = await walletCall('POST', `/internal/connections/${connectionId}/revoke`, {
            owner_id: scope.owner_id, profile_id: scope.profile_id,
          });
          return json(res, 200, { connection_id: result.connection_id, state: result.state });
        }
        const result = await walletCall('GET', `/internal/connections/${connectionId}`, null, scope);
        return json(res, 200, { connection_id: result.connection_id, provider: result.provider,
          state: result.state, kv_version: result.kv_version, updated_at: result.updated_at });
      } catch (e) {
        return json(res, e.status === 404 ? 404 : 503,
          { error: e.status === 404 ? 'connection_unavailable' : 'wallet unavailable' });
      }
    }

    // ── POST /api/forms — form spec ────────────────────────────────────────────
    // One spec, two ways in: the human URL (/f/{form_id}) and the machine endpoint
    // (/api/forms/{form_id}/submit). Same auth, validation and destination rules as sessions.
    if (req.method === 'POST' && url.pathname === '/api/forms') {
      const { isAdmin, integrator } = resolveAuth(req.headers['authorization']);
      if (!isAdmin && !integrator) return json(res, 401, { error: 'unauthorized' });
      const payload = await readJson(req);
      if (!payload) return json(res, 400, { error: 'bad json' });

      const { name, kind = 'token', title, description, destination, ttl_minutes = 30 } = payload;
      if (typeof name !== 'string' || !HANDLE_NAME_RE.test(name)) {
        return json(res, 400, { error: 'name must match [a-z0-9][a-z0-9_.-]{0,63} (it becomes the handle cred:<name>)' });
      }
      if (typeof kind !== 'string' || !Object.hasOwn(FORM_KINDS, kind)) {
        return json(res, 400, { error: `kind must be one of: ${Object.keys(FORM_KINDS).join(', ')}` });
      }
      if (title !== undefined && (typeof title !== 'string' || !title.trim() || title.length > 200)) {
        return json(res, 400, { error: 'title must be a non-empty string (max 200 chars)' });
      }
      if (description != null && (typeof description !== 'string' || description.length > 2000)) {
        return json(res, 400, { error: 'description must be a string (max 2000 chars)' });
      }
      const validated = validateFields(payload.fields === undefined ? FORM_KINDS[kind] : payload.fields);
      if (validated.error) return json(res, 400, { error: validated.error });
      if (destination === undefined || destination === null || destination === '') {
        return json(res, 400, { error: 'missing destination' });
      }
      if (typeof ttl_minutes !== 'number' || !Number.isFinite(ttl_minutes)) {
        return json(res, 400, { error: 'ttl_minutes must be a number' });
      }
      const r = resolveDestination(destination, integrator, isAdmin);
      const destErr = r.error || validateDestination(r.dest, DEST_OPTS);
      if (destErr) return json(res, 400, { error: destErr });
      if (typeof destination !== 'string' && r.dest.type === 'vault' && r.dest.preflight_path_prefix) {
        return json(res, 400, { error: 'openbao_preflight_requires_named_destination' });
      }
      const preflight = await preflightDestination(r.dest, payload, validated.fields);
      if (preflight?.error) return json(res, 400, preflight);

      const formId = crypto.randomBytes(16).toString('hex');
      const submitToken = 'zcs_' + crypto.randomBytes(24).toString('hex');
      const pending = {
        token: formId,
        title: title || `Save ${name}`,
        description: description || '',
        fields: validated.fields,
        destination: preflight?.preflight ? Object.fromEntries(Object.entries(r.dest).filter(([k]) => !['token', 'role_id', 'secret_id', 'preflight_metadata_token'].includes(k))) : r.dest,
        ...(preflight?.preflight ? {
          preflight: preflight.preflight,
          destination_ref: destination,
          destination_sha256: destinationFingerprint(r.dest),
        } : {}),
        destinations_by_level: null,
        expires: Date.now() + Math.min(Math.max(ttl_minutes, 1), 1440) * 60 * 1000,
        notify: null,
        integrator_id: integrator?.id || 'admin',
        requester: integrator ? String(integrator.name || integrator.id).slice(0, 100) : null,
        uid: null,
        form: { name, kind, handle: `cred:${name}`, submit_token_hash: tokenHash(submitToken).toString('hex') },
      };
      const manifest = signedManifest(formId, pending);
      pending.form.manifest_id = manifest.manifest_id;
      fs.mkdirSync(CONNECT_PENDING_DIR, { recursive: true, mode: 0o700 });
      fs.writeFileSync(pendingPath(formId), JSON.stringify(pending), { mode: 0o600 });

      return json(res, 200, {
        form_id: formId,
        handle: pending.form.handle,
        url: `${BASE_URL}/f/${formId}`,
        submit_url: `${BASE_URL}/api/forms/${formId}/submit`,
        status_url: `${BASE_URL}/api/session/${formId}/status`,
        submit_token: submitToken,
        expires_at: new Date(pending.expires).toISOString(),
        manifest,
        api_example: formApiSnippets(formId, pending, BASE_URL),
      });
    }

    // ── POST /api/forms/:id/submit — machine submit ────────────────────────────
    // Auth: the owner's key (the integrator that created the form, or admin) or the
    // form's one-time submit token. Returns the same signed receipt as the human form.
    const formSubmitMatch = url.pathname.match(/^\/api\/forms\/([a-f0-9]{32})\/submit$/);
    if (formSubmitMatch && req.method === 'POST') {
      const formId = formSubmitMatch[1];
      const pending = readPending(formId);
      if (!pending?.form || !Array.isArray(pending.fields)) return json(res, 404, { error: 'invalid or expired form' });

      const authHeader = req.headers['authorization'];
      const bearer = typeof authHeader === 'string' && authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
      const { isAdmin, integrator } = resolveAuth(authHeader);
      const isOwner = isAdmin || (integrator !== null && integrator.id === pending.integrator_id);
      const hasSubmitToken = SUBMIT_TOKEN_RE.test(bearer) &&
        crypto.timingSafeEqual(tokenHash(bearer), Buffer.from(String(pending.form.submit_token_hash), 'hex'));
      if (!isOwner && !hasSubmitToken) return json(res, 401, { error: 'owner key or submit token required' });

      if (pending.expires < Date.now()) { deletePending(formId); return json(res, 404, { error: 'invalid or expired form' }); }
      const payload = await readJson(req);
      if (!payload) return json(res, 400, { error: 'bad json' });
      if (payload.manifest_id !== undefined && payload.manifest_id !== pending.form.manifest_id) {
        return json(res, 409, { error: 'manifest_id does not match this form' });
      }
      const result = await submitPending(formId, pending, payload.fields, 'api');
      return json(res, result.status, result.body);
    }

    // ── GET /api/session/:token/status ─────────────────────────────────────────
    // Integrators only see their own sessions; anything else looks like an unknown token.
    const statusMatch = url.pathname.match(/^\/api\/session\/([a-f0-9]{32})\/status$/);
    if (statusMatch && req.method === 'GET') {
      const { isAdmin, integrator } = resolveAuth(req.headers['authorization']);
      if (!isAdmin && !integrator) return json(res, 401, { error: 'unauthorized' });
      const token = statusMatch[1];
      const owns = (ownerId) => isAdmin || (ownerId !== undefined && ownerId === integrator.id);

      const doneFile = pendingPath(token, 'done');
      if (fs.existsSync(doneFile)) {
        let doneData = {};
        try { doneData = JSON.parse(fs.readFileSync(doneFile, 'utf8')); } catch {}
        const { _integrator_id, ...result } = doneData;
        // Old .done markers predate owner recording. Their 128-bit URL token was
        // the status capability; keep that contract for pre-existing keys only.
        const legacyDone = _integrator_id === undefined && isLegacyIntegrator(integrator);
        if (!owns(_integrator_id) && !legacyDone) return json(res, 200, { status: 'expired' });
        return json(res, 200, { status: 'done', ...result });
      }
      let p = readPending(token);
      if (!p) {
        try { p = JSON.parse(fs.readFileSync(pendingPath(token, 'claimed'), 'utf8')); } catch {}
      }
      if (!p || !owns(p.integrator_id) || p.expires < Date.now()) return json(res, 200, { status: 'expired' });
      return json(res, 200, { status: 'pending' });
    }

    // ── GET /api/destinations ──────────────────────────────────────────────────
    if (url.pathname === '/api/destinations' && req.method === 'GET') {
      const { isAdmin, integrator } = resolveAuth(req.headers['authorization']);
      if (!isAdmin && !integrator) return json(res, 401, { error: 'unauthorized' });
      // Build destinations map: only expose type (no credentials)
      const adminDests = {};
      for (const [name, dest] of Object.entries(NAMED_DESTINATIONS)) {
        adminDests[name] = { type: dest?.type };
      }
      if (isAdmin) {
        return json(res, 200, { destinations: adminDests });
      }
      // Integrator: merge admin destinations with integrator's own (integrator overrides)
      const merged = { ...adminDests };
      for (const [name, dest] of Object.entries(integrator.destinations)) {
        merged[name] = { type: dest?.type };
      }
      return json(res, 200, { destinations: merged });
    }

    // ── /f/:token — dynamic form ───────────────────────────────────────────────
    const dynMatch = url.pathname.match(/^\/f\/([a-f0-9]{32})$/);
    if (dynMatch) {
      const token = dynMatch[1];

      if (req.method === 'GET') {
        const pending = readPending(token);
        if (!pending || !pending.fields) return sendHtml(res, 404, expiredHtml());
        if (pending.expires < Date.now()) return sendHtml(res, 410, expiredHtml());
        return renderDynamicForm(res, req, token, pending);
      }

      if (req.method === 'POST') {
        const payload = await readJson(req);
        if (!payload) return json(res, 400, { error: 'bad json' });
        const { t, fields: submitted } = payload;
        if (typeof t !== 'string' || !submitted || typeof submitted !== 'object' || Array.isArray(submitted)) {
          return json(res, 400, { error: 'missing t or fields' });
        }
        if (t !== token) return json(res, 400, { error: 'token mismatch' });

        const pending = readPending(token);
        if (!pending || !Array.isArray(pending.fields)) return json(res, 403, { error: 'invalid or expired token' });
        if (pending.expires < Date.now()) { deletePending(token); return json(res, 403, { error: 'link expired' }); }

        const r = await submitPending(token, pending, submitted, 'form');
        return json(res, r.status, r.body);

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
      if (gen && TOKEN_RE.test(gen)) {
        pending = readPending(gen);
        if (!pending || pending.integrator_slug !== slug || pending.service_slug !== svc || pending.user_hash !== hash) {
          return sendHtml(res, 404, expiredHtml());
        }
      } else {
        pending = findActiveSession(slug, svc, hash);
        if (pending) {
          res.writeHead(302, { Location: `${BASE_URL}/${slug}/${svc}/${hash}?gen=${pending.token}`, 'Cache-Control': 'no-store' }).end();
          return;
        }
      }

      if (!pending || !pending.fields) return sendHtml(res, 404, expiredHtml());
      if (pending.expires < Date.now()) return sendHtml(res, 410, expiredHtml());
      if (!TOKEN_RE.test(String(pending.token))) return sendHtml(res, 404, expiredHtml());

      return renderDynamicForm(res, req, pending.token, pending);
    }

    json(res, 404, { error: 'not found' });
  }

  // Any exception inside a request becomes a 500 for that request — never a process crash.
  const server = http.createServer((req, res) => {
    handle(req, res).catch(err => {
      if (err instanceof HttpError) {
        if (!res.headersSent) json(res, err.status, { error: err.message }, { Connection: 'close' });
        return;
      }
      console.error('[server] request failed:', err?.stack || err);
      if (!res.headersSent) json(res, 500, { error: 'internal error' });
      else res.destroy();
    });
  });

  sweepPending();
  const sweepTimer = setInterval(() => sweepPending(), SWEEP_INTERVAL_MS);
  sweepTimer.unref();
  server.on('close', () => clearInterval(sweepTimer));
  server.sweepPending = sweepPending;

  return server;
}

// ── Entry point ───────────────────────────────────────────────────────────────

if (require.main === module) {
  process.on('unhandledRejection', (reason) => {
    console.error('[server] unhandled rejection:', reason?.stack || reason);
  });
  const PORT = process.env.PORT || 3456;
  let server;
  try {
    server = createApp();
  } catch (e) {
    console.error(`[server] ${e.message}`);
    process.exit(1);
  }
  const onListening = () => {
    const addr = server.address();
    console.log(`zerocreds-server v${VERSION} (${COMMIT}) listening on :${addr.port}`);
  };
  if (process.env.ZEROCREDS_LOCAL_MODE === '1') server.listen(PORT, '127.0.0.1', onListening);
  else server.listen(PORT, onListening);
  const shutdown = () => {
    server.close(() => process.exit(0));
    try { require('./nalog-login').closeAll(); } catch {}
    setTimeout(() => process.exit(0), 10_000).unref();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

module.exports = { createApp };
