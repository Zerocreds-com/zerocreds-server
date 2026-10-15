#!/usr/bin/env node
'use strict';
// Renders the dynamic form (/f/:token) in Playwright Chromium and saves screenshots:
// desktop + 375px mobile, light + dark (via prefers-color-scheme emulation).
// Usage: node scripts/form-screenshots.js [outDir] [prefix]
//   (needs a browser: npx playwright install chromium, or PW_CHANNEL=chrome to use installed Chrome)
const fs = require('fs');
const os = require('os');
const path = require('path');
const { chromium } = require('playwright');
const { createApp } = require('../src/server');

const outDir = path.resolve(process.argv[2] || path.join(__dirname, '../../docs/screenshots'));
const prefix = process.argv[3] || 'form';

const SESSION = {
  title: 'Connect your GitHub account',
  description: 'Paste a fine-grained token. It goes straight into your secret store — the AI assistant never sees it.',
  fields: [
    { name: 'login', label: 'GitHub username', placeholder: 'octocat', level: 'attribute' },
    { name: 'email', label: 'Email', type: 'email', placeholder: 'you@example.com', level: 'pii' },
    { name: 'token', label: 'Personal access token', type: 'password', placeholder: 'github_pat_…', level: 'secret' },
    { name: 'note', label: 'Note for the agent', type: 'textarea', placeholder: 'Optional context', required: false },
  ],
  destination: { type: 'local_file', uid: 'demo', filename: 'github' },
};

const SHOTS = [
  { name: 'desktop-light', viewport: { width: 1280, height: 900 }, colorScheme: 'light' },
  { name: 'desktop-dark', viewport: { width: 1280, height: 900 }, colorScheme: 'dark' },
  { name: 'mobile-light', viewport: { width: 375, height: 812 }, colorScheme: 'light', isMobile: true, hasTouch: true },
  { name: 'mobile-dark', viewport: { width: 375, height: 812 }, colorScheme: 'dark', isMobile: true, hasTouch: true },
];

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zc-shots-'));
  for (const d of ['pending', 'tokens', 'saved']) fs.mkdirSync(path.join(tmp, d));
  fs.writeFileSync(path.join(tmp, 'destinations.json'), '{}');
  fs.writeFileSync(path.join(tmp, 'integrators.json'), '{}');
  const adminToken = 'shots-admin';
  const server = createApp({
    adminToken,
    pendingDir: path.join(tmp, 'pending'), tokensDir: path.join(tmp, 'tokens'),
    allowInlineDestinations: true, // local demo session with an inline local_file destination
    destinationsFile: path.join(tmp, 'destinations.json'), integratorsFile: path.join(tmp, 'integrators.json'),
    baseUrl: 'http://localhost',
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch(process.env.PW_CHANNEL ? { channel: process.env.PW_CHANNEL } : {});
  try {
    for (const shot of SHOTS) {
      // One-time links: a fresh session per screenshot.
      const r = await fetch(`${base}/api/session/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify(SESSION),
      });
      const { token } = await r.json();
      const { name, ...ctxOpts } = shot;
      const ctx = await browser.newContext({ ...ctxOpts, deviceScaleFactor: 2 });
      const page = await ctx.newPage();
      await page.goto(`${base}/f/${token}`);
      await page.fill('#f_login', 'octocat');
      const file = path.join(outDir, `${prefix}-${name}.png`);
      await page.screenshot({ path: file });
      console.log(file);
      await ctx.close();
    }
  } finally {
    await browser.close();
    server.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

main().catch(e => { console.error(e); process.exit(1); });
