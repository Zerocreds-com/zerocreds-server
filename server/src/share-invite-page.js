'use strict';

// This page deliberately has no JavaScript: the bearer code stays in the URL
// fragment and is never read by a page script or sent with an HTTP request.
function shareInvitePage() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Receive a credential · ZeroCreds</title>
<style>
  :root{color-scheme:light dark;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
  *{box-sizing:border-box}body{min-height:100vh;min-height:100dvh;margin:0;padding:28px 16px;display:grid;place-items:center;background:radial-gradient(circle at 50% 0%,#dbeafe 0,#f4f7fc 45%,#eef2f8 100%);color:#172033}
  main{width:min(100%,520px);padding:32px;border:1px solid #dce4f0;border-radius:20px;background:#fff;box-shadow:0 20px 60px -30px #33415566}
  .brand{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:750;color:#25304d;letter-spacing:.01em}.mark{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;background:linear-gradient(135deg,#4f46e5,#0ea5e9);color:white;font-size:17px}
  .eyebrow{margin:30px 0 8px;color:#4338ca;font-size:12px;font-weight:800;letter-spacing:.1em;text-transform:uppercase}h1{margin:0;font-size:clamp(26px,5vw,32px);line-height:1.2;letter-spacing:-.035em}p{line-height:1.55;color:#526078}.intro{margin:14px 0 24px}
  ol{counter-reset:steps;list-style:none;padding:0;margin:0}li{position:relative;padding:0 0 20px 46px;min-height:46px;line-height:1.5}li:last-child{padding-bottom:0}li:before{counter-increment:steps;content:counter(steps);position:absolute;left:0;top:0;width:30px;height:30px;border-radius:10px;background:#eef2ff;color:#4338ca;display:grid;place-items:center;font-weight:800;font-size:14px}
  .note{margin-top:24px;padding:14px 16px;border-radius:12px;background:#f7f9fd;border:1px solid #e3e9f3;color:#43516b;font-size:13px;line-height:1.5}.note strong{color:#25304d}a{color:#4338ca;text-underline-offset:3px}footer{margin-top:24px;font-size:12px;color:#69758b}
  @media(prefers-color-scheme:dark){body{background:radial-gradient(circle at 50% 0%,#1c2750 0,#0d1220 55%);color:#f3f6ff}main{background:#171e2f;border-color:#2c3955;box-shadow:0 20px 60px -30px #000}p{color:#a9b6d0}.brand,.note strong{color:#e9efff}.eyebrow,a{color:#a5b4fc}li:before{background:#252c50;color:#c7d2fe}.note{background:#1d263b;border-color:#2c3955;color:#b7c3d9}footer{color:#8c9bb5}}
</style></head><body><main>
  <div class="brand"><span class="mark" aria-hidden="true">◆</span>ZeroCreds</div>
  <div class="eyebrow">Private one-time transfer</div>
  <h1>A credential is ready for you</h1>
  <p class="intro">Your colleague shared a credential through an encrypted invitation. To save it on your computer:</p>
  <ol><li><a href="https://github.com/Zerocreds-com/zerocreds-server/blob/main/docs/local-mac-setup.md" rel="noreferrer">Install local ZeroCreds</a> if you have not already.</li>
  <li>Copy the <strong>entire address from your browser’s address bar</strong>, including the part after <code>#</code>.</li>
  <li>Paste it into your agent and ask it to receive the credential with ZeroCreds. It will be saved directly in your Keychain.</li></ol>
  <div class="note"><strong>Keep the full link private.</strong> It works once and expires soon. Your colleague’s computer must remain online until you finish. Neither agent needs to display the credential value.</div>
  <footer>If the claim fails, ask your colleague for a new invitation.</footer>
</main></body></html>`;
}

module.exports = { shareInvitePage };
