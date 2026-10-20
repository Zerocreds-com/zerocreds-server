'use strict';

// This page deliberately has no JavaScript: the bearer code stays in the URL
// fragment and is never read by a page script or sent with an HTTP request.
function shareInvitePage(acceptLanguage = '') {
  const preferredLanguage = acceptLanguage.split(',').map((part, index) => {
    const [tag, ...parameters] = part.trim().toLowerCase().split(';');
    const q = parameters.map(value => value.trim().match(/^q=(0(?:\.\d+)?|1(?:\.0+)?)$/)?.[1])
      .find(value => value !== undefined);
    return { tag, quality: q === undefined ? 1 : Number(q), index };
  }).filter(item => item.quality > 0).sort((a, b) => b.quality - a.quality || a.index - b.index)[0]?.tag;
  const russian = preferredLanguage === 'ru' || preferredLanguage?.startsWith('ru-');
  const copy = russian ? {
    lang: 'ru', title: 'Получить доступ · ZeroCreds', eyebrow: 'Защищённая одноразовая передача',
    heading: 'Коллега поделился с вами доступом',
    intro: 'Чтобы сохранить доступ на своём компьютере:',
    install: 'Установите локальный ZeroCreds, если ещё не сделали этого.',
    copy: 'Скопируйте полный адрес из строки браузера, включая часть после символа #.',
    paste: 'Вставьте адрес в свой ИИ-агент и попросите его получить доступ, которым поделился коллега, через ZeroCreds. Доступ сохранится в приложении «Связка ключей» на вашем Mac.',
    keep: 'Не пересылайте эту ссылку другим. Ею можно воспользоваться один раз, и срок её действия скоро закончится.',
    online: 'Компьютер коллеги должен оставаться включённым и подключённым к интернету, пока вы сохраняете доступ.',
    private: 'Ссылка даёт право получить доступ. Сам секрет не показывается агентам.',
    failed: 'Если получить доступ не получится, попросите коллегу создать новую ссылку.',
  } : {
    lang: 'en', title: 'Receive access · ZeroCreds', eyebrow: 'Private one-time transfer',
    heading: 'Your colleague shared access with you',
    intro: 'To save this access on your computer:',
    install: 'Install local ZeroCreds if you have not already.',
    copy: 'Copy the full address from your browser, including everything after #.',
    paste: 'Paste it into your AI agent and ask it to receive the access your colleague shared with you through ZeroCreds. It will be saved directly in your Mac Keychain.',
    keep: 'Keep this link private. It can be used once and expires soon.',
    online: 'Your colleague’s computer must stay on and connected to the internet while you save the access.',
    private: 'The link grants access. The secret itself is never shown to either agent.',
    failed: 'If receiving the access fails, ask your colleague for a new link.',
  };
  return `<!doctype html>
<html lang="${copy.lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>${copy.title}</title>
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
  <div class="eyebrow">${copy.eyebrow}</div>
  <h1>${copy.heading}</h1>
  <p class="intro">${copy.intro}</p>
  <ol><li><a href="https://github.com/Zerocreds-com/zerocreds-server/blob/main/docs/local-mac-setup.md" rel="noreferrer">${copy.install}</a></li>
  <li>${copy.copy}</li>
  <li>${copy.paste}</li></ol>
  <div class="note"><strong>${copy.keep}</strong> ${copy.online} ${copy.private}</div>
  <footer>${copy.failed}</footer>
</main></body></html>`;
}

module.exports = { shareInvitePage };
