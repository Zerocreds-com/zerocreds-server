'use strict';

const crypto = require('node:crypto');
const net = require('node:net');

const ID = /^[a-f0-9]{32}$/;
const TOKEN = /^[a-f0-9]{64}$/;
const KEY = /^[A-Za-z0-9+/]{55,256}={0,2}$/;
const MAX_SESSIONS = 100;
const MAX_PER_IP = 5;
const MAX_BODY = 96 * 1024;

function answer(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', chunk => {
      total += chunk.length;
      if (total > MAX_BODY) { req.destroy(); reject(new Error('body too large')); }
      else chunks.push(chunk);
    });
    req.once('end', () => {
      try {
        const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('bad json');
        resolve(value);
      } catch { reject(new Error('bad json')); }
    });
    req.once('error', reject);
  });
}

function equalToken(a, b) {
  return typeof a === 'string' && TOKEN.test(a) && crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

function createShareRelay({ clientIp } = {}) {
  const sessions = new Map();
  const now = () => Date.now();
  const cleanup = () => {
    for (const [id, item] of sessions) if (item.expires <= now() || item.state === 'complete' && item.completedAt + 60000 <= now()) sessions.delete(id);
  };
  const timer = setInterval(cleanup, 30000);
  timer.unref();
  const stop = () => clearInterval(timer);

  async function handle(req, res, url) {
    if (req.method === 'GET' && /^\/api\/share-relay\/invite\/[a-f0-9]{32}$/.test(url.pathname)) return false;
    if (!url.pathname.startsWith('/api/share-relay/') && url.pathname !== '/share') return false;
    if (url.pathname === '/api/share-relay/sessions' && req.method === 'POST') {
      let body;
      try { body = await readBody(req); } catch { answer(res, 400, { error: 'bad request' }); return true; }
      if (!ID.test(body.id || '') || !TOKEN.test(body.owner_token || '')
          || !Number.isInteger(body.ttl_minutes) || body.ttl_minutes < 1 || body.ttl_minutes > 120) {
        answer(res, 400, { error: 'invalid session' }); return true;
      }
      cleanup();
      const ip = clientIp ? clientIp(req) : req.socket.remoteAddress || 'unknown';
      if (!net.isIP(ip)) { answer(res, 400, { error: 'invalid client address' }); return true; }
      if (sessions.size >= MAX_SESSIONS || [...sessions.values()].filter(item => item.ip === ip).length >= MAX_PER_IP) {
        answer(res, 429, { error: 'relay capacity reached' }); return true;
      }
      if (sessions.has(body.id)) { answer(res, 409, { error: 'session exists' }); return true; }
      const expires = now() + body.ttl_minutes * 60000;
      sessions.set(body.id, { id: body.id, ownerToken: body.owner_token, ip, expires,
        state: 'pending', claim: null, attempts: 0 });
      answer(res, 201, { share_id: body.id, expires_at: new Date(expires).toISOString() });
      return true;
    }
    const deleteMatch = url.pathname.match(/^\/api\/share-relay\/sessions\/([a-f0-9]{32})$/);
    if (deleteMatch && req.method === 'DELETE') {
      const item = sessions.get(deleteMatch[1]);
      if (!item || item.expires <= now()) { answer(res, 410, { error: 'share unavailable' }); return true; }
      const bearer = /^Bearer ([a-f0-9]{64})$/.exec(String(req.headers.authorization || ''))?.[1];
      if (!equalToken(bearer, item.ownerToken)) { answer(res, 401, { error: 'unauthorized' }); return true; }
      sessions.delete(deleteMatch[1]);
      answer(res, 200, { status: 'cancelled' });
      return true;
    }
    const match = url.pathname.match(/^\/api\/share-relay\/sessions\/([a-f0-9]{32})\/(poll|claim|reject|envelope|ack)$/);
    if (!match) { answer(res, 404, { error: 'not found' }); return true; }
    const item = sessions.get(match[1]);
    if (!item || item.expires <= now()) { answer(res, 410, { error: 'share unavailable' }); return true; }
    const action = match[2];
    const bearer = /^Bearer ([a-f0-9]{64})$/.exec(String(req.headers.authorization || ''))?.[1];
    if (action === 'claim' && req.method === 'POST') {
      if (item.state !== 'pending') {
        answer(res, 409, { error: 'claim unavailable' }); return true;
      }
      let body;
      try { body = await readBody(req); } catch { answer(res, 400, { error: 'bad request' }); return true; }
      if (!KEY.test(body.public_key || '') || !TOKEN.test(body.proof || '')) {
        answer(res, 400, { error: 'invalid claim' }); return true;
      }
      if (item.claim && item.claim.state !== 'rejected') {
        if (item.claim.publicKey === body.public_key && item.claim.proof === body.proof) {
          answer(res, 200, { claim_id: item.claim.id, claim_token: item.claim.token });
        } else answer(res, 409, { error: 'claim unavailable' });
        return true;
      }
      if (++item.attempts > 5) { answer(res, 429, { error: 'too many claims' }); return true; }
      item.claim = { id: crypto.randomBytes(16).toString('hex'), token: crypto.randomBytes(32).toString('hex'),
        publicKey: body.public_key, proof: body.proof, envelope: null, state: 'pending' };
      answer(res, 200, { claim_id: item.claim.id, claim_token: item.claim.token });
      return true;
    }
    if (['poll', 'reject'].includes(action) || action === 'envelope' && req.method === 'POST') {
      if (!equalToken(bearer, item.ownerToken)) { answer(res, 401, { error: 'unauthorized' }); return true; }
    }
    if (action === 'poll' && req.method === 'GET') {
      answer(res, 200, item.state === 'complete' ? { status: 'complete' }
        : item.claim ? { status: item.claim.state, claim_id: item.claim.id,
          public_key: item.claim.publicKey, proof: item.claim.proof } : { status: 'pending' });
      return true;
    }
    if (action === 'reject' && req.method === 'POST') {
      let body;
      try { body = await readBody(req); } catch { answer(res, 400, { error: 'bad request' }); return true; }
      if (!item.claim || body.claim_id !== item.claim.id) { answer(res, 409, { error: 'claim changed' }); return true; }
      item.claim.state = 'rejected';
      answer(res, 200, { status: 'rejected' });
      return true;
    }
    if (action === 'envelope' && req.method === 'POST') {
      let body;
      try { body = await readBody(req); } catch { answer(res, 400, { error: 'bad request' }); return true; }
      if (!item.claim || body.claim_id !== item.claim.id || item.claim.state !== 'pending'
          || !body.envelope || typeof body.envelope !== 'object' || Array.isArray(body.envelope)
          || !['sender_key', 'iv', 'ciphertext', 'tag'].every(k => typeof body.envelope[k] === 'string')
          || JSON.stringify(body.envelope).length > MAX_BODY - 1024) {
        answer(res, 409, { error: 'invalid envelope' }); return true;
      }
      item.claim.envelope = body.envelope;
      item.claim.state = 'ready';
      answer(res, 200, { status: 'ready' });
      return true;
    }
    if (action === 'envelope' && req.method === 'GET') {
      if (!item.claim || !equalToken(bearer, item.claim.token)) { answer(res, 401, { error: 'unauthorized' }); return true; }
      answer(res, 200, item.claim.state === 'rejected' ? { status: 'rejected' }
        : item.claim.envelope ? { status: 'ready', envelope: item.claim.envelope }
          : { status: 'pending' });
      return true;
    }
    if (action === 'ack' && req.method === 'POST') {
      if (!item.claim || !equalToken(bearer, item.claim.token) || item.claim.state !== 'ready') {
        answer(res, 401, { error: 'unauthorized' }); return true;
      }
      item.state = 'complete';
      item.completedAt = now();
      item.claim.envelope = null;
      answer(res, 200, { status: 'complete' });
      return true;
    }
    answer(res, 405, { error: 'method not allowed' });
    return true;
  }
  return { handle, stop, sessions };
}

module.exports = { createShareRelay };
