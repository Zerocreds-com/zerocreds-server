'use strict';

const crypto = require('node:crypto');

const INFO = Buffer.from('zerocreds-share-v1');
const pendingClaims = new Map();
const ID = /^[a-f0-9]{32}$/;
const SECRET = /^#[a-f0-9]{64}$/;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function relayOrigin(value, { allowLoopback = false } = {}) {
  let url;
  try { url = new URL(value); } catch { throw new Error('invalid share relay URL'); }
  const loopback = allowLoopback && url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname);
  if (!loopback && url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
      || url.pathname !== '/' || !url.hostname) throw new Error('invalid share relay URL');
  return url.origin;
}

function parseInvite(link, relayUrl, options = {}) {
  const origin = relayOrigin(relayUrl, options);
  let url;
  try { url = new URL(link); } catch { throw new Error('invalid share link'); }
  const match = url.pathname.match(/^\/api\/share-relay\/invite\/([a-f0-9]{32})$/);
  if (url.origin !== origin || !match || !SECRET.test(url.hash) || url.username || url.password || url.search) {
    throw new Error('invalid share link');
  }
  return { origin, id: match[1], secret: Buffer.from(url.hash.slice(1), 'hex') };
}

function mac(secret, value) {
  return crypto.createHmac('sha256', secret).update(value).digest('hex');
}

function validProof(secret, value, proof) {
  if (typeof proof !== 'string' || !/^[a-f0-9]{64}$/.test(proof)) return false;
  return crypto.timingSafeEqual(Buffer.from(mac(secret, value), 'hex'), Buffer.from(proof, 'hex'));
}

async function call(origin, method, pathname, body, token) {
  const res = await fetch(`${origin}${pathname}`, {
    method, redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  let value;
  try { value = await res.json(); } catch { throw new Error(`relay HTTP ${res.status}`); }
  if (!res.ok) throw new Error(`relay ${value?.error || `HTTP ${res.status}`}`);
  return value;
}

function encrypt(secret, id, publicKey, payload) {
  const recipient = crypto.createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' });
  if (recipient.asymmetricKeyType !== 'x25519') throw new Error('invalid recipient key');
  const sender = crypto.generateKeyPairSync('x25519');
  const shared = crypto.diffieHellman({ privateKey: sender.privateKey, publicKey: recipient });
  const key = crypto.hkdfSync('sha256', shared, secret, INFO, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(id));
  const plaintext = Buffer.from(JSON.stringify(payload));
  if (plaintext.length > 64000) throw new Error('credential too large');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { sender_key: sender.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}

function decrypt(secret, id, privateKey, envelope) {
  try {
    const sender = crypto.createPublicKey({ key: Buffer.from(envelope.sender_key, 'base64'), format: 'der', type: 'spki' });
    if (sender.asymmetricKeyType !== 'x25519') throw new Error('invalid sender key');
    const shared = crypto.diffieHellman({ privateKey, publicKey: sender });
    const key = crypto.hkdfSync('sha256', shared, secret, INFO, 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(Buffer.from(id));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const payload = JSON.parse(Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final(),
    ]).toString('utf8'));
    if (!payload || !payload.metadata || !payload.fields || typeof payload.fields !== 'object'
        || Array.isArray(payload.fields)) throw new Error('invalid payload');
    return payload;
  } catch { throw new Error('share decryption failed'); }
}

async function createPeerShare({ relayUrl, metadata, readCredential, ttlMinutes = 15,
  allowLoopback = false, pollIntervalMs = 1000 }) {
  const origin = relayOrigin(relayUrl, { allowLoopback });
  if (!Number.isInteger(ttlMinutes) || ttlMinutes < 1 || ttlMinutes > 120) throw new Error('invalid share lifetime');
  if (typeof readCredential !== 'function') throw new Error('credential reader required');
  const id = crypto.randomBytes(16).toString('hex');
  const secret = crypto.randomBytes(32);
  const ownerToken = crypto.randomBytes(32).toString('hex');
  const created = await call(origin, 'POST', '/api/share-relay/sessions', {
    id, owner_token: ownerToken, ttl_minutes: ttlMinutes,
  });
  let state = 'pending';
  let stopped = false;
  let handledClaim = null;
  const pump = async () => {
    while (!stopped && Date.now() < Date.parse(created.expires_at)) {
      try {
        const result = await call(origin, 'GET', `/api/share-relay/sessions/${id}/poll`, undefined, ownerToken);
        if (result.status === 'complete') { state = 'complete'; break; }
        if (result.status === 'ready') state = 'claimed';
        if (result.status === 'pending' && result.claim_id && result.claim_id !== handledClaim) {
          handledClaim = result.claim_id;
          if (!validProof(secret, `${id}:${result.public_key}`, result.proof)) {
            await call(origin, 'POST', `/api/share-relay/sessions/${id}/reject`, { claim_id: result.claim_id }, ownerToken);
            handledClaim = null;
          } else {
            let envelope;
            try {
              const fields = await readCredential();
              envelope = encrypt(secret, id, result.public_key, { metadata, fields });
            } catch {
              state = 'unavailable';
              await call(origin, 'POST', `/api/share-relay/sessions/${id}/reject`, { claim_id: result.claim_id }, ownerToken).catch(() => {});
              handledClaim = null;
              await sleep(pollIntervalMs);
              continue;
            }
            try {
              await call(origin, 'POST', `/api/share-relay/sessions/${id}/envelope`,
                { claim_id: result.claim_id, envelope }, ownerToken);
              state = 'claimed';
            } catch {
              // The relay may have stored the envelope before the response was lost.
              // Poll again instead of rejecting a claim with an ambiguous outcome.
              handledClaim = null;
            }
          }
        }
      } catch { /* A transient network outage should not consume the invitation. */ }
      await sleep(pollIntervalMs);
    }
    if (!stopped && state !== 'complete') state = 'expired';
  };
  void pump();
  return { id, url: `${origin}/api/share-relay/invite/${id}#${secret.toString('hex')}`,
    expires_at: created.expires_at, status: () => state,
    close: () => {
      stopped = true;
      if (state !== 'complete') {
        state = 'cancelled';
        void call(origin, 'DELETE', `/api/share-relay/sessions/${id}`, undefined, ownerToken).catch(() => {});
      }
    } };
}

async function claimPeerShare(link, saveCredential, { relayUrl, allowLoopback = false, pollIntervalMs = 1000 } = {}) {
  if (typeof saveCredential !== 'function') throw new Error('credential writer required');
  const invite = parseInvite(link, relayUrl, { allowLoopback });
  const claimKey = crypto.createHash('sha256').update(link).digest('hex');
  let pending = pendingClaims.get(claimKey);
  if (pending?.busy) throw new Error('share claim already in progress');
  if (!pending) {
    pending = { keys: crypto.generateKeyPairSync('x25519'), claim: null, busy: false };
    pendingClaims.set(claimKey, pending);
  }
  pending.busy = true;
  try {
  const publicKey = pending.keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const claim = pending.claim || await call(invite.origin, 'POST', `/api/share-relay/sessions/${invite.id}/claim`, {
    public_key: publicKey, proof: mac(invite.secret, `${invite.id}:${publicKey}`),
  });
  pending.claim = claim;
  const until = Date.now() + 120000;
  let envelope;
  while (Date.now() < until) {
    const response = await call(invite.origin, 'GET', `/api/share-relay/sessions/${invite.id}/envelope`,
      undefined, claim.claim_token);
    if (response.status === 'rejected') throw new Error('share claim denied');
    if (response.status === 'ready') { envelope = response.envelope; break; }
    await sleep(pollIntervalMs);
  }
  if (!envelope) throw new Error('share claim timed out; ask the sender to keep ZeroCreds running');
  const payload = decrypt(invite.secret, invite.id, pending.keys.privateKey, envelope);
  const saved = await saveCredential(payload.metadata, payload.fields);
  let acknowledged = true;
  try { await call(invite.origin, 'POST', `/api/share-relay/sessions/${invite.id}/ack`, {}, claim.claim_token); }
  catch { acknowledged = false; }
  pendingClaims.delete(claimKey);
  return { status: acknowledged ? 'saved' : 'saved_ack_unknown', ...saved,
    setup_prompt: payload.metadata.setup_prompt || '', source: 'sender_supplied_untrusted_text' };
  } catch (error) {
    if (/share unavailable|share claim denied|share decryption failed/.test(error.message)) pendingClaims.delete(claimKey);
    throw error;
  } finally { pending.busy = false; }
}

module.exports = { createPeerShare, claimPeerShare, parseInvite, relayOrigin, encrypt, decrypt };
