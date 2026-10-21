'use strict';

const crypto = require('node:crypto');

// A share link is a one-time bearer invitation split in two: the path holds the
// public session id, the fragment holds the secret that unlocks the encrypted
// envelope. Both are base64url now, which keeps the link short enough to send
// in a chat message. The earlier hex forms stay readable, so an invitation
// that is already in flight keeps working after an update.
const ID = /^[A-Za-z0-9_-]{14}$/;
const LEGACY_ID = /^[a-f0-9]{32}$/;
const SECRET = /^[A-Za-z0-9_-]{22}$/;
const LEGACY_SECRET = /^[a-f0-9]{64}$/;

// The invitation path stays under /api/ because the public website proxies
// that prefix to the server. A shorter top level path would need a new
// location in the nginx configuration of the host.
const INVITE_PATH = '/api/i/';

// Matches both id forms. The longer one comes first so a 32 character hex id
// is never cut into a 14 character prefix.
const SESSION_ID_SOURCE = '(?:[a-f0-9]{32}|[A-Za-z0-9_-]{14})';
const INVITE_PATH_RE = /^\/(?:api\/i\/([A-Za-z0-9_-]{14})|api\/share-relay\/invite\/([a-f0-9]{32}))$/;

function newSessionId() {
  return crypto.randomBytes(10).toString('base64url');
}

// The secret is the salt of the key derivation and the key of the claim proof.
// 128 bits is the standard size for a one-time secret and 256 bits bought
// nothing here.
function newSecret() {
  return crypto.randomBytes(16);
}

function encodeSecret(secret) {
  return secret.toString('base64url');
}

function decodeSecret(fragment) {
  const value = typeof fragment === 'string' ? fragment.replace(/^#/, '') : '';
  if (LEGACY_SECRET.test(value)) return Buffer.from(value, 'hex');
  if (SECRET.test(value)) return Buffer.from(value, 'base64url');
  return null;
}

function validSessionId(id) {
  return typeof id === 'string' && (ID.test(id) || LEGACY_ID.test(id));
}

function inviteUrl(origin, id, secret) {
  return `${origin}${INVITE_PATH}${id}#${encodeSecret(secret)}`;
}

function matchInvitePath(pathname) {
  const match = INVITE_PATH_RE.exec(pathname);
  if (!match) return null;
  return match[1] || match[2];
}

module.exports = { newSessionId, newSecret, decodeSecret, validSessionId,
  inviteUrl, matchInvitePath, SESSION_ID_SOURCE };
