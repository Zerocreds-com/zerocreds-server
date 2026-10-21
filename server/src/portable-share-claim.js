'use strict';

const crypto = require('node:crypto');
const { claimPeerShare } = require('./local-share');

function validateContents(meta, fields) {
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(meta?.provider || '')
      || !/^[a-zA-Z0-9_-]{1,64}$/.test(meta?.account_alias || '')
      || typeof meta.setup_prompt !== 'string' || meta.setup_prompt.length > 2000
      || (meta.credential_expires_at !== null && meta.credential_expires_at !== undefined
        && (!Number.isFinite(Date.parse(meta.credential_expires_at))
          || Date.parse(meta.credential_expires_at) <= Date.now()))
      || !fields || typeof fields !== 'object' || Array.isArray(fields)
      || Object.entries(fields).length < 1 || Object.entries(fields).length > 20
      || Object.entries(fields).some(([key, value]) => !/^[a-zA-Z0-9_]{1,64}$/.test(key)
        || typeof value !== 'string' || value.length > 65536)) {
    throw new Error('invalid share contents');
  }
}

function storageAccount(provider, alias) {
  const requested = `${provider}-${alias}`;
  return requested.length <= 128 ? requested
    : `zc-${crypto.createHash('sha256').update(requested).digest('hex')}`;
}

async function claimPortableShare(shareUrl, saveCredential, { accountAlias,
  relayUrl = process.env.ZEROCREDS_SHARE_RELAY_URL || ['https://zerocreds.ru', 'https://zerocreds.com'], allowLoopback = false } = {}) {
  if (typeof saveCredential !== 'function') throw new Error('credential writer required');
  return claimPeerShare(shareUrl, async (meta, fields) => {
    validateContents(meta, fields);
    const alias = accountAlias || meta.account_alias;
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(alias)) throw new Error('invalid account alias');
    const account = storageAccount(meta.provider, alias);
    await saveCredential({ service: 'zerocreds', account, create_only: true }, fields);
    return { provider: meta.provider, account_alias: alias, storage: `zerocreds/${account}` };
  }, { relayUrl, allowLoopback });
}

module.exports = { claimPortableShare, validateContents, storageAccount };
