#!/usr/bin/env node
'use strict';

// Portable one-time share receiver. It accepts only a bearer invitation, never
// prints the envelope or its decrypted fields, and passes fields to the native
// credential-store helper through stdin.
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { claimPortableShare } = require('../src/portable-share-claim');
const { saveToDestination } = require('../src/destinations');

function usage() {
  return 'Usage: pbpaste | node server/scripts/claim-share.cjs [--account-alias NAME] [--relay-url HTTPS_URL]';
}

function parseArgs(args) {
  let accountAlias;
  let relayUrl;
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--account-alias' && args[index + 1]) accountAlias = args[++index];
    else if (args[index] === '--relay-url' && args[index + 1]) relayUrl = args[++index];
    else if (args[index] === '--help') { process.stdout.write(`${usage()}\n`); process.exit(0); }
    else throw new Error(usage());
  }
  return { accountAlias, relayUrl };
}

function inviteFromStdin() {
  const invite = fs.readFileSync(0, 'utf8').trim();
  if (!invite || invite.length > 512) throw new Error('read one full share invitation from standard input');
  return invite;
}

function temporaryMacHelper() {
  if (process.env.ZEROCREDS_KEYCHAIN_HELPER) return () => {};
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-claim-'));
  const helper = path.join(root, 'keychain-helper');
  const source = path.join(__dirname, 'macos-keychain.swift');
  const result = childProcess.spawnSync('swiftc', ['-O', source, '-o', helper], { stdio: 'ignore' });
  if (result.status !== 0) {
    fs.rmSync(root, { recursive: true, force: true });
    throw new Error('could not prepare macOS Keychain helper; install Xcode Command Line Tools or set ZEROCREDS_KEYCHAIN_HELPER');
  }
  fs.chmodSync(helper, 0o700);
  process.env.ZEROCREDS_KEYCHAIN_HELPER = helper;
  return () => {
    delete process.env.ZEROCREDS_KEYCHAIN_HELPER;
    fs.rmSync(root, { recursive: true, force: true });
  };
}

async function main() {
  const { accountAlias, relayUrl } = parseArgs(process.argv.slice(2));
  const invite = inviteFromStdin();
  if (!['darwin', 'win32'].includes(process.platform)) throw new Error('portable claim currently supports macOS and Windows');
  const cleanup = process.platform === 'darwin' ? temporaryMacHelper() : () => {};
  try {
    const result = await claimPortableShare(invite, (destination, fields) => saveToDestination({
      type: process.platform === 'darwin' ? 'macos_keychain' : 'windows_credential_manager',
      ...destination,
    }, fields), { accountAlias, relayUrl });
    process.stdout.write(JSON.stringify({ status: result.status, provider: result.provider,
      account_alias: result.account_alias, storage: result.storage, setup_prompt: result.setup_prompt,
      setup_prompt_source: result.source }) + '\n');
  } finally {
    cleanup();
  }
}

main().catch(error => {
  process.stderr.write(`Could not save shared credential: ${error.message}\n`);
  process.exitCode = 1;
});
