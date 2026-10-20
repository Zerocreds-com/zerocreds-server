'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { install, configureReadOnlyTools, GUIDANCE, READ_ONLY_TOOLS } = require('../install-codex-guidance');

test('adds guidance without changing existing user instructions and is idempotent', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-guidance-'));
  const file = path.join(dir, 'AGENTS.md');
  try {
    fs.writeFileSync(file, '# My instructions\n\nKeep this rule.\n');
    install(file);
    assert.equal(fs.readFileSync(file, 'utf8'), `# My instructions\n\nKeep this rule.\n\n${GUIDANCE}\n`);
    install(file);
    assert.equal(fs.readFileSync(file, 'utf8'), `# My instructions\n\nKeep this rule.\n\n${GUIDANCE}\n`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects an incomplete managed block without replacing other instructions', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-guidance-'));
  const file = path.join(dir, 'AGENTS.md');
  try {
    const original = '# My instructions\n\n<!-- zerocreds:begin -->\nCustom notes\n';
    fs.writeFileSync(file, original);
    assert.throws(() => install(file), /Malformed ZeroCreds guidance block/);
    assert.equal(fs.readFileSync(file, 'utf8'), original);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('approves only metadata reads and preserves existing approval choices', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zerocreds-approvals-'));
  const file = path.join(dir, 'config.toml');
  try {
    fs.writeFileSync(file, '[mcp_servers.zerocreds]\ncommand = "node"\n\n[mcp_servers.zerocreds.tools.doctor]\napproval_mode = "prompt"\n');
    configureReadOnlyTools(file);
    const first = fs.readFileSync(file, 'utf8');
    assert.match(first, /\[mcp_servers\.zerocreds\.tools\.doctor\]\napproval_mode = "prompt"/);
    for (const tool of READ_ONLY_TOOLS) {
      assert.equal(first.split(`[mcp_servers.zerocreds.tools.${tool}]`).length, 2);
    }
    assert.doesNotMatch(first, /\[mcp_servers\.zerocreds\.tools\.share_create\]/);
    configureReadOnlyTools(file);
    assert.equal(fs.readFileSync(file, 'utf8'), first);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('manual installation guide contains the exact managed Codex block', () => {
  const guide = fs.readFileSync(path.join(__dirname, '..', '..', 'docs', 'local-mac-setup.md'), 'utf8');
  assert.ok(guide.includes(`\`\`\`md\n${GUIDANCE}\n\`\`\``));
});
