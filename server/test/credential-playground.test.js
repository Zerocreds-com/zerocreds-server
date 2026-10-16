'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { validateRules, evaluateRules, simulateScenario, listScenarios } = require('../src/credential-playground');

test('generic rules accept regex and length checks without returning the candidate', () => {
  const parsed = validateRules([
    { type: 'matches', pattern: '^[A-Z]{3}_[0-9]{4}$' },
    { type: 'min_length', value: 8 },
    { type: 'max_length', value: 16 },
  ]);
  assert.equal(parsed.error, undefined);
  assert.equal(evaluateRules('ABC_1234', parsed.rules).accepted, true);
  assert.equal(evaluateRules('abc_1234', parsed.rules).accepted, false);
});

test('regex is bounded and rejects high-risk backtracking constructs', () => {
  assert.match(validateRules([{ type: 'matches', pattern: '(a+)+$' }]).error, /disallowed/);
  assert.match(validateRules([{ type: 'matches', pattern: '(a|aa)+' }]).error, /disallowed/);
  assert.match(validateRules([{ type: 'matches', pattern: 'a'.repeat(129) }]).error, /1–128/);
  assert.match(validateRules([{ type: 'matches', pattern: '(' }]).error, /valid regular expression/);
});

test('scenarios are fixed synthetic samples and expose no sample values', () => {
  const rules = validateRules([{ type: 'matches', pattern: '^PLAYGROUND_SYNTHETIC_VALID_' }]).rules;
  const result = simulateScenario('valid', rules);
  assert.equal(result.outcome, 'accepted');
  assert.equal(result.matched_expectation, true);
  assert.equal(result.provider_contacted, false);
  assert.equal(result.storage_contacted, false);
  assert.equal(JSON.stringify(result).includes('7f3a'), false);
  assert.equal(listScenarios().some(item => item.id === 'provider_timeout'), true);
});
