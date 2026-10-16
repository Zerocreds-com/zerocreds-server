'use strict';

const SCENARIOS = Object.freeze({
  valid: { value: 'PLAYGROUND_SYNTHETIC_VALID_7f3a', expected: 'accepted', description: 'Synthetic value that should pass the configured rules.' },
  invalid: { value: 'PLAYGROUND_SYNTHETIC_INVALID_x', expected: 'rejected', description: 'Synthetic value that should fail a configured rule.' },
  empty: { value: '', expected: 'rejected', description: 'Missing required value.' },
  expired: { value: 'PLAYGROUND_SYNTHETIC_EXPIRED_4d2b', expected: 'expired', description: 'Simulated expired credential; no provider is contacted.' },
  provider_timeout: { value: 'PLAYGROUND_SYNTHETIC_TIMEOUT_2a9c', expected: 'provider_timeout', description: 'Simulated verifier timeout; no network request is made.' },
  storage_failure: { value: 'PLAYGROUND_SYNTHETIC_STORAGE_6b1e', expected: 'storage_failure', description: 'Simulated storage failure; no storage is contacted.' },
});

const MAX_RULES = 12;
const MAX_PATTERN_LENGTH = 128;

function validateRules(rules) {
  if (!Array.isArray(rules) || rules.length > MAX_RULES) return { error: `rules must be an array (max ${MAX_RULES})` };
  const output = [];
  for (const rule of rules) {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule) || typeof rule.type !== 'string') return { error: 'each rule must be an object with a type' };
    switch (rule.type) {
      case 'required':
        output.push({ type: 'required' });
        break;
      case 'min_length':
      case 'max_length':
        if (!Number.isInteger(rule.value) || rule.value < 0 || rule.value > 8192) return { error: `${rule.type} value must be an integer from 0 to 8192` };
        output.push({ type: rule.type, value: rule.value });
        break;
      case 'equals':
      case 'contains':
        if (typeof rule.value !== 'string' || rule.value.length > 256) return { error: `${rule.type} value must be a string (max 256 characters)` };
        output.push({ type: rule.type, value: rule.value });
        break;
      case 'one_of':
        if (!Array.isArray(rule.values) || rule.values.length < 1 || rule.values.length > 20 || rule.values.some(value => typeof value !== 'string' || value.length > 128)) return { error: 'one_of needs 1–20 strings (max 128 characters each)' };
        output.push({ type: 'one_of', values: [...rule.values] });
        break;
      case 'matches': {
        if (typeof rule.pattern !== 'string' || rule.pattern.length < 1 || rule.pattern.length > MAX_PATTERN_LENGTH) return { error: `matches pattern must be 1–${MAX_PATTERN_LENGTH} characters` };
        // Disallow constructs commonly responsible for catastrophic backtracking.
        if (/\\[1-9]|\(\?[=!<]|\(\?>|\)[+*{]|(?:\.\*|\.\+){2}/.test(rule.pattern)
            || (rule.pattern.match(/[+*?{]/g) || []).length > 3) return { error: 'matches pattern uses a disallowed construct' };
        try { new RegExp(rule.pattern, 'u'); } catch { return { error: 'matches pattern is not a valid regular expression' }; }
        output.push({ type: 'matches', pattern: rule.pattern });
        break;
      }
      default:
        return { error: `unsupported rule type: ${String(rule.type).slice(0, 40)}` };
    }
  }
  return { rules: output };
}

function evaluateRules(value, rules) {
  const results = rules.map((rule, index) => {
    let passed;
    switch (rule.type) {
      case 'required': passed = value.length > 0; break;
      case 'min_length': passed = value.length >= rule.value; break;
      case 'max_length': passed = value.length <= rule.value; break;
      case 'equals': passed = value === rule.value; break;
      case 'contains': passed = value.includes(rule.value); break;
      case 'one_of': passed = rule.values.includes(value); break;
      case 'matches': passed = new RegExp(rule.pattern, 'u').test(value); break;
      default: passed = false;
    }
    return { rule: index + 1, type: rule.type, passed };
  });
  return { accepted: results.every(result => result.passed), results };
}

function simulateScenario(scenario, rules) {
  const sample = SCENARIOS[scenario];
  if (!sample) return null;
  const validation = evaluateRules(sample.value, rules);
  const outcome = ['valid', 'invalid', 'empty'].includes(scenario)
    ? (validation.accepted ? 'accepted' : 'rejected')
    : sample.expected;
  return {
    scenario,
    outcome,
    expected_outcome: sample.expected,
    matched_expectation: outcome === sample.expected,
    rules: validation.results,
    synthetic_input: true,
    value_returned: false,
    provider_contacted: false,
    storage_contacted: false,
  };
}

function listScenarios() {
  return Object.entries(SCENARIOS).map(([id, item]) => ({ id, expected_outcome: item.expected, description: item.description }));
}

module.exports = { validateRules, evaluateRules, simulateScenario, listScenarios };
