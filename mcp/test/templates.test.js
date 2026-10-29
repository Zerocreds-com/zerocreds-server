'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { githubUpdatePr, githubGetPr, githubListPrs } = require('../templates');

test('githubUpdatePr builds a PATCH request', () => {
  const req = githubUpdatePr({ connection_id: 'c1', repo: 'o/r', pr_number: 191, draft: false });
  assert.equal(req.method, 'PATCH');
  assert.equal(req.url, 'https://api.github.com/repos/o/r/pulls/191');
  assert.equal(req.body.draft, false);
  assert.equal(req.headers['X-GitHub-Api-Version'], '2022-11-28');
});

test('githubListPrs defaults to open', () => {
  const req = githubListPrs({ connection_id: 'c1', repo: 'o/r' });
  assert.match(req.url, /state=open/);
});
