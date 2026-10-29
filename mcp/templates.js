'use strict';

// Convenience templates that expand to a generic connection_request payload.
// These are NOT security boundaries and NOT separate MCP tools: they only
// build the request shape; the actual call still goes through connection_request.

function githubUpdatePr({ connection_id, repo, pr_number, draft, title, body }) {
  const payload = { draft };
  if (title !== undefined) payload.title = title;
  if (body !== undefined) payload.body = body;
  return {
    connection_id,
    method: 'PATCH',
    url: `https://api.github.com/repos/${repo}/pulls/${pr_number}`,
    headers: {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    body: payload,
  };
}

function githubGetPr({ connection_id, repo, pr_number }) {
  return {
    connection_id,
    method: 'GET',
    url: `https://api.github.com/repos/${repo}/pulls/${pr_number}`,
    headers: {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  };
}

function githubListPrs({ connection_id, repo, state = 'open' }) {
  return {
    connection_id,
    method: 'GET',
    url: `https://api.github.com/repos/${repo}/pulls?state=${encodeURIComponent(state)}`,
    headers: {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  };
}

module.exports = { githubUpdatePr, githubGetPr, githubListPrs };
