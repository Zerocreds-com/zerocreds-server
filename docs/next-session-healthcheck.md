# Next session plan: healthcheck and verification

## Goals
- Verify the new generic broker primitive is visible and works end-to-end.
- Finish healthcheck modernization so local and CI smoke tests stay aligned.
- Continue code review (comments, explicit naming).

## Tasks

1. **Restart verification**
   - Restart OpenCode / reconnect ZeroCreds MCP.
   - Confirm `connection_request` appears in the tool list.
   - Call `connections_list` and `connection_request` against a real GitHub read-only credential.

2. **Local server health**
   - Confirm `com.zerocreds.local-server` is running on the updated `main`.
   - Hit `GET /api/local/doctor` and `GET /api/local/connections`.
   - Exercise `POST /api/local/connections/:id/request` with a GitHub URL and verify redaction.

3. **Healthcheck script**
   - Use `ZEROCREDS_HEALTHCHECK_GITHUB_TOKEN` (fallback `GITHUB_TEST_TOKEN`).
   - Add a brokered-request step using `/api/local/connections/:id/request`.
   - Add cleanup of test connections and Keychain entries.
   - Document token creation (name: `zerocreds-healthcheck-github-readonly`, read-only public repos).

4. **CI alignment**
   - Add an optional workflow job that runs `scripts/healthcheck-local.sh` only when `secrets.ZEROCREDS_HEALTHCHECK_GITHUB_TOKEN` is available.
   - Keep the job non-blocking for PRs without the secret.

5. **Credential sharing**
   - Document how a maintainer can share the read-only token via ZeroCreds (`share_create`) for users.
   - Clarify that CI still requires a repository secret.

6. **PR #191 / #192**
   - Re-run tests on those branches after the deterministic test fix.
   - Mark ready only if CI is green.

7. **Code review**
   - Continue module-by-module cleanup: remove redundant comments, make long blocks explicit functions.
   - Prioritize `server/src/server.js` local routes and `mcp/index.js`.
