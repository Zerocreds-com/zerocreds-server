# CI/CD Tests Spec

This is the original test plan. Use the current workflow and test files for the live CI contract.

## Goal and tools

Cover core server behavior before production deployment. Tests use built-in `node:test`, `node:assert`, and `node:http`, with a fresh ephemeral server port. Run `node --test server/test/*.test.js`.

## Original test layout

```text
server/test/helpers.js          startServer, stopServer, request
server/test/session.test.js     POST /api/session/create
server/test/form.test.js        GET and POST /f/:token
server/test/status.test.js      GET /api/session/:token/status
server/test/destinations.test.js by-level routing and destination writes
server/test/auth.test.js        tokens, registration, integrators
server/test/html.test.js        HTML escaping and level badges
```

## Cases

| Area | Scenario | Expected result |
|---|---|---|
| Session | Valid single or by-level destination, or both | 200 with token, URL, and expiration |
| Session | No destination; invalid field name, type, level, or named destination | 400 |
| Session | Missing Authorization | 401 |
| Session | TTL above 1440 minutes | Clamped to 1440 minutes |
| Form | Valid, expired, or unknown GET token | 200 HTML, 410, or 404 respectively |
| Form | All fields submitted | 200 `{ ok: true }` |
| Form | Missing required field, invalid URL field, or mismatched body token | 400 |
| Form | Resubmit an already used link | 403 |
| Status | Pending, completed, unknown, or expired session | Correct status without credential values |
| Status | Completed single or by-level destination | Safe `secret_id` or `secret_ids` metadata |
| Destination | Local-file write; by-level secret and attribute routing | Correct JSON file(s) |
| Destination | Field without level | Route through `default`; reject an unrouted field |
| Destination | `http_post` success or upstream failure | Form success or failure without upstream body leakage |
| Auth | Valid/invalid registration and rate limit | 200, 400, or 429 |
| Auth | Integrator creates a session using its own named destinations | Correct routing |
| Auth | Admin creates an integrator; integrator calls admin endpoint | 200 or 401 respectively |
| HTML | XSS strings in title, field label, placeholder, and description | Escaped in HTML and attributes |
| HTML | Field with or without `level` | Appropriate badge and information control |
| Language | Omitted, `en`, `ru`, unsupported value | English default, chosen locale, or 400 |

The original sketch proposed a test job on push and pull requests followed by a deploy job gated on that test. The repository's actual workflows now define the deployment gate.

## Original exclusions and implementation order

A real Nalog Playwright login, production GCP/AWS/Vault credentials, and live Telegram delivery were excluded from the initial CI scope. HTTP mocks exercise destination behavior; Telegram notification code should at least be checked for safe failure. The initial implementation order was helpers, session/status, form, destinations, HTML, then authentication.
