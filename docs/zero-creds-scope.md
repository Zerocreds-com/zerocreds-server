# ZeroCreds scope and responsibility

ZeroCreds is a **credential custodian and broker**. It stores credentials, verifies them, and provides controlled ways to use them. It is **not** an all-in-one API client for every provider.

## Principles

1. **Do not pull the blanket onto ZeroCreds.** ZeroCreds must not grow a separate tool or endpoint for every provider operation. Provider-specific workflows belong to the agent or to templates/cookbooks that generate ordinary requests.
2. **Provide tools, not workflows.** The primary capability is a generic primitive: use a stored credential to perform an arbitrary HTTP request without exposing the secret. Templates are convenience layers on top of that primitive.
3. **Secrets never leave custody.** A credential is never returned to the agent, prompt, logs, or Task Packet. Usage happens through brokered requests or explicitly authorized direct use.
4. **Policy is explicit and inspectable.** Connections carry usage policy metadata such as allowed hosts, allowed auth modes, and direct-use permission. Defaults are safe; restrictions, once set, persist.
5. **Security invariants are mandatory.** Host allowlists, TLS, redirect handling, response bounds, redaction, audit records, and (in hosted mode) run-scoped authorization are not optional features.

## Consequences

- New GitHub/GitLab/Cloudflare/... operations should be expressed as templates over the generic request primitive, not as new MCP tools.
- Issue #193-style requests for provider-specific APIs should be redirected to the generic broker + templates.
- ZeroCreds owns credential custody and policy; the agent owns task-specific API calls.
