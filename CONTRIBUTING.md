# Contributing to ZeroCreds

Thanks for your interest in contributing. ZeroCreds is a small, focused project — contributions that keep it simple and auditable are most welcome.

## What we're looking for

- **New destinations** — Yandex Lockbox, Azure Key Vault, 1Password, etc.
- **New built-in services** — other Russian services that need browser-based auth (Сбер, Госуслуги direct, etc.)
- **Security improvements** — rate limiting, better validation, audit logging
- **Bug fixes** — especially around token expiry, edge cases in destinations
- **Documentation** — clearer setup guides, integration examples

## What we're not looking for

- Dependencies that can't be audited easily (prefer stdlib over npm packages)
- Cloud-only features (the whole point is self-hosted)
- Breaking changes to the API without a clear migration path

## How to contribute

1. Fork the repo and create a branch
2. Make your changes — keep diffs small and focused
3. Test manually: run the server locally, check the endpoint works
4. Open a pull request with a clear description of what and why

## Code style

- Plain Node.js, no build step
- No TypeScript (auditors need to read the code directly)
- Prefer stdlib (`crypto`, `https`, `fs`) over npm packages
- New destinations go in `server/src/destinations.js`

## Security

If you find a security issue, please open a GitHub Issue marked `[security]`. For critical issues, you can also email the maintainers directly (contact in GitHub profile).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
