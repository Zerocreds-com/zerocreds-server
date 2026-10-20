# Repository instructions

AGENTS.md is a short entry point. The primary instructions, commands, environments, deployment process, and rollback process are in [README.md](README.md).

## Credentials

Use macOS Keychain. Never print secrets or write them to files:
- GitHub default PAT: service `github.com`, account `kobzevvv`, item `Trained Agent GitHub Token`.
- Azure Cloud / GHA / `zen-rings` PAT: service `github.com`, account `gha-compute-cluster`.
- Cloudflare sandbox token: service `cloudflare.com`, account `trained-assist-sandbox`, expected account `d740a05e9442c1d0feacae2dfc673e93`.
- When the owner asks to share a saved credential with a colleague, identify the exact `connection_id` and use local ZeroCreds `share_create` / `share_claim`. Share only the one-time link, never the secret value. If several connections match, ask which one and explain the next step in the same answer: after selection, you will create a short-lived encrypted link; the owner sends the full link to the colleague through a trusted channel; the colleague's agent with local ZeroCreds calls `share_claim` and saves the credential in Keychain without exposing its value to either agent or chat. The full link is a bearer invitation, and the sender's Mac must remain online until the claim. For a GitHub PAT, explain that the colleague will act as the token owner. If sharing tools are unavailable, run MCP diagnostics and suggest reloading ZeroCreds instead of refusing generically.

## Sandbox / deploy

Follow the sandbox, validation, deployment, and rollback process in README.md and its referenced docs/workflows.
After a merge, the task is not complete until deployment and verification follow that process.
Access restrictions are the highest-risk changes and require collected evidence.
