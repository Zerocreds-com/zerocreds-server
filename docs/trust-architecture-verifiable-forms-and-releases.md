# Trust architecture: verifiable forms and releases

Date: 2026-09-27. Goal: a user (and an external auditor) can **verify, not
believe**:

1. **Where** a submitted credential will go and **exactly which request** will
   write it. This must be fixed before the user types anything and must not
   change between render and submit.
2. The form they are typing into was **built from `main`** of this public repo
   and has not been modified on the server.
3. After the fact, what happened can be **checked independently**: append-only
   records that the operator cannot silently rewrite.

Honest boundary: on a plain VPS without a TEE, the machine operator can always
run different code. The design makes that **detectable** (public logs, external
monitors, signed artifacts) and, in phase 3, **useless** (end-to-end encryption
to the destination, so the server only relays ciphertext).

---

## 1. Submission manifest — immutable "where and how"

At `POST /api/session/create`, the server builds a **manifest** and freezes it:

```json
{
  "v": 1,
  "session": "<random id>",
  "created_at": "2026-09-27T20:00:00Z",
  "expires_at": "2026-09-27T20:30:00Z",
  "requester": { "integrator_id": "sar", "name": "serverless-ai-agent-run", "registered_at": "…" },
  "fields": [ { "name": "token", "label": "GitHub token", "type": "password", "level": "secret" } ],
  "destination": {
    "name": "openbao-users",
    "type": "vault",
    "target": "https://bao.example.com/v1/secret/data/users/u_123/github",
    "access": "write-only (policy zerocreds-writer: create, update)",
    "registered_at": "…"
  },
  "request": {
    "method": "POST",
    "url": "https://bao.example.com/v1/secret/data/users/u_123/github",
    "headers": { "X-Vault-Token": "<zerocreds writer token — redacted>", "Content-Type": "application/json" },
    "body": { "data": { "token": "{{field:token}}" } }
  },
  "server_release": { "commit": "bf1668f…", "artifact_sha256": "…", "attestation": "https://github.com/…/attestations/…" }
}
```

- `manifest_id = sha256(canonical JSON)` (RFC 8785 JCS canonicalization).
- **Signed** with the server's Ed25519 release-bound key. The public key is published
  in the repo and in the attestation.
- **The form shows it before input:** a human line ("Will be saved to *OpenBao* at
  `users/u_123/github`, write-only, requested by *serverless-ai-agent-run*"), plus a
  "Show exact request" disclosure with the request template, plus the short `manifest_id`.
- **Bound to submit:** the form POSTs `manifest_id` back. The server writes **only**
  by executing the stored manifest's request template, and rejects the POST if the
  id doesn't match. A swapped destination is therefore impossible without a visible
  id change.
- **Receipt after submit:** a signed `{manifest_id, submitted_at, result}`, where
  `result` carries the destination's own evidence (e.g. KV version number). The user
  can check it in their store.

### Destination rules that make the manifest meaningful

- **Production: no inline destinations.** Only named destinations registered by an
  identified integrator. Registration is itself a transparency-log entry, so the form
  can say "registered 12 days ago".
- `http_post` only to an allowlisted host per integrator. No private/metadata IPs
  (SSRF), and https only.
- The manifest shows `access` (write-only claim) **and** how to check it (the policy
  name/path). The auditor can compare it with the destination's policy.

## 2. Transparency log — append-only history

- Every manifest, destination registration, receipt and **deployment** is appended to
  a hash-chained log (`entry_n.prev = sha256(entry_{n-1})`). No secret values in it,
  only hashes and metadata.
- Served at `GET /transparency?after=` and `GET /transparency/head`.
- **Anchoring outside the operator's control:** a GitHub Action in a separate public
  repo `zerocreds-transparency` commits the current head hash every 15 minutes. After
  that, rewriting history breaks the chain against public git history. Optionally,
  each head can also go to a public transparency log (Sigstore Rekor).
- An external verifier script (`scripts/verify-transparency.ts`) replays the chain and
  checks it against the anchors.

## 3. Releases — "this form is from main"

| Step | Mechanism |
|---|---|
| Build | GitHub Actions on a push to `main`: `npm ci` from lockfile → release tarball (server + lockfile + static assets) → `sha256` |
| Provenance | `actions/attest-build-provenance` → Sigstore-signed SLSA provenance: repo, workflow, commit, digest |
| Deploy gate | The server pulls the **tarball**, not `git reset` on a working tree, and **verifies the attestation** (`gh attestation verify --owner Zerocreds-com`) before switching. It refuses anything not built by the main workflow |
| Runtime identity | `/version` returns `{commit, artifact_sha256, attestation_url, served_assets: {path: sha256}}` |
| Served-form check | The public monitor (extends `scripts/check-public.py`) fetches a live form page, normalizes the per-session parts, and compares asset hashes with the release manifest from the attestation. A mismatch opens an issue and alerts |
| Browser side | Strict CSP (no inline script, or hashed inline), SRI on every static asset, `frame-ancestors 'none'`. Footer: "Build `bf1668f` · verify" → page with verification steps |
| Reproducibility | Deterministic tarball (sorted entries, fixed mtimes), so anyone can rebuild and compare `sha256` |

Protected `main` (PR + required `test`, enforced for admins) is the precondition.
Enabled on 2026-09-27; before that, `main` was unprotected, and `auto-merge.yml`
merged and deployed every PR immediately.

## 4. Phase 3 — end-to-end encryption to the destination

The strongest guarantee: the server **cannot** read what it relays.

- The destination publishes an encryption public key (e.g. an OpenBao transit
  asymmetric key or an age/X25519 recipient). It is registered with the destination,
  so it is part of the manifest.
- The form encrypts in the browser (WebCrypto) to that key. The server writes
  ciphertext, and only the destination-side reader (e.g. the SAR broker via transit
  decrypt) can decrypt.
- Combined with a **static form hosted from the repo** (e.g. GitHub Pages built from
  `main`, content-addressed), the page the user types into is verifiable without
  trusting our server at all. Our server becomes a relay and a manifest notary.

## Roadmap (issues)

| # | Item | Size |
|---|---|---|
| Z0 | CI/CD guard: protect `main` (done), make auto-merge wait for checks, tests on Node 22+, lint/gitleaks, `npm audit` | S |
| Z1 | Submission manifest: build, canonicalize, sign, show in the form, bind to submit, signed receipt | M |
| Z2 | Destination hardening: no inline in prod, integrator registration, `http_post` allowlist + SSRF block | M |
| Z3 | Transparency log + external anchoring repo + verifier script | M |
| Z4 | Signed releases: tarball + build provenance attestation; deploy verifies before switching; `/version` with digests | M |
| Z5 | Served-form integrity: CSP + SRI + external monitor comparing live assets with the release manifest | S |
| Z6 | Phase 3: browser-side encryption to a destination key; static verifiable form | L |
| Z7 | Public security model + auditor guide: how to verify each claim step by step | S |
