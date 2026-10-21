# CGNAT-compatible peer sharing: transport research

Issue: [#158 — Research CGNAT-compatible peer sharing without a trusted ZeroCreds website](https://github.com/Zerocreds-com/zerocreds-server/issues/158)
Date: 2026-10-21
State: research proposal — no implementation yet
Scope: which transport can carry a one-time credential invitation when **neither** peer has an inbound public port, and how `share_create` can choose a transport without touching the encrypted payload format or the claim verification.

---

## 1. Summary

1. **The constraint is structural, not a bug.** Under CGNAT with no inbound path on either side, *some* third party has to carry the bytes. "No trusted ZeroCreds website" therefore cannot mean "no third party in the path". It can mean: *no third party that can decrypt the credential, and no party the user cannot replace with their own infrastructure.*
2. **The crypto is already transport-independent.** The invitation envelope (X25519 ECDH → HKDF-SHA256 → AES-256-GCM) and the claim proof (HMAC over the fragment secret) do not care who forwards the bytes. Swapping the transport does not require re-deriving the key material or changing the link format — only the host in the link changes.
3. **Preferred first implementation: a `tunnel` transport — the sender's own relay behind a user-supplied outbound tunnel.** The relay code already runs on the sender's machine in the `direct` transport; the new part is an origin policy that accepts an `https` hostname and a transport registry in the API. The ZeroCreds website is not in the path at all.
4. **Document, no code: point the existing relay at the user's own ZeroCreds instance.** `ZEROCREDS_SHARE_RELAY_URL` already makes this a configuration change; it is the strongest trust answer for users who already run a server, and it needs no new transport.
5. **Cloudflare Tunnel is a viable *optional* transport, not the default.** It is a network provider that proxies the encrypted traffic; it is not proof of a direct or trustless route. It is also degraded for our primary audience (Cloudflare throttles Russian users to roughly 16 KB per connection), so it must not be the default path.
6. **Deferred:** WebRTC/TURN, Tor onion services, Tailscale/Headscale as a *share* transport, Magic Wormhole interop, and generic mailbox polling. Reasons are in §8.2.

---

## 2. State of the code on `main` (2026-10-21, commit `73bae62`)

| Piece | Where | Note |
|---|---|---|
| Transport choice | `server/src/server.js:2394-2447` | `POST /api/local/shares` requires `transport` ∈ {`direct`,`relay`}, else `409 transport_selection_required` |
| Options copy | `server/src/server.js:2301-2307` | `GET /api/local/shares/options` returns two flat fields and two sentences |
| Sender-hosted relay | `server/src/direct-share.js:34-106` | The relay runs on the sender's machine; the public listener serves only recipient operations, the owner operations stay on loopback |
| Envelope | `server/src/local-share.js:58-72` | `X25519` ECDH → `HKDF-SHA256(salt = fragment secret, info = "zerocreds-share-v1")` → `AES-256-GCM`, 96-bit IV, **AAD = session id**, plaintext ≤ 64 KB |
| Claim proof | `server/src/local-share.js:37-44`, `171-173` | `HMAC-SHA256(secret, "<session id>:<recipient X25519 public key>")`, compared with `timingSafeEqual` |
| Recipient key | `server/src/local-share.js:165-167` | Ephemeral X25519 pair per link, private key never leaves the process |
| Relay state machine | `server/src/share-relay.js` | In-memory sessions, `MAX_SESSIONS = 100`, `MAX_PER_IP = 5`, TTL 1–120 min, one live claim, ≤ 5 claim attempts, envelope deleted on ack |
| Link format | `server/src/share-link.js` | `<origin>/api/i/<14 base64url id>#<22 base64url secret>`; the older `<origin>/api/share-relay/invite/<32 hex>#<64 hex>` still parses |
| Recipient origin pinning | `server/src/local-share.js:21-35` | `parseInvite` accepts the configured relay origin **or** a public-IPv4 origin; anything else is `invalid share link` |
| Reachability probe | `server/src/share-relay.js:56-100`, `server/src/direct-share.js:44-48`, `server/src/server.js:2338-2372` | The ZeroCreds server asks the sender's machine to expose `GET /api/share-relay/probe/<token>` → `204`, then probes `public_ip:port` itself and returns `{ public_ip, port, reachable }`; one probe per IP per 10 s |

Consequences for this research:

* The `direct` transport is exactly "sender-hosted relay + a public URL" — the only public part is the *link host*.
* The `relay` transport is the same envelope through the shared website.
* The payload format and the claim verification are already transport-independent, but the **recipient-side origin pinning is not**: a link whose host is neither the configured relay nor a public IPv4 is rejected today. Any new transport must extend that pinning, and extending it is a security decision (see §4.3, §9.4).

### 2.1 Why the current `direct` transport cannot work here

`directOrigin()` (`server/src/direct-share.js:22-32`) accepts only a **public IPv4 address with an explicit port**. Under CGNAT the sender has no such address: the carrier NAT owns the public IPv4 and drops unsolicited inbound traffic. A home-router port-forward rule cannot help, because the packet never reaches the home router from outside the carrier NAT. The port probe added in [#155](https://github.com/Zerocreds-com/zerocreds-server/issues/155)/[#157](https://github.com/Zerocreds-com/zerocreds-server/issues/157) can prove that a port is *not* reachable; it cannot make it reachable.

---

## 3. The network constraint, stated precisely

### 3.1 Vocabulary

* **NAT mapping behaviour** (RFC 4787): *endpoint-independent* (a single external port per internal session) vs *address-dependent* / *address-and-port-dependent* (the external port changes per destination address/port).
* **NAT filtering behaviour** (RFC 4787): whether unsolicited inbound traffic is permitted to an existing mapping.
* **CGNAT** (RFC 6598): carrier-grade NAT — many subscribers share one public IPv4 (and often IPv4↔IPv6 translation). The subscriber has no address that any other host can address.

### 3.2 When is a direct path possible?

A direct connection between peer A and peer B is possible **only** if at least one of the following holds:

1. **B (or A) has a publicly routable address** that the other side can reach — a public IPv4/IPv6 with the port reachable, or a port-forward on a home router whose upstream NAT is not CGNAT.
2. **Both peers are behind cone NATs** whose mapping is endpoint-independent and whose filtering permits unsolicited inbound to the mapped port; then a simultaneous outbound "hole punch" (STUN-discovered reflexive candidates, RFC 5780) can establish the path.

Under CGNAT, condition 1 is false for the subscriber, and condition 2 is normally false as well: carrier NATs are typically address-and-port-dependent with restrictive filtering, and the same public IPv4 is shared by many subscribers, so unsolicited inbound is dropped regardless of what the subscriber does. Therefore:

> **If both peers are behind CGNAT, a direct path is impossible. No amount of router configuration, port probing or STUN discovery changes that.**

### 3.3 What is unavoidable

When no direct path exists, exactly one of these must carry the traffic:

| Mechanism | Who supplies the public endpoint | Example |
|---|---|---|
| **Outbound tunnel** (reverse tunnel) | A tunnel provider or the user's own VPS | `cloudflared tunnel`, `ngrok http`, `ssh -R`, `frp`, `Tailscale Funnel` |
| **Rendezvous + relay service** | A service both sides poll | the current ZeroCreds relay; a wormhole mailbox + transit relay |
| **Overlay network** | A control plane that brokers connectivity, plus relays when the direct path fails | Tailscale / Headscale / WireGuard |
| **Recipient-hosted endpoint** | The recipient, if it has a public address | the recipient's own ZeroCreds instance behind a public URL |
| **Shared application store** | A mailbox / object store both sides already have | the recipient's IMAP mailbox, an S3-compatible bucket |

The last two rows are the only ones that do not introduce a *new* party into the path, and both require the recipient (or the sender) to already have a server.

### 3.4 What end-to-end encryption does and does not buy

The envelope already guarantees that a transport cannot decrypt the credential (§4). That removes the **confidentiality** reason to trust the intermediary. It does not remove:

* **Metadata**: client IPs, timing, request paths, sizes, the provider name if it leaks outside the sealed payload.
* **Availability**: the transport can refuse, delay, drop or replay traffic. AEAD detects replay and substitution, but it cannot stop a transport from *not delivering*.
* **Compulsion**: a transport operator can be compelled to hand over ciphertext and metadata. It cannot hand over the credential, because the fragment secret never leaves the recipient's process.

So the honest promise is: **"the transport cannot read your credential, cannot hand it to anyone, and cannot forge a replacement credential; it can see who talked when, and it can refuse to deliver."** The UX must say exactly that (§10).

---

## 4. Threat model

### 4.1 Assets

| Asset | Where it lives | Exposure if leaked |
|---|---|---|
| Credential value | Sender's Keychain until claimed; sealed in the envelope | Full account access |
| Fragment secret (256-bit) | URL fragment; recipient's process only | Ability to claim and decrypt |
| Invitation link | Chat/email of the user's choice | One-time access to the credential |
| Share metadata | `provider`, `account_alias`, `expires_at`, `setup_prompt` inside the sealed payload | Which service, which account label |
| Transport metadata | Transport operator | Who, when, how big |

### 4.2 Adversaries and what they can do

| Adversary | Capabilities | Bounded by |
|---|---|---|
| Transport / relay operator | Sees ciphertext, IPs, timing, paths; can block, delay, replay, or withhold | AEAD + AAD + one-time secret; can still deny service |
| Network observer (ISP, Wi-Fi) | Sees TLS metadata to the transport; not the plaintext | TLS to the transport host; the fragment never crosses the wire |
| Malicious or over-scoped recipient | Holds the link → gets the credential | By design; one-time claim, TTL, explicit "a copied PAT acts as its owner" warning |
| Compromised endpoint | Reads the Keychain | Out of scope of the transport question |
| Compelled operator | Hands over stored ciphertext + metadata | Cannot hand over the credential; cannot forge a valid envelope |

### 4.3 Transport contract (invariants every transport must satisfy)

These are the properties the implementation and the tests must enforce. They are the reason a transport can be swapped safely.

* **T1 — Secret locality.** The fragment secret never leaves the recipient's process. It is never sent to any server, never placed in a path, a query string, a header or a log.
* **T2 — Claim proof.** A claim is only accepted if the claimant proves knowledge of the fragment secret *and* the proof is bound to the claimant's own ephemeral X25519 key: `HMAC-SHA256(secret, "<id>:<pubkey>")`. A third party therefore cannot claim on the recipient's behalf.
* **T3 — Session binding.** The envelope is AEAD-bound to the session id (AAD). An envelope cannot be moved between sessions, between transports, or between links.
* **T4 — One winner.** At most one claim is honoured; the relay must not be able to release two distinct valid envelopes for one invitation.
* **T5 — Integrity.** The transport must not be able to alter the envelope: AES-GCM rejects any modification, and the recipient surfaces a decryption failure instead of saving anything.
* **T6 — Lifecycle.** TTL (1–120 min) and explicit cancellation are enforced by the relay, not by the transport. The transport is not allowed to extend the life of an invitation.
* **T7 — Hygiene.** No credential value, bearer link or token value in fixtures, issues, CI logs, or the invite page. Probes use random, non-secret values.
* **T8 — Informed consent.** Before claiming, the recipient's agent must show the invitation's host and its trust class ("this asks your agent to talk to `host` — a third-party network provider that can see ciphertext but not the credential").

---

## 5. Candidate transports

Each entry covers the questions from the issue: setup for both sides, NAT/CGNAT behaviour, who observes metadata / can delay / block / replay / substitute, whether the operator can decrypt, expiry / one-time claim / cancellation / offline behaviour / recovery, cost / self-hosting / abuse controls, and a verdict.

### 5.1 Cloudflare Tunnel (and equivalents: `ngrok`, `frp`, `rathole`, `ssh -R`, `sish`, `Tailscale Funnel`)

* **Setup.** The sender installs a tunnel client (`cloudflared`, `ngrok`, …) and points it at a local HTTP port. The recipient needs nothing. A *quick* tunnel needs no account; a *named* tunnel needs a Cloudflare account and a domain on Cloudflare's DNS (or a CNAME to the tunnel hostname with partial DNS).
* **NAT / CGNAT.** Fully outbound — this is the reason it works behind CGNAT. The tunnel client dials out and holds the connection; the edge terminates TLS and forwards to the sender.
* **Observers.** Cloudflare (or the VPS operator) sees the recipient's IP, timing, URL paths, request sizes and the ciphertext. It can delay, block, or drop. It can replay a captured envelope — harmless, because the envelope is AEAD-bound to the session id and the claimant needs the fragment secret. It cannot substitute a valid envelope: the GCM tag and the claim proof stop it.
* **Can it decrypt?** No. The fragment secret never leaves the recipient's process; the envelope is sealed to the recipient's X25519 key. Cloudflare is a **network provider in the path**, not proof of a direct or trustless route — the traffic is decrypted by the edge and re-encrypted to the tunnel, and the operator is part of the trust boundary even though it cannot read the credential.
* **Lifecycle.** Expiry, one-time claim and cancellation are enforced by our relay behind the tunnel, so they work unchanged. The sender (and the tunnel) must stay online until the claim.
* **Cost / self-hosting / abuse.** Cloudflare Tunnel is free; quick tunnels have no uptime guarantee, a changing hostname per start, a 200 in-flight request ceiling and no SSE (our relay is plain JSON polling, so SSE is irrelevant). `ngrok`'s free tier allows 20 000 HTTP requests/month, 1 GB egress and up to 3 online endpoints. `ssh -R`/`sish`/`frp`/`rathole` are free and fully self-hosted on any VPS the user already has, with token auth and TLS between client and server.
* **Verdict — supported, optional.** Accepted as one concrete way to satisfy the "user-supplied tunnel" contract. Not the default: Cloudflare documents that Russian ISPs throttle Cloudflare-protected traffic to roughly 16 KB per connection, which makes a tunnel unreliable for the audience that reported the CGNAT problem in the first place. A stable hostname for the whole invitation lifetime also rules out quick tunnels, so a named tunnel (account + domain) is required.

### 5.2 WebRTC data channel with STUN and TURN fallback

* **Setup.** Both peers need a WebRTC stack. In an MCP agent (Node) that means a native binding such as `wrtc`, which conflicts with the repository's "plain Node, no build step, stdlib only, auditors must be able to read the code" rule. The browser cannot be the peer, because the agent's tool call must complete unattended.
* **NAT / CGNAT.** Hole punching succeeds only when at least one side has endpoint-independent mapping and permissive filtering. With two CGNAT peers it fails, and the connection falls back to **TURN**, i.e. a relay — a third party in the path, with the same trust class as a relay.
* **Observers.** The STUN server learns both peers' reflexive addresses (a metadata leak that a relay does not have). The TURN server sees the ciphertext and the timing. ICE needs a **signalling channel** to exchange candidates — which is itself a rendezvous service, i.e. the very third party the issue wants to avoid.
* **Can it decrypt?** No (DTLS/SRTP plus our own AEAD). But the stack that provides that guarantee is large.
* **Lifecycle.** The data channel dies with the last peer; expiry and cancellation would have to be re-implemented on top of it. One-time claim and the claim proof would have to be re-implemented too.
* **Cost / self-hosting / abuse.** TURN needs a public server with an open relay port range, long-term credentials, and abuse controls; static TURN credentials are a known abuse vector (a captured credential turns the server into an open proxy).
* **Verdict — defer.** It replaces one trusted third party (a relay) with two (signalling + TURN) plus a large native dependency, and buys no confidentiality that the existing envelope does not already provide.

### 5.3 Tor onion service

* **Setup.** The sender runs a Tor daemon and publishes an onion service; the recipient must run a Tor client (Tor Browser or a SOCKS-capable agent). Both peers need Tor installed.
* **NAT / CGNAT.** Works behind CGNAT — the onion service is reached through Tor's circuits.
* **Observers.** Onion addresses are the only identifier; the guard/relay chain hides the sender's IP from the recipient and vice versa. Strongest metadata resistance of the candidates.
* **Can it decrypt?** No — onion services are additionally encrypted hop by hop, and our envelope is sealed on top.
* **Lifecycle.** Onion services are reachable only while the sender's daemon runs; the relay behind it handles expiry/one-time claim.
* **Cost / self-hosting / abuse.** Free and self-hostable; abuse is handled by Tor's own reputation systems, but the practical burden falls on the user (installing and configuring Tor, plus bridge/obfs4 use on censored networks).
* **Verdict — defer, but keep the door open.** The metadata win is real but not the bottleneck we have: our transport is already confidential. The costs are a heavy per-peer dependency, degraded connectivity on Russian networks (bridge operators report ISP-level interference with obfs4/WebTunnel in Russia), and long, error-prone addresses. Later, if we want it, an onion service is just another tunnel base URL, so nothing in the design forecloses it.

### 5.4 Tailscale / Headscale / WireGuard overlay

* **Setup.** Both peers install the client and enrol in a tailnet. That means accounts on a coordination server (Tailscale's) or a self-hosted control plane (Headscale) — for an ad-hoc share with a colleague who is not already on your tailnet, this is a provisioning problem, not a transport problem.
* **NAT / CGNAT.** The client dials out to coordination/DERP servers and relays traffic when a direct path is impossible. Works behind CGNAT.
* **Observers.** The coordination server sees the node graph, node keys, and (in the normal case) the peers' real IPs — more metadata than a relay sees. WireGuard encrypts the payload; the coordinator still knows who talked to whom and when.
* **Can it decrypt?** No.
* **Lifecycle.** A tunnel that stays up is a permanent capability — worse for one-time credentials than a short-lived relay session.
* **Cost / self-hosting / abuse.** Tailscale's Personal plan is free (up to 6 users, unlimited user devices); Standard is $8/user/month. Headscale is self-hostable. Static credentials and long-lived nodes are the abuse surface.
* **Verdict — defer as a *share* transport; recommend as a *deployment* option.** For organisations that already run Headscale or Tailscale, the right move is to point the relay at the shared tailnet (or run a headscale-hosted relay), not to invent a new share protocol. For ad-hoc sharing, enrolment cost and coordination-plane metadata make it worse than a one-shot tunnel.

### 5.5 Recipient polling an encrypted mailbox

* **Setup.** The sender uploads the sealed envelope under a long random object name to a mailbox the recipient can poll — an S3-compatible bucket, an IMAP/SMTP mailbox, or a self-hosted MinIO. Both peers need credentials for that mailbox, and the object name must travel out of band (it is part of the invitation link).
* **NAT / CGNAT.** Trivially fine — both sides only make outbound requests.
* **Observers.** The mailbox operator sees the object name, the uploader's and the reader's IPs, and the timing; it stores the ciphertext at rest. It can delete, withhold or replace the object; a replacement fails the GCM tag check. Storage lifetime is longer than a relay's, which enlarges the window for later compromise (ciphertext only — the secret is still with the recipient).
* **Can it decrypt?** No.
* **Lifecycle.** Best offline behaviour of all candidates: the sender uploads once and can go offline immediately. One-time claim and expiry would be enforced by the sender's signed state (e.g. a signed envelope with an expiry + a "claimed" marker written by the recipient), which is *more* code than today's relay state machine.
* **Cost / self-hosting / abuse.** Free tiers exist but "which mailbox?" has no universally available answer for our audience, and every candidate provider is a company that sees who stores what.
* **Verdict — defer, but design for it.** The API in §9 keeps `transport.kind` open so `mailbox` can be added without touching the envelope. It is the natural second transport after `tunnel`, especially for senders who cannot stay online.

### 5.6 Magic Wormhole (or a comparable mature end-to-end transfer protocol)

* **Setup.** `wormhole` (Python, MIT, 0.24.0 released May 2026 — actively maintained) on both sides. Interoperating without the Python client means re-implementing SPAKE2 + the mailbox and transit protocols in Node.
* **NAT / CGNAT.** The mailbox server performs the rendezvous; the transit relay forwards the encrypted bulk data. Works behind CGNAT.
* **Observers.** The mailbox and transit servers see the wormhole code, IPs and timing, but not the payload: the key is derived from a PAKE (SPAKE2) the server cannot compute.
* **Can it decrypt?** No.
* **Lifecycle.** The wormhole code is a short, human-typable phrase (`4-purple-sausages`) — deliberately low entropy, because the PAKE protects it. That is a *different* security model from ours: our link fragment is 256 bits of entropy and is delivered over a channel the user chooses. The wormhole UX also does not fit our one-time-URL flow, and it needs a third-party service that is volunteer-run with no SLA.
* **Cost / self-hosting / abuse.** Free; a self-hosted mailbox + transit relay is possible but is a service to operate.
* **Verdict — defer as an interop target; adopt as a design reference.** Its PAKE is unnecessary for us *because* we already have a high-entropy out-of-band secret; the parts worth copying are the transport-independent key derivation and the "server sees nothing" property, which we already have.

### 5.7 Baseline: the ZeroCreds-hosted relay (today)

Already end-to-end encrypted; the residual trust is metadata, availability and operator compulsion, not confidentiality. It works behind CGNAT today, with zero setup for the user. **Keep it as the default fallback**, because for many users it remains the lowest-friction option, and the wording must be honest about what the website can and cannot see.

### 5.8 Self-hosted ZeroCreds relay (configuration, not code)

`ZEROCREDS_SHARE_RELAY_URL` (config key `shareRelayUrl`, `server/src/server.js:1278`) already allows pointing the relay at the user's own instance. The sender connects outbound; the recipient polls. The ZeroCreds website is not in the path at all, and the operator is the user. This is the strongest trust answer available today, needs no new transport, and is limited only by "the user already runs a server".

---

## 6. Comparison

| Transport | Setup for both peers | Works with **both** peers behind CGNAT | Intermediary sees metadata | Intermediary can decrypt | Sender may stop running the transfer afterwards | One-time claim + expiry enforced by | Cost / self-host | Verdict |
|---|---|---|---|---|---|---|---|---|
| ZeroCreds relay (today) | none | yes | IPs, timing, sizes | **no** | no | our relay | free / self-hostable | keep as default fallback |
| Self-hosted relay | user runs a server | yes | IPs, timing, sizes | **no** | no | our relay | user's own server | document it (config only) |
| **User tunnel → sender relay (proposed)** | sender runs a tunnel client | yes | IPs, timing, paths, sizes | **no** | no | our relay | free / any VPS | **preferred first implementation** |
| Cloudflare Tunnel | sender installs `cloudflared` | yes | IPs, timing, paths, sizes | **no** | no | our relay | free tier; degraded for RU | optional, not default |
| ngrok / frp / `ssh -R` | sender runs a tunnel client | yes | IPs, timing, paths, sizes | **no** | no | our relay | free / self-hostable | optional, not default |
| WebRTC + STUN/TURN | native WebRTC both sides | only with TURN | IPs (STUN), timing | **no** | no | re-implementation | TURN server cost | defer |
| Tor onion service | Tor on both sides | yes | almost none | **no** | no | our relay | free | defer |
| Tailscale / Headscale | enrolment both sides | yes | node graph, IPs | **no** | no — the relay still runs on the sender | tailnet ACLs | free–$8/user/mo | defer as share transport |
| Mailbox polling | mailbox access both sides | yes | object name, IPs, timing | **no** | **yes** | signed state (new code) | provider-dependent | defer (design for it) |
| Magic Wormhole | Python on both sides | yes | code, IPs, timing | **no** | yes | wormhole | free | defer; use as reference |

---

## 7. Cloudflare Tunnel: the explicit verdict (issue question 4)

**Is Cloudflare Tunnel a viable optional transport? Yes — as one implementation of the "user-supplied tunnel" contract, and nothing more.**

* It is a **network provider that proxies encrypted traffic**. It is not evidence of a direct route, and it is not a trustless path: the edge terminates TLS, sees the recipient's IP, the timing, the request paths and the ciphertext, and can refuse or delay delivery. The route from the recipient to the sender is *through Cloudflare*, not peer-to-peer.
* It cannot decrypt the credential, because the fragment secret stays in the recipient's process and the envelope is sealed to the recipient's X25519 key. This is a property of our envelope, not of Cloudflare.
* Practical limits for our use: quick tunnels have no uptime guarantee and a hostname that changes on every start (unusable for a link that must live for the invitation TTL); a named tunnel needs an account and a domain on Cloudflare's DNS; Cloudflare's own support documentation states that Russian ISPs throttle Cloudflare-protected traffic to about 16 KB per connection, which makes it a poor default for the audience that raised this issue.
* Therefore: **accept any user-supplied `https` tunnel URL, document `cloudflared` as one way to produce one, never present it as "direct" or "private", and never make it the default path for Russian users.**

---

## 8. Recommendation

### 8.1 Preferred first implementation: transport kind `tunnel`

**The sender's own ZeroCreds relay, exposed through a tunnel the user controls.**

```
   recipient agent                       sender's computer                tunnel / VPS
   ┌────────────────┐                    ┌──────────────────────┐          ┌──────────────┐
   │ POST  /claim   │ ──── ciphertext ──▶│ relay on loopback    │ ──out──▶ │ public HTTPS │
   │ GET   /envelope│ ◀── ciphertext ────│ (recipient-facing)   │ ◀─out─── │ endpoint    │
   │ POST  /ack     │                    │ owner ops stay local │          └──────────────┘
   └────────────────┘                    └──────────────────────┘
        fragment secret stays here        Keychain read here              sees ciphertext only
```

Why this one:

1. **It satisfies the hard constraint.** The tunnel is outbound-only, so it works with both peers behind CGNAT.
2. **The intermediary cannot decrypt.** The secret never leaves the recipient's process; the envelope is AEAD-sealed to the recipient's key; the claim proof binds the claim to the recipient's key.
3. **The ZeroCreds website leaves the path.** No special website, no shared operator, no shared infrastructure between the two peers.
4. **Smallest defensible code delta.** The sender-hosted relay, the public/internal listener split, the envelope, the claim proof, the one-time claim, the TTL and the cancellation already exist in the `direct` transport. The new part is (a) an origin policy that accepts an `https` hostname, (b) a transport registry in the API, (c) a reachability probe for the tunnel URL, (d) recipient-side origin confirmation.
5. **No new dependency in the agent.** The tunnel is an external process the user already chose; the agent speaks plain HTTPS to it. The repository keeps its "plain Node, stdlib only, auditable" property.
6. **Replaceable and self-hostable.** The same code path serves `ssh -R` to the user's own VPS, a company Headscale/Tailscale, `frp`, `ngrok`, or `cloudflared`. The user can always choose the one they already trust; the ZeroCreds site is never required.
7. **UX continuity.** The link format, the one-time claim, the "the sender must stay online" wording and the copy of the invitation message all stay the same. Only the host in the link changes.

What it does **not** solve, and must be stated in the UX:

* The tunnel operator still sees metadata (IPs, timing, sizes) and can refuse or delay delivery — availability is not solved by encryption.
* The sender's machine and the tunnel must stay online until the claim.
* The tunnel's TLS certificate is trusted by the recipient's operating system, not by ZeroCreds. The recipient's agent must say whose certificate is being trusted (public CA for a named tunnel; the VPS's own certificate for `ssh -R`).

### 8.2 Rejected and deferred, with reasons

| Option | Decision | Reason |
|---|---|---|
| WebRTC data channel + STUN/TURN | **Reject for now** | Needs a signalling rendezvous anyway plus a TURN relay, a native WebRTC dependency, and a re-implementation of claim/expiry semantics — more trusted parties and more audit surface for no confidentiality gain |
| Tor onion service | **Defer** | Both peers must run Tor; degraded on Russian networks; heavy per-peer dependency for a metadata property we do not currently need. Design keeps the door open (an onion service is just another tunnel URL) |
| Tailscale / Headscale / WireGuard as the share transport | **Defer; recommend as deployment** | Enrolment and control-plane metadata make ad-hoc sharing worse than a one-shot tunnel; but for organisations with an existing tailnet, pointing the relay at the tailnet is the right move |
| Recipient polling an encrypted mailbox | **Defer (design for it)** | Strongest offline behaviour and no new parties, but it needs mailbox access on both sides and a new signed-state implementation of one-time claim/expiry |
| Magic Wormhole interop | **Defer; adopt as reference** | Python on both sides or a full SPAKE2 re-implementation; the 3-word code model does not fit our high-entropy one-time link; the public services have no SLA |
| Making Cloudflare Tunnel the default | **Reject** | Cloudflare documents ISP throttling of Cloudflare-protected traffic for Russian users (~16 KB/connection); quick tunnels change hostname per start |
| Replacing the envelope with a new scheme | **Reject** | The existing X25519 + HKDF + AES-GCM envelope with a session-id AAD already gives the exact guarantees the transports need; a new scheme would add risk without adding a property |

### 8.3 The no-code step we should ship first

Document and surface the existing capability: point `ZEROCREDS_SHARE_RELAY_URL` at the user's own ZeroCreds instance (or any compatible relay) to remove the shared website from the path entirely. This is a configuration change, needs no transport work, and answers the trust half of the issue for users who already run a server. It should appear in `share_options` as a first-class option ("use my own relay"), not only in a config file.

---

## 9. Protocol and API boundary (issue question 5)

### 9.1 Design rule

> The transport supplies **a base URL and a byte pipe**. It never supplies key material, and it never sees the fragment secret.

Everything cryptographic lives in the envelope + claim proof, which stay byte-for-byte identical across transports. This is what makes `share_create` transport-agnostic.

### 9.2 Transport descriptor

`GET /api/local/shares/options` should return a list of descriptors instead of two flat fields:

```jsonc
{
  "choice_required": true,
  "transports": [
    {
      "kind": "relay",              // relay | direct | tunnel | mailbox
      "label": "ZeroCreds website",
      "base_url": "https://zerocreds.ru",
      "operator": "zerocreds",      // zerocreds | self-hosted | user-provided | none
      "trust": "website",           // website | self-hosted | network-provider | none
      "can_read_credential": false, // always false: the envelope is sealed end-to-end
      "requires": [],               // e.g. ["router-port-forward"], ["tunnel-client"]
      "available": true,
      "description": "Plain-language sentence shown to the user, including what the operator can and cannot see."
    }
  ]
}
```

`can_read_credential` is `false` for every transport by construction; it is included so the agent can state the guarantee instead of implying it.

### 9.3 Create / claim

```
POST /api/local/shares
{
  "connection_id": "<32 hex>",
  "setup_prompt": "...",
  "ttl_minutes": 15,                       // 1..120, optional
  "transport": { "kind": "tunnel", "base_url": "https://<tunnel host>" }
  // backward compatible: "transport": "relay" | "direct" is still accepted and mapped
}

POST /api/local/shares/transport/setup
{ "kind": "tunnel", "base_url": "https://<tunnel host>" }
→ 200 { "base_url": "...", "verified_at": "...", "probe": "ok",
        "trust_class": "network-provider",
        "next_step": "Plain-language instruction for the user." }

POST /api/local/shares/claim
{ "share_url": "<full link with fragment>", "account_alias": "optional" }
→ 200 { "status": "saved", "connection_id": "...", "provider": "...", ... }
```

Reachability check for a tunnel: `GET <base_url>/api/share-relay/probe/<random 32 hex>` must answer `204`. The probe token is random and non-secret, and the probe carries no credential (invariant T7). Unlike the `direct` transport there is no public-IP comparison to make — the tunnel host *is* the public endpoint — so the check can be run by the sender itself instead of by the ZeroCreds server, which also keeps that check off our infrastructure.

`POST /api/local/shares/transport/setup` generalises the existing `POST /api/local/shares/direct/setup` (`server/src/server.js:2309-2392`): the same handler, with the origin policy and the reachability check chosen by `kind`.

### 9.4 Link format and recipient-side pinning

The link format was written for the tunnel research as:

```
<base_url>/api/share-relay/invite/<session id 32 hex>#<secret 64 hex>
```

It has since become shorter — `<base_url>/api/i/<session id 14 base64url>#<secret 22 base64url>` — and the older form still parses, so a link that is already in flight keeps working.

Only the host changes. The recipient's claim code is unchanged — with one deliberate change: `parseInvite` currently accepts only the configured relay origin or a public-IPv4 origin (`server/src/local-share.js:21-35`). It must additionally accept origins from the **user's configured transports**, and the agent must show the origin and its trust class before claiming (invariant T8). An origin that is in neither list is rejected exactly as today.

### 9.5 Wire protocol the transport must support

The transport must forward these unchanged (the relay is already implemented; the table states the contract a transport must not break):

| Method + path | Actor | Purpose | Transport obligation |
|---|---|---|---|
| `POST /api/share-relay/sessions` | owner (loopback) | create the invitation | never exposed publicly |
| `GET /api/share-relay/sessions/:id/poll` | owner (loopback) | learn about a claim | never exposed publicly |
| `POST /api/share-relay/sessions/:id/reject` | owner (loopback) | refuse a claim | never exposed publicly |
| `POST /api/share-relay/sessions/:id/envelope` | owner (loopback) | publish the sealed envelope | never exposed publicly |
| `DELETE /api/share-relay/sessions/:id` | owner (loopback) | cancel | never exposed publicly |
| `POST /api/share-relay/sessions/:id/claim` | recipient | claim with the proof | forwards the body unchanged |
| `GET /api/share-relay/sessions/:id/envelope` | recipient | fetch the envelope | forwards the body unchanged; must not cache |
| `POST /api/share-relay/sessions/:id/ack` | recipient | confirm receipt | forwards the body unchanged |
| `GET /api/i/:id` (and the older `GET /api/share-relay/invite/:id`) | anyone | the invite page | no credential material, no secret |

Transport obligations, restated as a checklist for a future transport implementer:

* Must not see, log, or be able to reconstruct the fragment secret.
* Must not deliver an envelope to more than one claimant (the relay enforces it; the transport must not fan out).
* Must not mutate, reorder into another session, or re-format bodies.
* Must enforce no caching of the envelope response (`Cache-Control: no-store`).
* Must not extend the TTL; the relay's `expires_at` is authoritative.
* Should tolerate the 1 s polling loop of both peers without rate-limiting it into failure.

### 9.6 What must not change

* The envelope structure `{ sender_key, iv, ciphertext, tag }` and the AEAD parameters.
* The claim proof `HMAC-SHA256(secret, "<id>:<pubkey>")`.
* The link format and the fragment semantics.
* The one-time claim, TTL and cancellation semantics.

---

## 10. UX: what we tell the user

The current wording ("the website cannot open and read it") is true but incomplete. The agent should state three things separately, in the user's language, in everyday words:

1. **Who carries the link.** "This invitation asks your agent to connect to `host`. That host is <the ZeroCreds website / your own server / a tunnel provider>. It sees the encrypted blob and the timing. It cannot read the credential and cannot give it to anyone."
2. **What the operator can still do.** "It can refuse or delay the delivery. If it is down, the invitation fails and you have to create a new one."
3. **Who holds the secret.** "The one-time code never leaves your computer; the link you pasted is the only copy."

And the existing warnings stay: a copied personal PAT acts as its owner; the full link grants access once; the sender's computer must stay online until the claim.

---

## 11. Test plan (synthetic values only)

No credential values, bearer links or token values in fixtures, issues or CI logs. The existing convention in `scripts/share-cross-platform.cjs` — synthetic provider `ci_fixture`, synthetic alias, synthetic token string — is reused.

### 11.1 Unit (CI, `node --test`)

| Test | Expectation |
|---|---|
| Transport registry | `options` lists every transport with `can_read_credential: false`, an `available` flag and a non-empty description |
| Origin policy: `tunnel` | accepts `https://host`, `https://host:8443`; rejects `http://host` (non-loopback), a URL with userinfo, query, fragment or a path, a bare `host` |
| Origin policy: `direct` | unchanged — public IPv4 with an explicit port only |
| Backward compatibility | `"transport": "relay"` and `"transport": "direct"` still map to the new descriptors |
| Envelope is transport-independent | an envelope produced under one transport decrypts through the claim flow of another; the payload structure and the AEAD parameters are identical (the sender key and the IV are fresh per envelope by design) |
| Claim proof | wrong secret → `409`; proof bound to another public key → rejected; timing-safe comparison path unchanged |
| Substituted envelope | an envelope with one flipped ciphertext byte fails GCM verification → `share decryption failed`, nothing is saved |
| Replayed envelope | an envelope from another session id fails on AAD → `share decryption failed` |
| Second claim | a second distinct claimant gets `409`, the first envelope is not re-served |
| Lifecycle | TTL expiry, explicit cancel, `saved_ack_unknown` path behave identically for every transport |
| Secret hygiene | no server-side log line, response body or fixture contains the fragment secret or a credential value |

### 11.2 Integration (CI)

* A **fake tunnel**: a local HTTPS reverse proxy in front of the sender's loopback relay, forwarding the recipient-facing paths and refusing the owner-facing paths (exactly as `direct-share.js:56-63` does today). This exercises the whole `tunnel` path without the internet and without an external dependency.
* Assertions: the owner's `poll`/`envelope`/`DELETE` paths are *not* reachable through the public surface (404), the recipient path works, and the share link produced by a `tunnel` transport has the tunnel host and the standard path + fragment.
* Reachability probe: the fake tunnel forwards `GET /api/share-relay/probe/<random 32 hex>` and the sender's listener answers `204` (the same route `direct-share.js:44-48` already exposes); a wrong host returns a clear error and no session is created.
* Claim across transports: the same envelope claimed through a `tunnel` transport decrypts to the same payload as through the `relay` transport (cross-transport compatibility).
* The existing peer-share CI already runs on Linux and Windows ([#157](https://github.com/Zerocreds-com/zerocreds-server/pull/157)); the new cases join the same matrix.

### 11.3 Local (developer machine)

1. `ssh -R 8443:127.0.0.1:<port> user@own-vps` (or `cloudflared tunnel --url http://127.0.0.1:<port>`) → `POST /api/local/shares/transport/setup` with the resulting `https://host` → create a share → claim it from a second local instance → the credential lands in the recipient's Keychain.
2. Confirm the fragment secret never appears in the sender's or the tunnel's logs (grep the local server log and the tunnel log for the fragment).
3. Confirm the recipient's agent shows the invitation host and trust class before claiming, and that an unconfirmed host is refused.
4. Kill the tunnel mid-invitation → the claim fails with the plain-language "the sender's computer must stay online" message, and no partial credential is written.
5. Re-run `python3 scripts/check-share-relay.py` against the deployment to confirm the shared relay is unaffected by the new transport.

### 11.4 CI wiring

* New file `server/test/share-transport.test.js` (unit) and additions to `server/test/local-share-routes.test.js` (integration); both run under the existing `node --test test/*.test.js` step in `.github/workflows/test.yml`.
* No new npm dependency, no new build step, no change to the deploy workflow.

---

## 12. Open questions

1. Should the recipient's allowlist of acceptable invitation origins be per-link (ask every time) or per-transport (remember the tunnel host once)? Recommendation: per-transport, with a visible "trusted transports" list the user can clear.
2. Should the sender's relay keep running after a successful claim? Today the session ends at `ack`; the tunnel should be closed by the user, and the agent should say so.
3. What is the honest wording for "your invitation is travelling through `host`"? The `share_options` copy is user-facing and needs a translation pass (Russian first, matching the rest of the product).
4. Should the mailbox transport be designed now (signature of the one-time claim state) even though it is deferred? Recommendation: yes, sketch the signed-state format in a follow-up issue before implementing `tunnel`, so the two do not diverge.
5. Do we want a transport-level "provider" field in the audit record, so that a later auditor can tell whether a given invitation travelled through the ZeroCreds site or through a tunnel?

---

## 13. Sources

Cloudflare
- Quick Tunnels — <https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/> (updated 2026-09-30): no account needed, changing hostname per start, no uptime guarantee, 200 in-flight requests, no SSE.
- Tunnels FAQ — <https://developers.cloudflare.com/cloudflare-one/faq/cloudflare-tunnels-faq/>: WebSocket support; arbitrary TCP requires the Cloudflare One Client.
- Potential disruption of services for Russian users — <https://developers.cloudflare.com/support/troubleshooting/general-troubleshooting/service-disruption/> (updated 2026-04-23) and <https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/> (2025-06-26): Russian ISPs throttle Cloudflare-protected traffic to roughly 16 KB per connection.
- ngrok free-plan limits — <https://ngrok.com/docs/pricing-limits/free-plan-limits>: 20 000 HTTP requests/month, 1 GB egress, up to 3 online endpoints.

Networking
- RFC 4787 (NAT behaviour: mapping and filtering) — <https://www.rfc-editor.org/rfc/rfc4787>
- RFC 6598 (Carrier-Grade NAT) — <https://www.rfc-editor.org/rfc/rfc6598>
- RFC 5780 (NAT behaviour discovery, STUN) — <https://www.rfc-editor.org/rfc/rfc5780>
- RFC 8445 (ICE) — <https://www.rfc-editor.org/rfc/rfc8445>
- TURN and why hole punching fails with address-dependent mapping — <https://www.fanyamin.com/webrtc/tutorial/build/html/2.transport/turn.html>
- TURN in production: coturn deployment and static-credential abuse — <https://openvidu.io/blog/2026/06/09/turn-key-considerations/> (2026-06-09)

Tor
- Client authorization for v3 onion services — <https://community.torproject.org/onion-services/advanced/client-auth/>
- v3 rendezvous specification — <https://torproject.gitlab.io/torproject/rend-spec-v3.html>
- Tor bridges and Russian ISPs — <https://forum.torproject.org/t/tor-bridges-affected-by-unrelated-block-of-connections-to-some-isps-in-russia/21053>

Overlays and transfer protocols
- Tailscale pricing (Personal free, Standard $8/user/month) — <https://tailscale.com/pricing>
- magic-wormhole package health (0.24.0, 2026-05, MIT) — <https://security.snyk.io/package/pip/magic-wormhole>
- Magic Wormhole mailbox server protocol (PAKE, server cannot read the payload) — <https://magic-wormhole.readthedocs.io/en/latest/server-protocol.html>
- ngrok/frp/rathole/sish comparison for CGNAT — <https://ipwithease.com/best-ngrok-alternatives/> (2026-10-09)

Internal
- Issue #158 — <https://github.com/Zerocreds-com/zerocreds-server/issues/158>
- Issue #155 (batch port checks) — <https://github.com/Zerocreds-com/zerocreds-server/issues/155>
- Issue #157 / PR #157 (probe backoff, peer-share CI on Linux and Windows) — <https://github.com/Zerocreds-com/zerocreds-server/pull/157>
- `docs/trust-architecture-verifiable-forms-and-releases.md` — the trust vocabulary used here
