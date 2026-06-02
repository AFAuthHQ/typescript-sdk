# @afauthhq/core

## 0.2.0

### Minor Changes

- Attested sessions (§10.7) — let an attestor-side revoke reach already-signed-up agents, without paying for per-request attestation.

  An `attested_only` service used to face a hard choice. Re-verify an attestation on **every** request and the attestor sits on every call's critical path; check it **once at signup** and thereafter trust the agent's signature, and revoking that agent's binding at the attestor **never reaches you** — the stolen key keeps working until your own revocation list catches it (the §8.5 blind spot). Attested sessions are the middle ground: the service keeps a _currently-valid_ attestation **on file** per account and challenges with `401 attestation_required` only once that freshness window lapses. Revoke the binding at the attestor and the agent can no longer mint a replacement, so every attested-session service drops the account within its window. It is the OAuth refresh pattern applied to attestation — the binding is the refresh token, the attestation is the short-lived access token.

  **`@afauthhq/server` — new.** `server.verifyAttested(req, body?)` gates your own authenticated endpoints (not the protocol endpoints, which self-verify): it always checks the RFC 9421 request signature, and when the request carries an `AFAuth-Attestation` header it verifies that token — audience-pinned to your `serviceDid` — and slides the freshness window; it throws `401 attestation_required` once no valid attestation is on file. Turn it on with the new `attestedSession: { store, mode, sessionTtlSeconds? }` option. Two modes: **`strict`** (default — the window is the attestation's own `exp`, ≤ 15 min, so you never serve past a token's expiry) and **`extended`** (the window is `sessionTtlSeconds`, refreshed on each presentation — relief from re-mint cadence in exchange for a longer revocation latency you choose). Also exported: `AttestedSessionGate`, the `AttestedFreshnessStore` interface, and `MemoryAttestedFreshnessStore`. Advertise the capability with the new `attested_session` value in your discovery document's `features`.

  **`@afauthhq/worker` — new.** `KvAttestedFreshnessStore`, a Cloudflare KV-backed `AttestedFreshnessStore`. It sets each KV entry's TTL to the remaining window, so lapsed sessions self-evict — the gate is reactive, with no background sweep. Wire it as `attestedSession: { store: new KvAttestedFreshnessStore(env.AFAUTH_ATTESTED) }`.

  **`@afauthhq/agent` — new.** `AttestedFetcher` runs the agent side of the loop for you: it signs each request and, on `401 attestation_required`, mints a fresh attestation via `TrustClient` and retries once (re-signing with a new nonce). Reactive by default — steady-state requests carry no attestation header; pass `proactive: true` to attach a cached attestation up front and skip the extra round-trip at each window boundary. A refused mint surfaces as a terminal `TrustHttpError` (`isBindingRevoked()` / `isBindingExpired()`): re-link the agent, don't retry.

  **`@afauthhq/core`.** The `DiscoveryDocument` `features` union now accepts `"attested_session"`.

  Guide: https://docs.afauth.org/guides/keep-attested-access-live · model: https://docs.afauth.org/concepts/revocation

- BREAKING: remove `did:web` as an agent account DID method.

  Agents typically run on user machines behind home routers and cannot host a persistent web domain, so `did:web` is not a viable _agent_ identity. Agent account identifiers are `did:key` only.

  Removed:

  - `DidWebResolver` and `DidWebResolverOptions` (`@afauthhq/server`)
  - `CompositeDidResolver` (`@afauthhq/core`) — it existed only to compose `did:key` + `did:web`; with one agent method it has no purpose. Supply a custom `DidResolver` if you ever accept additional methods.

  Unchanged (still `did:web`): the service's own `service_did`, owner-recipient DIDs (`--type did`), and service-audience identifiers. `DidKeyResolver`, the `DidResolver` interface, and the `Verifier`'s `didResolver` option remain.

## 0.1.0

### Minor Changes

- Initial v0.1 alpha release of the AFAuth TypeScript SDK.

  The four `@afauthhq/*` packages implement the AFAuth v0.1 protocol
  (see [AFAuthHQ/spec](https://github.com/AFAuthHQ/spec)) across the
  M0–M4 milestones:

  - **M1** — Ed25519 keypair generation, RFC 9421 canonicalisation,
    `did:key` codec, full signature verification including replay
    protection and clock-skew tolerance.
  - **M2** — owner invitation and claim completion with the §7.7 match
    relation, reference email recipient handler, atomic invitation
    storage.
  - **M3** — pre-claim key rotation, §8.4 owner-initiated revocation,
    durable revocation list.
  - **M4** — full §11 error envelope coverage, replay-window
    conformance against the spec's §C.5 and §C.6 vectors.

  All 17 §11.3 reserved error codes are declared and produce the
  canonical envelope shape. All 29 spec test vectors pass through the
  SDK's `Verifier.verify`.

- Stable `0.1.0` release. Carries the four pre-publication critical
  fixes identified during the alpha review:

  - **LICENSE.** Each package now ships its MIT LICENSE file in the
    published tarball (alpha tarballs were missing the file even
    though `package.json` declared MIT).
  - **`extractOwnerSession` fails closed.** The reference Worker
    template now requires an explicit `AFAUTH_DEV_TRUST_HEADER=true`
    env var before the demo-only `X-Owner-Session` header path is
    accepted. Production deployments derived from the template will
    reject claim attempts that don't go through a real session
    extractor.
  - **`DurableObjectNonceStore` ships in `@afauthhq/worker`.** Provides
    the §5.6 atomic insert that Cloudflare KV can't. The reference
    Worker prefers DO when the binding is configured; `KvNonceStore`
    remains exported with a prominent JSDoc warning about its
    eventually-consistent replay window.
  - **`createNonceDurableObject()` factory** for users to register
    the DO class in their `wrangler.toml`.

## 0.1.0-alpha.0

### Minor Changes

- Initial v0.1 alpha release of the AFAuth TypeScript SDK.

  The four `@afauthhq/*` packages implement the AFAuth v0.1 protocol
  (see [AFAuthHQ/spec](https://github.com/AFAuthHQ/spec)) across the
  M0–M4 milestones:

  - **M1** — Ed25519 keypair generation, RFC 9421 canonicalisation,
    `did:key` codec, full signature verification including replay
    protection and clock-skew tolerance.
  - **M2** — owner invitation and claim completion with the §7.7 match
    relation, reference email recipient handler, atomic invitation
    storage.
  - **M3** — pre-claim key rotation, §8.4 owner-initiated revocation,
    durable revocation list.
  - **M4** — full §11 error envelope coverage, replay-window
    conformance against the spec's §C.5 and §C.6 vectors.

  All 17 §11.3 reserved error codes are declared and produce the
  canonical envelope shape. All 29 spec test vectors pass through the
  SDK's `Verifier.verify`.
