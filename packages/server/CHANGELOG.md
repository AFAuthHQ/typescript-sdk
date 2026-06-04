# @afauthhq/server

## 0.6.0

### Minor Changes

- Align `defineService` discovery paths with the agent's request builders so a default `@afauthhq/agent` interoperates with a default `defineService` service out of the box. Previously the two diverged — the agent signed canonical `/afauth/v1/...` paths while `defineService` synthesized different ones — so a default agent received a 404.

  - **server:** `synthesizeDiscovery` now advertises the canonical §4.1 endpoints (`/afauth/v1/accounts`, `/afauth/v1/accounts/me/owner-invitation`, `/afauth/v1/claim`, and `key_rotation`), matching the agent builders, the spec examples, the reference server, and `examples/worker`.
  - **agent:** `buildAccountIntrospection`, `buildOwnerInvitation`, and `buildKeyRotation` now accept an optional `discovery` document and resolve their request URLs from the service's advertised `endpoints` (§4.3/§4.5), so the agent also interoperates with services that mount custom paths. The canonical §4.1 paths remain the fallback when no discovery document is passed, so existing callers are unaffected.

- Harden `Verifier.verify` against two attestation / body-binding gaps:

  - **Body-binding (§5.2 / §5.5 step 7):** the verifier now requires `content-digest` to be a covered signature component whenever a request carries a body, and requires `Content-Digest` to be absent when it does not. Previously a signer could omit `content-digest` from the covered set and present an attacker-controlled body under an otherwise-valid signature (for example, rewriting an owner-invitation recipient to hijack the §7 claim link). The covered component list is bound via `@signature-params`, so an on-path attacker can only exploit a missing coverage — never add one.
  - **Attestation lifetime cap (§10.3.1):** `HmacAttestor` and `JwksAttestor` now accept an optional `maxLifetimeSeconds`. `trustAttestor()` pins it to 900s and requires `iat`, rejecting any attestation whose `exp - iat` exceeds the cap so a long-lived token from a compromised or misconfigured attestor key cannot outlive the §10.7 attested-session revocation window. Generic attestors stay uncapped unless you opt in (§10.2 imposes no generic ceiling).

## 0.5.0

### Minor Changes

- Multi-agent accounts — "one account, many devices" (§10.4.4). Replaces the single-DID account model: an account is now an opaque, stable `accountId` that groups every agent credential of one human, rather than being identified by a single `did:key`.

  How it works: in attested mode, `signupAgent({ did, principal })` groups agents by the verified `(iss, sub_h)` principal — a human's PC and phone agents resolve to the SAME `accountId`. Agents with no `sub_h` (attestation `off`/`optional`, or a runtime-only attestation) each get a distinct singleton account. This is how §10.4.4's "same human, same bucket" is now enforced — by grouping a second signup onto the existing account, not by rejecting it.

  **Breaking — `@afauthhq/server`:**

  - `Account` is reworked to `{ accountId, principal?: { iss, subH }, agents: AccountAgent[], state, owner?, … }` — no longer keyed on a DID. New `AccountAgent { did, addedAt, revoked? }`, one per device.
  - `AccountStore` is reworked: reads `getByAgentDid` / `getById` / `findByPrincipal(iss, subH)`; mutations `signupAgent({ did, principal }): SignupResult` (find-or-create + attach), `attachAgent`, `revokeAgent` (per-device), `revoke(accountId)` (whole-account), `rotateAgent(oldDid, newDid)` and `reKey(oldDid, newDid)`. `accountId` stays stable across rotation and re-key — the central simplification. Custom `AccountStore` / `SweepableAccountStore` implementations must adopt the new interface; the bundled `MemoryAccountStore` already does.
  - Owner binding is bound once and shared by every device on the account; whole-account `Account.revoked` is distinct from a single credential's `AccountAgent.revoked`.

  **Breaking — `@afauthhq/worker`:**

  - `D1AccountStore` implements the multi-agent model.
  - The D1 schema (`migrations/0001_init.sql`) is reworked: `afauth_accounts` (`account_id` PRIMARY KEY, `UNIQUE (iss, sub_h)`), `afauth_account_agents` (`agent_did` PRIMARY KEY → account), and `afauth_invitations`. The change is to `0001_init.sql` itself, so it does NOT re-migrate in place — **existing D1 databases provisioned on the previous single-DID schema must be recreated.**

### Patch Changes

- Security: the verifier now rejects a signature whose covered components omit a required component (`@method` or `@target-uri`), per §5.2 / §5.5 step 1 and `conformance.md` ("reject requests with … missing components").

  Previously the verifier rejected unknown/extra components and enforced the required signature _parameters_, but never checked that the always-required _components_ were present. A signature that omitted `@target-uri` therefore verified against any URL, silently losing the §12.2 cross-service replay binding for any under-covering signer (portable DIDs are the §3.3/D.1 default). First-party `Agent` signers always cover both components and were unaffected; this closes the gap for third-party signers and brings the verifier into conformance.

## 0.4.0

### Minor Changes

- **Attested sessions (§10.7) — revocation that reaches already-signed-up agents.** New `verifyAttested()` and the `attestedSession` option keep a valid attestation "on file" and re-challenge only once it lapses. Revoking an agent at the attestor now cuts off its access within minutes — without the cost of re-checking attestation on every request. [Guide](https://docs.afauth.org/guides/keep-attested-access-live) · [revocation model](https://docs.afauth.org/concepts/revocation).
- **Breaking — agents are `did:key` only.** Removed the `did:web` agent resolver (`DidWebResolver`, `CompositeDidResolver`). Your service's own `did:web` identity and owner DIDs are unaffected.

### Patch Changes

- **Fix:** an agent that tries to rotate a _claimed_ account's key now gets the correct `owner_binding_blocked` error instead of `owner_authentication_required`, so recovery tools can tell "the owner must step in" apart from "just sign in."
- Updated dependency `@afauthhq/core@0.2.0`.

## 0.2.0

### Minor Changes

- Close v0.1 spec gaps: `Account.createdAt`, `EXPIRED` state, and TTL
  sweep helper.

  **`@afauthhq/server`.** `Account.createdAt` is now a required field
  (set by `createUnclaimed` / preserved through `claim` and `rotate`).
  `AccountState` already declared `"EXPIRED"`; the server now actually
  enforces it — signup and key-rotation against an EXPIRED account
  return `account_expired` (HTTP 410). `GET /accounts/me` includes
  `created_at`, and `unclaimed_expires_at` when the discovery doc
  advertises `limits.unclaimed_ttl_seconds`.

  New `SweepableAccountStore` interface extends `AccountStore` with
  `listOpenAccounts()` + `expire(did, expiredAt)`. New top-level
  `sweepExpiredAccounts(store, { unclaimedTtlSeconds })` helper
  transitions UNCLAIMED / INVITED accounts past their TTL to EXPIRED —
  spec §6.1 / Appendix A make this mandatory but the SDK does not run
  it automatically (call it from your scheduler: cron, Workers
  scheduled trigger, Lambda EventBridge). CLAIMED → EXPIRED is
  forbidden by the spec; `expire()` throws `already_claimed` if asked.
  `MemoryAccountStore` implements `SweepableAccountStore` out of the box.

  **`@afauthhq/worker`.** `D1AccountStore` implements
  `SweepableAccountStore`. The D1 schema already had `created_at` —
  no migration needed. `listOpenAccounts()` queries
  `state IN ('UNCLAIMED', 'INVITED')` ordered by `created_at`; `expire()`
  flips state and atomically deletes any pending invitation row.

  **Breaking surface** (0.x semver): third-party `AccountStore`
  implementations now need to return `createdAt` on every `Account`.
  Built-in stores handle this transparently.

- AFAP-0006 `afauth-trust` attestor — client and server bindings.

  **`@afauthhq/agent` — new exports.** `TrustClient` drives the deep-link
  binding flow (`linkStart` → `linkPoll`) and mints short-lived
  audience-bound §10 attestation JWTs via `token(serviceDid)`. Tokens are
  cached per audience and refreshed at 80% of TTL. `TrustHttpError`
  surfaces the upstream error code so callers can distinguish
  `binding_expired` ("re-link"), `binding_revoked` ("ask the human"), and
  `verification_required` ("upgrade the account"). `AFAUTH_TRUST_DEFAULT_BASE`
  pins `https://trust.afauth.org` per AFAP-0006 §10.3.1.

  **`@afauthhq/server` — new `trustAttestor()` factory and audience
  binding.** `trustAttestor()` returns a pre-configured `JwksAttestor`
  against `iss = "afauth-trust"` and the AFAP-pinned JWKS URL — drop it
  into `MultiAttestor` alongside any service-operator HMAC or platform
  attestor:

  ```ts
  const attestor = new MultiAttestor([
    trustAttestor(),
    new HmacAttestor({ iss: "my-service", secret: SHARED_SECRET }),
  ]);
  ```

  `Attestor.verify` gains an optional third `opts` argument carrying
  `{ audience }`. `Server.handle*` now always passes the configured
  `serviceDid` as the audience — AFAP-0006 §10.3.1 makes this MUST for
  the afauth-trust attestor and defends every other attestor against
  cross-service token replay. Custom `Attestor` implementations should
  honor `opts.audience` when set.

  The `unsupported_attestor` error code remains absent from §11.3;
  unknown issuers continue to be reported as `invalid_attestation`. The
  prior JSDoc on `Attestor.verify` referenced it in error and has been
  corrected.

## 0.1.1

### Patch Changes

- **Fix**: Hash raw body bytes, not a UTF-8 roundtrip of them.

  `Server.handleOwnerInvitation` and `handleKeyRotation` previously
  read bodies via `await req.text()`, which replaces invalid UTF-8
  bytes with U+FFFD before `sha256ContentDigest` re-encodes them.
  Result: any RFC-9421-conformant agent (Go, Rust, Python) that signs
  the raw bytes of a binary payload (multipart, ZIP, protobuf) failed
  verification with `401 invalid_signature`. JSON bodies happened to
  work because UTF-8 is byte-identity on ASCII.

  Handlers now read via `arrayBuffer()` and pass `Uint8Array` to the
  Verifier; JSON.parse decodes only when the route's contract requires
  it. `Verifier.verify` and `VerifiedRequest.body` are widened to
  `string | Uint8Array | null` — the runtime already accepted bytes
  via `sha256ContentDigest`'s typeof-string branch; only the public
  type signature was lying.

  No protocol/spec change — RFC 9421 §2 already defines
  `Content-Digest` over bytes.

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

### Patch Changes

- Updated dependencies
- Updated dependencies
  - @afauthhq/core@0.1.0

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

### Patch Changes

- Updated dependencies
  - @afauthhq/core@0.1.0-alpha.0
