# @afauthhq/server

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
