# @afauthhq/worker

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

- Updated dependencies
- Updated dependencies
  - @afauthhq/server@0.5.0

## 0.4.0

### Minor Changes

- **`KvAttestedFreshnessStore` — attested sessions on Cloudflare Workers.** A drop-in KV-backed store for §10.7 attested sessions (pair it with `@afauthhq/server`). Entries expire themselves, so there's nothing to clean up. [Guide](https://docs.afauth.org/guides/keep-attested-access-live).

### Patch Changes

- Updated dependencies `@afauthhq/core@0.2.0`, `@afauthhq/server@0.4.0`.

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

### Patch Changes

- Updated dependencies
- Updated dependencies
  - @afauthhq/server@0.2.0

## 0.1.1

### Patch Changes

- Bumps `@afauthhq/server` dependency to `0.1.1`, which fixes binary-body
  Content-Digest verification (`Server.handle*` now reads raw bytes via
  `arrayBuffer()` instead of a lossy `req.text()` roundtrip). No worker
  source changes.

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
  - @afauthhq/server@0.1.0

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
  - @afauthhq/server@0.1.0-alpha.0
