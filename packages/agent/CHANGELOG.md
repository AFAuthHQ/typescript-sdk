# @afauthhq/agent

## 0.5.0

### Minor Changes

- Align `defineService` discovery paths with the agent's request builders so a default `@afauthhq/agent` interoperates with a default `defineService` service out of the box. Previously the two diverged — the agent signed canonical `/afauth/v1/...` paths while `defineService` synthesized different ones — so a default agent received a 404.

  - **server:** `synthesizeDiscovery` now advertises the canonical §4.1 endpoints (`/afauth/v1/accounts`, `/afauth/v1/accounts/me/owner-invitation`, `/afauth/v1/claim`, and `key_rotation`), matching the agent builders, the spec examples, the reference server, and `examples/worker`.
  - **agent:** `buildAccountIntrospection`, `buildOwnerInvitation`, and `buildKeyRotation` now accept an optional `discovery` document and resolve their request URLs from the service's advertised `endpoints` (§4.3/§4.5), so the agent also interoperates with services that mount custom paths. The canonical §4.1 paths remain the fallback when no discovery document is passed, so existing callers are unaffected.

## 0.4.0

### Minor Changes

- Keyless trust mint — the agent authenticates `/v1/token` by signing the request with its account key (§3.1), not a bearer `binding_token`.

  `TrustClient.token()` now signs the mint request per RFC 9421 (§5) with the agent key and sends no `Authorization: Bearer` header — the keypair is the sole credential, so there is no standing bearer secret to store or leak.

  **Breaking (pre-1.0 minor):** `TrustBinding` no longer has a `binding_token` field; `linkPoll()` resolves to `{ binding_id, binding_token_expires_at }` (the binding's lifetime). Callers that persisted a `binding_token` should drop it — nothing else changes, because `token()` already held the agent key. Requires an attestor that accepts §5-signed mints; the default `afauth-trust` attestor does so as of this release.

## 0.3.0

### Minor Changes

- **`AttestedFetcher` — stay attested automatically.** Wrap your agent's requests and, whenever a service needs a fresh attestation (§10.7), it mints one and retries for you — long-running agents keep working without re-running signup. If the human has unlinked the agent it stops rather than retrying, so you know to re-link. [Guide](https://docs.afauth.org/guides/keep-attested-access-live).

### Patch Changes

- Updated dependency `@afauthhq/core@0.2.0`.

## 0.2.0

### Minor Changes

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

- `signRequest` and `SignedRequest.body` now accept `Uint8Array` so JS
  agents can sign binary bodies (multipart, ZIP, protobuf) symmetrically
  with non-JS agents on Go/Rust/Python. The default
  `content-type: application/json` header is set only for string bodies
  — binary callers know their own content-type. Pairs with
  `@afauthhq/server@0.1.1`, which fixes the symmetric server-side bug
  that prevented byte-accurate verification.

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
