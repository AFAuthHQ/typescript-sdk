# `@afauth/server`

Service SDK for the AFAuth Protocol. Verifies signed requests per
§5.5/§5.6, runs the owner-invitation and claim-completion ceremonies
per §7, handles pre-claim key rotation per §8.1, and serves the
discovery and account-introspection endpoints.

## Quickstart

```typescript
import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  Server,
} from "@afauth/server";

const server = new Server({
  nonceStore: new MemoryNonceStore(),
  revocationList: new MemoryRevocationList(),
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  discovery: { /* see @afauth/agent DiscoveryDocument */ },
  baseUrl: "https://api.example.com",

  // §7.2: redirect_url is rejected unless its host is in this list.
  redirectAllowList: ["yourapp.com"],

  // §6.3: implicit signup on first touch. Default true.
  implicitSignup: true,
});
```

## Exports

- **`Server`** — five endpoint handlers (`handleDiscovery`,
  `handleOwnerInvitation`, `handleClaimCompletion`,
  `handleKeyRotation`, `handleAccountIntrospection`) plus
  `revoke(did)` for §8.4 owner-initiated revocation.
- **`Verifier`** — standalone request verifier (§5.5 + §5.6). Use
  directly as an edge plugin (Appendix E) or as the front half of
  `Server`. Accepts an optional `didResolver` — default is
  `did:key`-only.
- **`DidWebResolver`** — §3.1.2 resolver. Fetches and validates
  `https://<host>/.well-known/did.json`; TLS-only; configurable
  positive + negative cache. Compose with `did:key` via
  `CompositeDidResolver` from `@afauth/core` to accept both methods
  in one `Verifier`.
- **`assertFreshOwnerSession(session, { maxAgeSeconds })`** —
  §7.5 freshness floor for post-claim owner-binding routes
  (revoke, rotate, change-credential, add-recovery-contact, ...).
  Throws `owner_session_too_stale` (403) when the session's
  `authenticatedAt` is missing or older than the window. Call this
  from YOUR owner-binding routes; the SDK does not call it
  automatically (it is NOT enforced by `handleClaimCompletion`).
- **Rate limiter** (§11.3) — `RateLimiter`, `RateLimitConfig`,
  `RateLimitDecision`, `MemoryRateLimiter`, `ServerRateLimits`.
  Pass `rateLimiter` + `rateLimits` to `Server` to gate
  per-route per-DID buckets; over-limit calls return `429
  rate_limit_exceeded` with `Retry-After`.
- **Attestation** (§10) — `Attestor`, `AttestationClaims`,
  `HmacAttestor` (HS256 shared-secret), `JwksAttestor` (asymmetric
  via JWKS URL), `MultiAttestor` (dispatch by `iss`). Pass
  `attestor` to `Server`; §9.2 `attested_only` enforced
  automatically on the implicit-signup path.
- **Stores** — `NonceStore` + `MemoryNonceStore` (lazy GC on every
  Nth insert), `AccountStore` + `MemoryAccountStore` (atomic
  invitation supersession with O(1) reverse index),
  `RevocationList` + `MemoryRevocationList`. Production-grade
  durable stores ship in [`@afauth/worker`](../worker/)
  (`D1AccountStore`, `KvNonceStore`, `KvRevocationList`,
  `KvRateLimiter`).
- **Recipient handlers** — `RecipientHandler<R>` interface; ships
  `consoleEmailHandler` for local development (logs the magic link
  to `console.error`).

## See also

- [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec) — protocol spec.
- [`@afauth/worker`](../worker/) — Cloudflare Workers bindings that
  route requests to this Server's handlers.
