# `@afauthhq/server`

Service SDK for the AFAuth Protocol. Verifies signed requests per
§5.5/§5.6, runs the owner-invitation and claim-completion ceremonies
per §7, handles pre-claim key rotation per §8.1, and serves the
discovery and account-introspection endpoints.

## Quickstart

```typescript
import {
  consoleEmailHandler,
  defineService,
  MemoryAccountStore,
  MemoryNonceStore,
} from "@afauthhq/server";

const server = defineService({
  baseUrl: "https://api.example.com",
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  nonceStore: new MemoryNonceStore(),
  // attestation: "required" (default) wires trustAttestor() and sets
  //   discovery.billing.unclaimed_mode = "attested_only".
  // Override with "optional" (migration path) or "off" (paid/read-only).
});
```

`defineService` flips three protocol switches ON by default: it advertises
`attested_only` in the discovery doc (§9.2), configures `trustAttestor()`
as the verifier (§10), and enforces **per-principal uniqueness** (§10.4.4).
The net effect is spam-resistance out of the box — un-attested implicit
signups are rejected with `401 attestation_required`, and a second account
for a human who already has one (same `(iss, sub_h)`) is rejected with
`409 principal_already_registered`. "Same human, same bucket" holds by
default. The default slot is a process-local `MemorySubHUniquenessStore`, so
supply a durable, atomic `SubHUniquenessStore` (`D1SubHUniquenessStore`) in
production — or pass `subHUniqueness: false` to allow many agents per human
(fleet operators).

For `MultiAttestor` setups, custom `HmacAttestor`, or fully custom
discovery, use `new Server({...})` — see [Advanced configuration](#advanced-configuration).

### Advanced configuration

```typescript
import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  Server,
} from "@afauthhq/server";

const server = new Server({
  nonceStore: new MemoryNonceStore(),
  revocationList: new MemoryRevocationList(),
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  discovery: { /* see @afauthhq/agent DiscoveryDocument */ },
  baseUrl: "https://api.example.com",

  // §7.2: redirect_url is rejected unless its host is in this list.
  redirectAllowList: ["yourapp.com"],

  // §6.3: implicit signup on first touch. Default true.
  implicitSignup: true,
});
```

## Exports

- **`defineService(opts)`** — opinionated convenience factory. Returns
  a `Server` with `attestation: "required"` defaults (`unclaimed_mode:
  "attested_only"` + `trustAttestor()`). Pass `attestation: "optional"`
  or `"off"` to opt out. Override `discovery`, `attestor`, etc. for
  partial customizations; drop to `new Server({...})` for full control.
- **`Server`** — five endpoint handlers (`handleDiscovery`,
  `handleOwnerInvitation`, `handleClaimCompletion`,
  `handleKeyRotation`, `handleAccountIntrospection`) plus
  `revoke(did)` for §8.4 owner-initiated revocation.
- **`Verifier`** — standalone request verifier (§5.5 + §5.6). Use
  directly as an edge plugin (Appendix E) or as the front half of
  `Server`. Accepts an optional `didResolver` — default is
  `did:key`-only.
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
- **Attested sessions** (§10.7) — `server.verifyAttested(req)` gates
  your own authenticated routes on a currently-valid attestation,
  refreshing the window when the agent re-presents one and challenging
  with `401 attestation_required` when it lapses. Configure via
  `attestedSession: { store, mode }` (needs an `attestor`);
  `AttestedSessionGate` is the standalone primitive. Stores:
  `AttestedFreshnessStore` + `MemoryAttestedFreshnessStore` here,
  `KvAttestedFreshnessStore` in [`@afauthhq/worker`](../worker/).
- **Per-principal uniqueness** (§10.4.4) — `SubHUniquenessStore` +
  `MemorySubHUniquenessStore` enforce "at most one account per human":
  a signup whose verified `(iss, sub_h)` already holds an account is
  rejected with `409 principal_already_registered`. ON by default in
  `defineService` `required` mode. Pass `subHUniqueness` a durable,
  atomic store (`D1SubHUniquenessStore` in
  [`@afauthhq/worker`](../worker/)) for production, or `false` to allow
  agent fleets. The slot follows key rotations (§8.1/§8.2) and is
  released on account expiry — pass the store to `sweepExpiredAccounts`
  (`server.subHUniquenessStore` exposes the configured instance).
- **Stores** — `NonceStore` + `MemoryNonceStore` (lazy GC on every
  Nth insert), `AccountStore` + `MemoryAccountStore` (atomic
  invitation supersession with O(1) reverse index),
  `RevocationList` + `MemoryRevocationList`. Production-grade
  durable stores ship in [`@afauthhq/worker`](../worker/)
  (`D1AccountStore`, `D1SubHUniquenessStore`, `KvNonceStore`,
  `KvRevocationList`, `KvAttestedFreshnessStore`, `KvRateLimiter`).
- **Recipient handlers** — `RecipientHandler<R>` interface; ships
  `consoleEmailHandler` for local development (logs the magic link
  to `console.error`).

## Sign in with AFAuth (relying party)

`trust.afauth.org` is also an **OpenID Provider**, so the human behind an agent
can **Sign in with AFAuth** and land in the very account this Server provisioned
for them — the `(iss, sub_h)` account from per-principal uniqueness (§10.4.4)
above is exactly an OIDC `(issuer, subject)`. There is **no SDK helper for this
yet**: a relying party hand-wires the OIDC Authorization-Code + PKCE callback
(≈ a "Sign in with Google" route), verifies the `id_token` against the trust
JWKS, and resolves the account by `(iss, sub_h)`.

One rule the SDK does *not* enforce for you: the `id_token`'s `iss` is the URL
`https://trust.afauth.org`, while the attestation `iss` is the bare string
`afauth-trust`. Canonicalize both to one issuer before lookup, or the human
lands in a new account ([spec §10.8.4](https://github.com/AFAuthHQ/spec/blob/main/spec/core.md#1084-issuer-canonicalization-convergence-requirement)).
A reusable `OidcRpHandler` is planned for this package.

- Concept + guide: [Sign in with AFAuth](https://docs.afauth.org/concepts/human-oidc-signin), [Add Sign in with AFAuth](https://docs.afauth.org/guides/add-sign-in-with-afauth).
- Spec: [`core.md` §10.8](https://github.com/AFAuthHQ/spec/blob/main/spec/core.md#108-human-sign-in-via-the-trust-attestor-openid-provider) (AFAP-0008).

## See also

- [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec) — protocol spec.
- [`@afauthhq/worker`](../worker/) — Cloudflare Workers bindings that
  route requests to this Server's handlers.
- [`@afauthhq/agent` → `TrustClient`](../agent/) — the agent side of the
  default path: how an agent links to a human at `trust.afauth.org` and
  mints the `AFAuth-Attestation` JWT this Server's `attested_only`
  default requires.
