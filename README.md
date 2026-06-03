# AFAuth — TypeScript SDK

> Reference TypeScript SDK for the [AFAuth Protocol](https://github.com/AFAuthHQ/spec) — **Agent-First Auth**, the open protocol that makes AI agents first-class citizens of every service.

Human attention is finite. Agent attention is exploding. AFAuth is how that new attention reaches services. This SDK is the drop-in implementation: agents sign requests with their own keypair, services accept them as first-class principals, ownership hands off to a human only when (or if) that makes sense.

Five lines to integrate. Every AFAuth-compatible agent on day one. No portal to maintain.

## Packages

This is a pnpm workspace with four publishable packages plus a runnable
example Worker.

| Package | Purpose |
|---|---|
| [`@afauthhq/core`](packages/core) | Shared primitives: `did:key` codec, `DidResolver` + `DidKeyResolver`, RFC 9421 canonicalisation, SHA-256 content-digest, `Recipient` types, `AFAuthError` envelope, `deriveInvitationId`, `normaliseRecipient` |
| [`@afauthhq/agent`](packages/agent) | `Agent.generate()` / `fromPrivateKey()`, `signRequest`, protocol-aware builders (owner invitation, key rotation, account introspection), `fetchDiscovery` + `assertDiscoveryDocument`, **AFAP-0006 `TrustClient`** (link flow + per-service JWT minting against `afauth-trust`) |
| [`@afauthhq/server`](packages/server) | **`defineService` factory** (spam-resistant defaults), `Verifier` (§5.5/§5.6), `Server` (endpoint handlers + `revoke` / `handleKeyReKey` / `handleKeyRevocation`), `RateLimiter` + `MemoryRateLimiter` (§11.3), `Attestor` + `HmacAttestor`/`JwksAttestor`/`MultiAttestor` + `trustAttestor()` factory (§10), `assertFreshOwnerSession` (§7.5), `SweepableAccountStore` + `sweepExpiredAccounts()`, Memory stores, reference `consoleEmailHandler` |
| [`@afauthhq/worker`](packages/worker) | Cloudflare Workers bindings: `createWorker`, `KvNonceStore`, `DurableObjectNonceStore`/`createNonceDurableObject`, `KvRevocationList`, `KvRateLimiter`, `D1AccountStore` (+ `migrations/0001_init.sql`, implements `SweepableAccountStore`) |
| [`examples/worker`](examples/worker) | Reference Cloudflare Worker composing the above |

## Status

**Published on npm: `@afauthhq/{server,worker}@0.3.0` + `@afauthhq/agent@0.2.0` + `@afauthhq/core@0.1.0`.** Tracks v0.1 of the spec.

The SDK implements milestones M0–M5 of the v0.1 spec — the full
ceremony surface plus rotation, revocation, and full §11 error envelope
coverage — plus three hardening additions:

- **Rate-limit helper** (§11.3 `rate_limit_exceeded`) — per-route configs, `Retry-After` on the 429.
- **Attestation JWT verifier** (§10) — `HmacAttestor`, `JwksAttestor`, `MultiAttestor`; §9.2 `attested_only` enforcement.
- **`D1AccountStore`** — durable AccountStore on Cloudflare D1 with ADR-0004 atomic ops via `D1.batch()`.

`0.2.0` ships [AFAP-0006](https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md) and account-expiry support:

- **`TrustClient`** in `@afauthhq/agent` — drives the trust-attestor link flow (`linkStart` → `linkPoll` → per-service `token`) and caches per-audience JWTs in memory. `TrustHttpError` surfaces upstream codes (`binding_expired`, `binding_revoked`, `verification_required`) for actionable recovery prompts.
- **`trustAttestor()`** factory in `@afauthhq/server` — one-line `Server` config that pre-pins `iss: "afauth-trust"`, the AFAP JWKS URL, and EdDSA. Audience binding threaded through `Attestor.verify`.
- **Account expiry** — `Account.createdAt` is now required; `EXPIRED` state enforced with `HTTP 410 account_expired`. `SweepableAccountStore` + `sweepExpiredAccounts()` give services a hook for periodic cleanup. `D1AccountStore` implements the sweep interface (no migration — schema already had `created_at`).

`@afauthhq/server@0.3.0` adds **`defineService`** — an opinionated factory that wires `attestation: "required"` defaults (discovery `unclaimed_mode: "attested_only"` + bundled `trustAttestor()`). Spam-resistance becomes the SDK happy path: un-attested implicit signups are rejected at the wire, and downstream anti-abuse state can key off the per-service human pseudonym `sub_h` (§10.4). Override with `attestation: "optional"` (migration path) or `"off"` (read-only / paid-only). `@afauthhq/worker@0.3.0` republishes against the new server.

`@afauthhq/server@0.5.0` makes **"same human, same bucket" true by default** (§10.4.4). `attested_only` on its own only proves a signup carries *some* valid attestation; it does not stop one human from minting many agent keypairs and burning many free tiers. `defineService` now enforces **per-principal uniqueness**: an attested signup whose `(iss, sub_h)` already holds an account is rejected with `409 principal_already_registered`. A new `SubHUniquenessStore` (default in-memory `MemorySubHUniquenessStore`; `D1SubHUniquenessStore` in `@afauthhq/worker` for atomic, durable claims) backs the slot, which follows key rotations and is released on account expiry. Opt out with `subHUniqueness: false` (fleet operators: many agents, one human). `@afauthhq/worker@0.5.0` ships `D1SubHUniquenessStore` (migration `0002_subh_uniqueness.sql`).

Conformance is verified against the spec's test vectors (Appendix
C.1–C.6) — see [`vendor/spec-vectors/`](vendor/spec-vectors/), which
is a snapshot of the vectors from
[`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec).

| Test surface | Count |
|---|---|
| `@afauthhq/core` | 62 (codec roundtrips, canonical input vs §C.1, content-digest, §C.4 recipient normalisation, §C.5 envelopes) |
| `@afauthhq/agent` | 46 (discovery validation, §C.3 corpus, `TrustClient` link flow + token caching, `AttestedFetcher` §10.7 refresh-on-challenge) |
| `@afauthhq/server` | 175 (nonce store, conformance vectors via `Verifier.verify`, ceremony, claim completion, rotation, replay-window §C.6, body shapes, verifier edge cases, rate-limit gates, attestation incl. `trustAttestor()` + audience binding, §10.4.4 per-principal uniqueness, §10.7 attested-session gate + cross-component E2E, owner-session freshness, account expiry) |
| `@afauthhq/worker` | 59 (D1AccountStore: §7.3 atomic supersession, claim, rotate, revoke, sweep; `D1SubHUniquenessStore` atomic claim; `createWorker` routing; KV stores incl. `KvAttestedFreshnessStore`) |
| **Total** | **342 tests, all green in CI** |

## Quickstart — agent

> Because `defineService` (below) defaults to `attested_only`, the default agent journey links to a human once at `trust.afauth.org` and presents a short-lived attestation — per request, or kept live as a §10.7 attested session (`AttestedFetcher`). The two quickstarts interoperate out of the box.

```typescript
import { Agent, TrustClient, fetchDiscovery } from "@afauthhq/agent";

// Generate a fresh keypair (or restore one with Agent.fromPrivateKey).
const agent = await Agent.generate();
console.log(agent.did); // "did:key:z6Mk…"

// Fetch + validate the service's discovery document.
const disc = await fetchDiscovery("https://api.example.com");

// Build a signed owner-invitation request.
const signed = await agent.buildOwnerInvitation({
  baseUrl: "https://api.example.com",
  recipient: { type: "email", value: "alice@example.com" },
});

// Default services advertise unclaimed_mode "attested_only" (see the
// service quickstart below). Link to a human once, then attach a
// per-service attestation JWT — otherwise the signup is rejected with
// `attestation_required`.
const trust = new TrustClient({
  agentDid: agent.did,
  agentPublicKey: agent.publicKey,
  agentPrivateKey: agent.exportPrivateKey(),
});
const link = await trust.linkStart({ label: "my-agent" });
console.log(`Have a human confirm: ${link.link_url}`);
while (!(await trust.linkPoll(link.req_id))) {
  await new Promise((r) => setTimeout(r, 2_000));
}
const { jwt } = await trust.token(disc.service_did);

const res = await fetch(signed.url, {
  method: signed.method,
  headers: { ...signed.headers, "AFAuth-Attestation": jwt },
  body: signed.body,
});
```

## Quickstart — service (any runtime)

```typescript
import {
  consoleEmailHandler,
  defineService,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
} from "@afauthhq/server";

const server = defineService({
  baseUrl: "https://api.example.com",
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  nonceStore: new MemoryNonceStore(),         // replace for production
  revocationList: new MemoryRevocationList(),
  // attestation: "required" is the default — wires trustAttestor() and
  //   sets discovery.billing.unclaimed_mode = "attested_only".
  // Pass "optional" for a migration path, "off" to disable entirely.

  // §7.2: redirect_url is rejected unless its host is in this list.
  redirectAllowList: ["yourapp.com"],
});

// In your HTTP layer, dispatch to the handlers. The synthesized
// discovery doc derives these paths from baseUrl; pass a `discovery`
// override on defineService to customize them.
//   GET  /.well-known/afauth                            → server.handleDiscovery(req)
//   POST /owner-invitations                             → server.handleOwnerInvitation(req)
//   POST /claim/complete                                → server.handleClaimCompletion(req, session)
//   POST /accounts/me/keys/rotate                       → server.handleKeyRotation(req)
//   GET  /accounts/me                                   → server.handleAccountIntrospection(req)
```

For Cloudflare Workers, use `createWorker` from `@afauthhq/worker` to
route all five endpoints automatically — see
[`examples/worker`](examples/worker).

## Develop

```bash
pnpm install
pnpm typecheck          # turbo: tsc --noEmit across all packages
pnpm build              # turbo: tsup ESM + .d.ts emit
pnpm test               # turbo: vitest across all packages
pnpm coverage           # turbo: vitest --coverage
```

CI runs all four on every push. See
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Architecture

API and architecture decisions are recorded as ADRs in the spec repo
under [`implementation/adr/`](https://github.com/AFAuthHQ/spec/tree/main/implementation/adr).
The headline decisions for v0.1 are:

- **Nonce store: KV with TTL** (ADR-0001) — `NonceStore` interface is
  pluggable; the SDK ships `MemoryNonceStore` and `KvNonceStore`.
- **No router framework** (ADR-0002) — `createWorker` uses a small
  in-house router; no Hono, no itty-router in the runtime dep tree.
- **DID resolver in v0.1** (ADR-0003) — agent account identifiers are
  `did:key`, so the SDK ships `DidKeyResolver` and the `Verifier`
  resolves the signing key straight from the DID with no I/O. The
  `didResolver` option remains for services that choose to accept
  additional agent DID methods.
- **SDK API shape** (ADR-0004) — `AccountStore` exposes named atomic
  operations (not generic CRUD); `Server.handleClaimCompletion` takes
  an explicit `session` parameter; `Agent.signRequest` is public with
  spec-conformant defaults; `RevocationList` is mandatory (defaults to
  `MemoryRevocationList` with a warning if not supplied).

## License

[MIT](LICENSE). The vendored spec vectors under
[`vendor/spec-vectors/`](vendor/spec-vectors/) carry their upstream
Apache-2.0 license per the spec repo's `LICENSE-CODE`.
