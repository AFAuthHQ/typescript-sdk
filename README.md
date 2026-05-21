# AFAuth — TypeScript SDK

> Reference TypeScript SDK for the [AFAuth Protocol](https://github.com/AFAuthHQ/spec).
> AFAuth lets AI agents sign up to services with a self-generated
> Ed25519 keypair and hand ownership to a human later, signing every
> request per RFC 9421 (HTTP Message Signatures).

## Packages

This is a pnpm workspace with four publishable packages plus a runnable
example Worker.

| Package | Purpose |
|---|---|
| [`@afauthhq/core`](packages/core) | Shared primitives: `did:key` codec, `DidResolver` + `DidKeyResolver` + `CompositeDidResolver`, RFC 9421 canonicalisation, SHA-256 content-digest, `Recipient` types, `AFAuthError` envelope, `deriveInvitationId`, `normaliseRecipient` |
| [`@afauthhq/agent`](packages/agent) | `Agent.generate()` / `fromPrivateKey()`, `signRequest`, protocol-aware builders (owner invitation, key rotation, account introspection), `fetchDiscovery` + `assertDiscoveryDocument` |
| [`@afauthhq/server`](packages/server) | `Verifier` (§5.5/§5.6), `Server` (five endpoint handlers + `revoke`), `DidWebResolver` (§3.1.2), `RateLimiter` + `MemoryRateLimiter` (§11.3), `Attestor` + `HmacAttestor`/`JwksAttestor`/`MultiAttestor` (§10), `assertFreshOwnerSession` (§7.5), Memory stores, reference `consoleEmailHandler` |
| [`@afauthhq/worker`](packages/worker) | Cloudflare Workers bindings: `createWorker`, `KvNonceStore`, `KvRevocationList`, `KvRateLimiter`, `D1AccountStore` (+ `migrations/0001_init.sql`) |
| [`examples/worker`](examples/worker) | Reference Cloudflare Worker composing the above |

## Status

**v0.1 conformance complete; beta hardening pass complete; awaiting first npm publish.**

The SDK implements milestones M0–M5 of the v0.1 spec — the full
ceremony surface plus rotation, revocation, and full §11 error envelope
coverage — and the four beta-hardening additions on top of that:

- **`did:web` resolver** (§3.1.2) with TLS-only fetch, schema validation, positive + negative caching.
- **Rate-limit helper** (§11.3 `rate_limit_exceeded`) — per-route configs, `Retry-After` on the 429.
- **Attestation JWT verifier** (§10) — `HmacAttestor`, `JwksAttestor`, `MultiAttestor`; §9.2 `attested_only` enforcement.
- **`D1AccountStore`** — durable AccountStore on Cloudflare D1 with ADR-0004 atomic ops via `D1.batch()`.

Conformance is verified against the spec's test vectors (Appendix
C.1–C.6) — see [`vendor/spec-vectors/`](vendor/spec-vectors/), which
is a snapshot of the vectors from
[`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec).

| Test surface | Count |
|---|---|
| `@afauthhq/core` | 62 (codec roundtrips, canonical input vs §C.1, content-digest, §C.4 recipient normalisation, §C.5 envelopes) |
| `@afauthhq/agent` | 29 (discovery validation, §C.3 corpus) |
| `@afauthhq/server` | 110 (nonce store, conformance vectors via `Verifier.verify`, ceremony, claim completion, rotation, replay-window §C.6, body shapes, verifier edge cases, did:web resolver, rate-limit gates, attestation, owner-session freshness) |
| `@afauthhq/worker` | 12 (D1AccountStore: §7.3 atomic supersession, claim, rotate, revoke via in-process miniflare D1) |
| **Total** | **213 tests, all green in CI** |

The first publish is staged as `0.1.0-alpha.0` (see
[`.changeset/initial-alpha.md`](.changeset/initial-alpha.md)).

## Quickstart — agent

```typescript
import { Agent, fetchDiscovery } from "@afauthhq/agent";

// Generate a fresh keypair (or restore one with Agent.fromPrivateKey).
const agent = await Agent.generate();
console.log(agent.did); // "did:key:z6Mk…"

// Fetch + validate the service's discovery document.
const disc = await fetchDiscovery("https://api.example.com");

// Build and send a signed owner-invitation request.
const signed = await agent.buildOwnerInvitation({
  baseUrl: "https://api.example.com",
  recipient: { type: "email", value: "alice@example.com" },
});

const res = await fetch(signed.url, {
  method: signed.method,
  headers: signed.headers,
  body: signed.body,
});
```

## Quickstart — service (any runtime)

```typescript
import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  Server,
} from "@afauthhq/server";

const server = new Server({
  nonceStore: new MemoryNonceStore(),       // replace for production
  revocationList: new MemoryRevocationList(),
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  discovery: {
    afauth_version: "0.1",
    service_did: "did:web:api.example.com",
    endpoints: {
      accounts: "/afauth/v1/accounts",
      owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
      claim_page: "/claim",
      claim_completion: "/afauth/v1/claim",
    },
    signature_algorithms: ["ed25519"],
    recipient_types: ["email"],
  },
  baseUrl: "https://api.example.com",

  // §7.2: redirect_url is rejected unless its host is in this list.
  redirectAllowList: ["yourapp.com"],
});

// In your HTTP layer, dispatch to the handlers:
//   GET  /.well-known/afauth                            → server.handleDiscovery(req)
//   POST /afauth/v1/accounts/me/owner-invitation        → server.handleOwnerInvitation(req)
//   POST /afauth/v1/claim/<token>                       → server.handleClaimCompletion(req, session)
//   POST /afauth/v1/accounts/me/keys/rotate             → server.handleKeyRotation(req)
//   GET  /afauth/v1/accounts/me                         → server.handleAccountIntrospection(req)
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
- **DID resolver in v0.1** (ADR-0003, amended) — the SDK ships both
  `DidKeyResolver` (in `@afauthhq/core`) and `DidWebResolver` (in
  `@afauthhq/server`). `Verifier`'s default is `did:key`-only for
  backward compat; pass
  `didResolver: new CompositeDidResolver({ key: new DidKeyResolver(), web: new DidWebResolver({}) })`
  to also accept `did:web` keyids.
- **SDK API shape** (ADR-0004) — `AccountStore` exposes named atomic
  operations (not generic CRUD); `Server.handleClaimCompletion` takes
  an explicit `session` parameter; `Agent.signRequest` is public with
  spec-conformant defaults; `RevocationList` is mandatory (defaults to
  `MemoryRevocationList` with a warning if not supplied).

## License

[MIT](LICENSE). The vendored spec vectors under
[`vendor/spec-vectors/`](vendor/spec-vectors/) carry their upstream
Apache-2.0 license per the spec repo's `LICENSE-CODE`.
