# AFAuth — TypeScript SDK

> Reference TypeScript SDK for the [AFAuth Protocol](https://github.com/AFAuthHQ/spec) — **Agent-First Auth**, the open protocol that makes AI agents first-class citizens of every service.

Human attention is finite. Agent attention is exploding. AFAuth is how that new attention reaches services — agents sign requests with their own keypair, services accept them as first-class principals, and ownership hands off to a human only when (or if) that makes sense. This SDK is the drop-in implementation.

A service goes live in a few lines. Every AFAuth-compatible agent works on day one. No portal to maintain.

## Install

```bash
# Building an agent:
npm i @afauthhq/agent

# Building a service:
npm i @afauthhq/server
npm i @afauthhq/worker   # …if you deploy on Cloudflare Workers
```

ESM-only, Node ≥ 20 (or any Web-standard runtime: Workers, Deno, Bun). `@afauthhq/core` is a shared dependency, pulled in automatically.

## Quickstart — agent

> Default services advertise `unclaimed_mode: "attested_only"` (see the service quickstart). An agent links to a human once at `trust.afauth.org` and presents a short-lived attestation — per request, or kept live as an attested session (`AttestedFetcher`). The two quickstarts interoperate out of the box.

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

// Link to a human once, then attach a per-service attestation JWT —
// otherwise the signup is rejected with `attestation_required`.
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
  redirectAllowList: ["yourapp.com"],         // hosts allowed in redirect_url
  // attestation defaults to "required": un-attested signups are rejected at
  // the wire and "same human, same bucket" holds. Pass "optional" for a
  // migration path, or "off" for read-only / paid-only services.
});
```

Then dispatch from your HTTP layer to the five handlers:

```
GET  /.well-known/afauth          → server.handleDiscovery(req)
POST /owner-invitations           → server.handleOwnerInvitation(req)
POST /claim/complete              → server.handleClaimCompletion(req, session)
POST /accounts/me/keys/rotate     → server.handleKeyRotation(req)
GET  /accounts/me                 → server.handleAccountIntrospection(req)
```

On Cloudflare Workers, `createWorker` from `@afauthhq/worker` wires all five routes for you — see [`examples/worker`](examples/worker). For focused snippets of the other surfaces (standalone `Verifier`, rotation, revocation, rate limits, attestors), see [`examples/recipes`](examples/recipes).

## Packages

A pnpm workspace with four publishable packages plus a runnable example Worker.

| Package | Install when you're… | What's inside |
|---|---|---|
| [`@afauthhq/agent`](packages/agent) | building an agent | keypair + RFC 9421 request signing, protocol builders (owner invitation, key rotation, introspection), discovery fetch/validate, `TrustClient` + `AttestedFetcher` |
| [`@afauthhq/server`](packages/server) | building a service | `defineService` (spam-resistant defaults), `Verifier`, `Server` endpoint handlers, rate limiter, attestors, per-principal uniqueness, in-memory stores |
| [`@afauthhq/worker`](packages/worker) | deploying on Cloudflare | `createWorker` router + durable bindings: D1 account/uniqueness stores, KV nonce/revocation/rate-limit/attested-session stores |
| [`@afauthhq/core`](packages/core) | (transitive) | shared primitives: `did:key` codec, DID resolver, RFC 9421 canonicalisation, content-digest, error envelope |
| [`examples/worker`](examples/worker) | — | reference Cloudflare Worker composing the above |

Each package README documents its full export surface and maps every feature to the relevant spec section.

## Conformance

Verified against the spec's test vectors (Appendix C.1–C.6) in [`vendor/spec-vectors/`](vendor/spec-vectors/) — a snapshot of the vectors from [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec). The SDK implements the full v0.1 ceremony surface (milestones M0–M5) plus key rotation, revocation, the §11 error envelope, rate limiting, attestation (§10), and per-principal uniqueness (§10.4.4).

| Package | Tests |
|---|---|
| `@afauthhq/core` | 62 |
| `@afauthhq/agent` | 46 |
| `@afauthhq/server` | 187 |
| `@afauthhq/worker` | 54 |
| **Total** | **349, all green in CI** |

## Architecture

API and architecture decisions are recorded as ADRs in the spec repo under [`implementation/adr/`](https://github.com/AFAuthHQ/spec/tree/main/implementation/adr). The headline v0.1 decisions:

- **Nonce store: KV with TTL** (ADR-0001) — `NonceStore` is pluggable; ships `MemoryNonceStore` and `KvNonceStore`.
- **No router framework** (ADR-0002) — `createWorker` uses a small in-house router; no Hono or itty-router in the runtime dep tree.
- **DID resolver** (ADR-0003) — agent identifiers are `did:key`, so the `Verifier` resolves the signing key straight from the DID with no I/O. `didResolver` stays pluggable for additional methods.
- **SDK API shape** (ADR-0004) — `AccountStore` exposes named atomic operations (not generic CRUD); `handleClaimCompletion` takes an explicit `session`; `RevocationList` is mandatory.

## Versioning

Current: `@afauthhq/server` / `@afauthhq/worker` **0.5.0**, `@afauthhq/agent` **0.4.0**, `@afauthhq/core` **0.2.0** — all published on npm and tracking **v0.1** of the spec. Per-package release notes live in each package's `CHANGELOG.md` (e.g. [`packages/server/CHANGELOG.md`](packages/server/CHANGELOG.md)).

## Develop

```bash
pnpm install
pnpm typecheck          # turbo: tsc --noEmit across all packages
pnpm build              # turbo: tsup ESM + .d.ts emit
pnpm test               # turbo: vitest across all packages
pnpm coverage           # turbo: vitest --coverage
```

CI runs all four on every push — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## License

[MIT](LICENSE). The vendored spec vectors under [`vendor/spec-vectors/`](vendor/spec-vectors/) carry their upstream Apache-2.0 license per the spec repo's `LICENSE-CODE`.
