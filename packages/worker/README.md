# `@afauthhq/worker`

Cloudflare Workers bindings for the AFAuth Protocol. Wraps
`@afauthhq/server` in a Worker-native router and provides storage
implementations backed by Durable Objects, KV, and D1.

## Quickstart

```typescript
import {
  AFAuthNonceDO,
  createNonceDurableObject,
  createWorker,
  DurableObjectNonceStore,
  KvRevocationList,
} from "@afauthhq/worker";
import {
  consoleEmailHandler,
  MemoryAccountStore,
  type DiscoveryDocument,
} from "@afauthhq/server";

// Re-export the nonce DO base class under whatever class_name your
// wrangler.toml binding declares (default: `AFAuthNonceDO`).
export class AFAuthNonceDO extends createNonceDurableObject() {}

interface Env {
  AFAUTH_NONCE_DO: DurableObjectNamespace;
  AFAUTH_REVOCATIONS: KVNamespace;
}

const discovery: DiscoveryDocument = { /* ... */ };
const accounts = new MemoryAccountStore(); // replace with durable impl

export default {
  fetch(req, env: Env, ctx) {
    const handler = createWorker({
      nonceStore: new DurableObjectNonceStore(env.AFAUTH_NONCE_DO),
      revocationList: new KvRevocationList(env.AFAUTH_REVOCATIONS),
      serviceDid: discovery.service_did,
      accounts,
      recipients: { email: consoleEmailHandler },
      discovery,
      baseUrl: "https://api.example.com",
      extractOwnerSession: async (req) => /* your session extraction */ null,
    });
    return handler.fetch!(req, env, ctx);
  },
};
```

`wrangler.toml` binding for the DO:

```toml
[[durable_objects.bindings]]
name       = "AFAUTH_NONCE_DO"
class_name = "AFAuthNonceDO"

[[migrations]]
tag         = "v1"
new_classes = ["AFAuthNonceDO"]
```

## Spam-resistant defaults

`createWorker` mirrors `new Server({...})` rather than the higher-level
[`defineService`](../server/README.md#quickstart) factory — the Worker
needs explicit options for its DO bindings, KV namespaces, and
`extractOwnerSession`. To get the same spam-resistance, pass
`trustAttestor()` and declare `attested_only` on the discovery doc:

```typescript
import { trustAttestor } from "@afauthhq/server";

const discovery: DiscoveryDocument = {
  /* ... */
  billing: {
    unclaimed_mode: "attested_only",
    accepted_attestors: ["afauth-trust"],
  },
};

createWorker({
  /* ... */
  attestor: trustAttestor(),
  discovery,
  // §10.4.4 "same human, same bucket". Because `createWorker` mirrors
  // `new Server` (not `defineService`), per-principal uniqueness is NOT
  // defaulted — pass it explicitly. `D1SubHUniquenessStore` gives an
  // atomic, durable claim via its UNIQUE index:
  subHUniqueness: new D1SubHUniquenessStore(env.AFAUTH_DB),
});
```

Agents that haven't run `afauth trust link` will be rejected with
`401 attestation_required`; the [`afauth signup`](https://github.com/AFAuthHQ/cli#usage)
CLI guides them through the link flow on that error. A second agent for a
human who already has an account here is rejected with
`409 principal_already_registered`. To free a human's slot when their
unclaimed account expires, pass the same store to `sweepExpiredAccounts`
(`subHUniqueness`).

## Nonce store: pick DO, not KV

§5.6 requires the seen-nonce set be **shared and atomic** across
verifier instances. Cloudflare KV is shared but offers no atomic
check-and-set: a `get`-then-`put` window admits cross-isolate
replay during the freshness window.

| Store | Atomic? | Shared? | When to use |
|---|---|---|---|
| `DurableObjectNonceStore` | **yes** | yes | **recommended for production** |
| `KvNonceStore` | no | yes | dev only, or single-region low-value deployments where the trade-off is documented |
| `MemoryNonceStore` (from `@afauthhq/server`) | yes | no | tests only |

`DurableObjectNonceStore` partitions by `keyid` so unrelated agents
fan out across distinct actor instances; only requests from the same
agent share an actor and serialize against each other.

## Exports

- **`createWorker(opts)`** — returns an `ExportedHandler` routing the
  five AFAuth endpoints to `@afauthhq/server` handlers. Routing is
  done with a small in-house router (ADR-0002).
- **`createNonceDurableObject()`** — factory that returns a
  Durable-Object base class implementing the §5.6 atomic
  check-and-set protocol. Subclass it in your Worker module and
  register the subclass in `wrangler.toml`.
- **`DurableObjectNonceStore`** — `NonceStore` that delegates to the
  DO above. Spec-compliant atomic insert; recommended for production.
- **`KvNonceStore`** — `NonceStore` backed by Cloudflare KV. Has a
  known eventual-consistency replay window; see the JSDoc on the
  class. Suitable for dev/low-value deployments only.
- **`KvRevocationList`** — `RevocationList` backed by Cloudflare KV
  (§8.3). Durable; no TTL.
- **`KvAttestedFreshnessStore`** — `AttestedFreshnessStore` backed by
  Cloudflare KV (§10.7). Stores each account's `attestedUntil`; the KV
  entry's TTL is set to the remaining window, so lapsed sessions
  self-evict. Pass to `Server` via `attestedSession: { store }`.
- **`KvRateLimiter`** — `RateLimiter` backed by Cloudflare KV
  (§11.3). Fixed-window counter per key; eventually-consistent
  reads mean racing isolates may over-count (fail-safe per §11.3),
  never under-count.
- **`D1AccountStore`** — `AccountStore` backed by Cloudflare D1
  (§6 + §7.3). Every ADR-0004 named atomic op uses `D1.batch()`
  for transactional grouping. The schema lives at
  [`migrations/0001_init.sql`](migrations/0001_init.sql); apply
  via `wrangler d1 migrations apply <db-name>` before first use.
  Schema is portable to standard Postgres/MySQL with minor
  syntactic changes.
- **`D1SubHUniquenessStore`** — `SubHUniquenessStore` backed by
  Cloudflare D1 (§10.4.4), in the same database as `D1AccountStore`.
  Enforces "at most one account per human": `claim()` is atomic via the
  composite PRIMARY KEY `(iss, sub_h)` (`INSERT … ON CONFLICT DO
  NOTHING`), which a `KvNonceStore`-style get-then-put could not give —
  so there is no KV variant. Schema lives at
  [`migrations/0002_subh_uniqueness.sql`](migrations/0002_subh_uniqueness.sql);
  apply after `0001`. Pass via `subHUniqueness` (and to
  `sweepExpiredAccounts` to release slots on expiry).
- **`WorkerOptions`** — extends `ServerOptions` with the required
  `extractOwnerSession` callback for the claim-completion route.

## See also

- [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec) — protocol spec.
- [`@afauthhq/server`](../server/) — the handlers `createWorker`
  dispatches to.
- [`examples/worker/`](../../examples/worker/) — runnable reference
  Worker that prefers DO when its binding is configured and falls
  back to KV (with a warning) otherwise.
