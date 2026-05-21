# `@afauth/worker`

Cloudflare Workers bindings for the AFAuth Protocol. Wraps
`@afauth/server` in a Worker-native router and provides KV-backed
storage implementations.

## Quickstart

```typescript
import { createWorker, KvNonceStore, KvRevocationList } from "@afauth/worker";
import {
  consoleEmailHandler,
  MemoryAccountStore,
  type DiscoveryDocument,
} from "@afauth/server";

interface Env {
  AFAUTH_NONCES: KVNamespace;
  AFAUTH_REVOCATIONS: KVNamespace;
}

const discovery: DiscoveryDocument = { /* ... */ };
const accounts = new MemoryAccountStore(); // replace with durable impl

export default {
  fetch(req, env: Env, ctx) {
    const handler = createWorker({
      nonceStore: new KvNonceStore(env.AFAUTH_NONCES),
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

## Exports

- **`createWorker(opts)`** — returns an `ExportedHandler` routing
  the five AFAuth endpoints to `@afauth/server` handlers. Routing is
  done with a small in-house router (ADR-0002).
- **`KvNonceStore`** — `NonceStore` backed by Cloudflare KV (§5.6).
  Uses KV `expirationTtl`; floored to KV's 60s minimum.
- **`KvRevocationList`** — `RevocationList` backed by Cloudflare KV
  (§8.3). Durable; no TTL.
- **`WorkerOptions`** — extends `ServerOptions` with the required
  `extractOwnerSession` callback for the claim-completion route.

## See also

- [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec) — protocol spec.
- [`@afauth/server`](../server/) — the handlers `createWorker`
  dispatches to.
- [`examples/worker/`](../../examples/worker/) — runnable reference
  Worker.
