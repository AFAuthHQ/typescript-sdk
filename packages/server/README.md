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
  `Server`.
- **Stores** — `NonceStore` + `MemoryNonceStore` (lazy GC on every
  Nth insert), `AccountStore` + `MemoryAccountStore` (atomic
  invitation supersession with O(1) reverse index),
  `RevocationList` + `MemoryRevocationList`.
- **Recipient handlers** — `RecipientHandler<R>` interface; ships
  `consoleEmailHandler` for local development (logs the magic link
  to `console.error`).

## See also

- [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec) — protocol spec.
- [`@afauth/worker`](../worker/) — Cloudflare Workers bindings that
  route requests to this Server's handlers.
