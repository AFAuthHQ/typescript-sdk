# `@afauth/agent`

Agent SDK for the AFAuth Protocol. Generates and uses an Ed25519
keypair to sign requests per RFC 9421, and builds protocol-aware
requests for the v0.1 endpoints.

## Quickstart

```typescript
import { Agent, fetchDiscovery } from "@afauth/agent";

const agent = await Agent.generate();
console.log(agent.did); // "did:key:z6Mk..."

const disc = await fetchDiscovery("https://api.example.com");

// Build a complete signed request for owner invitation:
const signed = await agent.buildOwnerInvitation({
  baseUrl: "https://api.example.com",
  recipient: { type: "email", value: "alice@example.com" },
});

// Send it:
const res = await fetch(signed.url, {
  method: signed.method,
  headers: signed.headers,
  body: signed.body,
});
```

## Exports

- **`Agent`** — `Agent.generate()`, `Agent.fromPrivateKey(seed)`,
  `agent.did`, `agent.publicKey`, `agent.exportPrivateKey()`,
  `agent.signRequest(req, opts?)` (lower-level), and protocol
  builders: `buildOwnerInvitation`, `buildKeyRotation`,
  `buildAccountIntrospection`.
- **`fetchDiscovery(baseUrl)`** — unsigned GET of
  `/.well-known/afauth` with full §4.3 / §4.5 validation.
- **`assertDiscoveryDocument(value)`** — validates a parsed
  discovery doc without fetching.

## See also

- [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec) — protocol spec.
- [`@afauth/core`](../core/) — shared types and primitives this
  package consumes.
