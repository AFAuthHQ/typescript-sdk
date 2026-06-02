# `@afauthhq/agent`

Agent SDK for the AFAuth Protocol. Generates and uses an Ed25519
keypair to sign requests per RFC 9421, and builds protocol-aware
requests for the v0.1 endpoints.

## Quickstart

```typescript
import { Agent, TrustClient, fetchDiscovery } from "@afauthhq/agent";

const agent = await Agent.generate();
console.log(agent.did); // "did:key:z6Mk..."

const disc = await fetchDiscovery("https://api.example.com");

// Build a complete signed request for owner invitation:
const signed = await agent.buildOwnerInvitation({
  baseUrl: "https://api.example.com",
  recipient: { type: "email", value: "alice@example.com" },
});

// Link this agent to a human once — default services require it.
const trust = new TrustClient({
  agentDid: agent.did,
  agentPublicKey: agent.publicKey,
  agentPrivateKey: agent.exportPrivateKey(),
});
const link = await trust.linkStart({ label: "my-agent" });
console.log(`Open to confirm: ${link.link_url}`);
while (!(await trust.linkPoll(link.req_id))) {
  await new Promise((r) => setTimeout(r, 2_000));
}
const { jwt } = await trust.token(disc.service_did);

// Send it, presenting the attestation:
const res = await fetch(signed.url, {
  method: signed.method,
  headers: { ...signed.headers, "AFAuth-Attestation": jwt },
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
- **`TrustClient`** (AFAP-0006) — trust-attestor client. `linkStart()` →
  show `link_url` to a human → `linkPoll(reqId)` returns a `TrustBinding`
  (persist it). `token(serviceDid)` mints a short-lived §10 attestation
  JWT (cached per audience) to send as the `AFAuth-Attestation` header.
  Defaults to `trust.afauth.org` (`AFAUTH_TRUST_DEFAULT_BASE`).
- **`TrustHttpError`** — surfaces upstream codes (`binding_expired`,
  `binding_revoked`, `verification_required`) for actionable recovery.
- **`AttestedFetcher`** (§10.7) — wraps an `Agent` + `TrustClient` and
  runs the refresh-on-challenge loop: signs each request and, on
  `401 attestation_required`, mints a fresh attestation and retries
  once. A revoked/expired binding surfaces as a terminal
  `TrustHttpError` rather than an unbounded retry. Reactive by default;
  `proactive: true` attaches an attestation on the first attempt.

> Services built with `defineService` default to `attested_only`, so an
> agent that only signs a request is rejected with `attestation_required`.
> Link to a human and attach a `TrustClient.token()` JWT to reach them.

## See also

- [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec) — protocol spec.
- [`@afauthhq/core`](../core/) — shared types and primitives this
  package consumes.
