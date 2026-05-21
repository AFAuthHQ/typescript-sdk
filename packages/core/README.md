# `@afauth/core`

Shared primitives for the AFAuth Protocol — used by `@afauth/agent`,
`@afauth/server`, and `@afauth/worker`.

## Exports

- **Identity** — `Did`, `Ed25519PublicKey`, `Ed25519PrivateKey`
- **`did:key` codec** (§3.1.1) — `encodeDidKey(pub)`, `decodeDidKey(did)`
- **Recipient registry** (§7.7) — `Recipient` (email / phone / oidc / did)
- **Signature parameters** (§5.2) — `SignatureParams`, `CoveredComponent`
- **Canonicalisation** (§5.2) — `buildCanonicalInput(req, params, covered)`
- **Content-digest** (RFC 9530) — `sha256ContentDigest(body)`
- **Discovery** (§4) — `DiscoveryDocument`
- **Error envelope** (§11) — `AFAuthError`, `AFAuthErrorCode`
- **Helpers** — `deriveInvitationId(token)` for non-secret invitation IDs

This package has no runtime dependencies on other `@afauth/*` packages;
it depends on `@noble/curves` and `@noble/hashes` for crypto primitives.

## See also

- [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec) — the protocol
  specification this package implements.
- [`AFAuthHQ/typescript-sdk`](https://github.com/AFAuthHQ/typescript-sdk)
  — the workspace this package lives in, including the agent, server,
  and worker packages.
