/**
 * Recipe: agent attestation (§10).
 *
 * AFAuth accepts any well-formed Ed25519 keypair by default. Services
 * that want to know WHICH runtime an agent operates in — for abuse
 * prevention, enterprise compliance, or rate-limit tiering — may
 * require an `AFAuth-Attestation` header carrying a JWT signed by an
 * accepted attestor.
 *
 * Three attestor classes ship in `@afauthhq/server`:
 *
 *   - `HmacAttestor` — HS256 with a shared secret. Use for first-party
 *     service-operator attestors (§10.3, "Service-operator HMAC").
 *   - `JwksAttestor` — asymmetric attestors with a published JWKS URL.
 *     Use for platform/commerce attestors (`stripe-projects`,
 *     `microsoft-entra-agent-id`, etc.).
 *   - `MultiAttestor` — dispatches by JWT `iss` claim. Construct once
 *     per service with every accepted attestor pre-configured.
 *
 * When the service declares `billing.unclaimed_mode = "attested_only"`
 * (§9.2), the `Server` enforces presence + validity automatically on
 * implicit signup — missing/invalid attestations are rejected before
 * the account row is created.
 */

import {
  consoleEmailHandler,
  HmacAttestor,
  JwksAttestor,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  MultiAttestor,
  Server,
} from "@afauthhq/server";

// First-party HMAC attestor — share the secret with whatever process
// mints the tokens. MUST be ≥32 bytes in production.
const firstParty = new HmacAttestor({
  iss: "my-service",
  secret: process.env["ATTESTATION_SECRET"] ?? "REPLACE_ME_WITH_32+_BYTES",
});

// Commerce attestor — verifies tokens signed by an external authority.
// JWKS URL MUST be https. `jose` caches the JWKS internally.
const stripe = new JwksAttestor({
  iss: "stripe-projects",
  jwksUrl: "https://stripe.example/.well-known/jwks.json",
  // Constrain the accepted algorithms per attestor for tighter pinning.
  algorithms: ["ES256"],
});

// Dispatch by `iss` claim. Unknown issuers throw `invalid_attestation`.
const attestor = new MultiAttestor([firstParty, stripe]);

const server = new Server({
  nonceStore: new MemoryNonceStore(),
  revocationList: new MemoryRevocationList(),
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  baseUrl: "https://api.example.com",
  discovery: {
    afauth_version: "0.1",
    service_did: "did:web:api.example.com",
    endpoints: {
      accounts: "/afauth/v1/accounts",
      owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
      claim_page: "/claim",
      claim_completion: "/afauth/v1/claim",
      key_rotation: "/afauth/v1/accounts/me/keys/rotate",
    },
    signature_algorithms: ["ed25519"],
    recipient_types: ["email"],
    // §9: declare which attestors this service trusts. When
    // `unclaimed_mode = "attested_only"`, the server requires an
    // attestation from one of these issuers on the implicit-signup
    // path.
    billing: {
      unclaimed_mode: "attested_only",
      accepted_attestors: ["my-service", "stripe-projects"],
    },
  },
  attestor,
});

export { server };
