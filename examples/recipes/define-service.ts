/**
 * Recipe: spam-resistant service in one call.
 *
 * `defineService` is the opinionated convenience wrapper for new
 * AFAuth integrations. It flips two protocol switches ON by default:
 *
 *   1. `billing.unclaimed_mode: "attested_only"` in the discovery doc
 *      (§9.2), so un-attested signups are rejected at the wire.
 *   2. `attestor: trustAttestor()` (AFAP-0006 §10), so the bundled
 *      afauth-trust attestor verifies incoming attestations offline
 *      against its published JWKS.
 *
 * The combination means: a bad actor cannot mint 10,000 throwaway
 * agent keypairs and burn through 10,000 free tiers, because every
 * signup must carry a trust attestation that ties the agent back to
 * a verified human via a per-service pseudonym `sub_h` (§10.4).
 * Service code keys its anti-abuse state off `sub_h` — same human,
 * same bucket.
 *
 * Opt out (`attestation: "off"`) for read-only or paid-only services
 * where a human signal is overkill. Use `"optional"` while migrating
 * an existing fleet: attestations are verified when present but not
 * required, so existing un-linked agents keep working.
 */

import {
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  consoleEmailHandler,
  defineService,
} from "@afauthhq/server";

// --- Spam-resistant by default (the recommended path) -----------------

const server = defineService({
  baseUrl: "https://api.example.com",
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  // attestation: "required" is the default — wires trustAttestor() and
  // sets discovery.billing.unclaimed_mode = "attested_only".
  //
  // Production deployments should also supply persistent stores:
  nonceStore: new MemoryNonceStore(),
  revocationList: new MemoryRevocationList(),
});

// --- Per-route hook-up (framework-agnostic Fetch handlers) ------------

export async function fetch(req: Request): Promise<Response> {
  const url = new URL(req.url);
  switch (url.pathname) {
    case "/.well-known/afauth":
      return server.handleDiscovery(req);
    case "/accounts/me":
      return server.handleAccountIntrospection(req);
    default:
      return new Response("not found", { status: 404 });
  }
}

// --- Opt-out variants -------------------------------------------------

// Migration path: verify attestations when present, accept un-linked
// agents while you ramp up. Switch to "required" once your agent
// population is linked.
export const optional = defineService({
  baseUrl: "https://api.example.com",
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  nonceStore: new MemoryNonceStore(),
  attestation: "optional",
});

// Genuinely doesn't need a human signal (e.g. read-only public API,
// paid-only service where billing is the implicit anti-abuse signal).
export const noAttestation = defineService({
  baseUrl: "https://api.example.com",
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  nonceStore: new MemoryNonceStore(),
  attestation: "off",
});

// --- Advanced: custom attestor (override the trustAttestor() default)

// `new Server({...})` remains the lower-level path for MultiAttestor,
// custom HmacAttestor, fully custom discovery, etc. Use `defineService`
// with the `attestor` override when you want the secure defaults but
// also accept platform/commerce attestors:
//
//   import { HmacAttestor, MultiAttestor, trustAttestor } from "@afauthhq/server";
//   const server = defineService({
//     baseUrl, serviceDid, accounts, recipients,
//     attestor: new MultiAttestor([
//       trustAttestor(),
//       new HmacAttestor({ iss: "my-service", secret: process.env.ATTEST_SECRET! }),
//     ]),
//   });
