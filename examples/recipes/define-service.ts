/**
 * Recipe: spam-resistant service in one call.
 *
 * `defineService` is the opinionated convenience wrapper for new
 * AFAuth integrations. It flips three protocol switches ON by default:
 *
 *   1. `billing.unclaimed_mode: "attested_only"` in the discovery doc
 *      (§9.2), so un-attested signups are rejected at the wire.
 *   2. `attestor: trustAttestor()` (AFAP-0006 §10), so the bundled
 *      afauth-trust attestor verifies incoming attestations offline
 *      against its published JWKS.
 *   3. `subHUniqueness` (§10.4.4) — a per-principal uniqueness slot
 *      keyed on `(iss, sub_h)`, so one human holds at most one account.
 *
 * The combination means: a bad actor cannot mint 10,000 throwaway agent
 * keypairs and burn through 10,000 free tiers. Every signup must carry a
 * trust attestation tying the agent back to a verified human via a
 * per-service pseudonym `sub_h` (§10.4) — and because all of that human's
 * agents present the SAME `sub_h`, the second account is rejected with
 * `409 principal_already_registered`. Same human, same bucket — enforced,
 * not just advertised.
 *
 * The default slot is a process-local `MemorySubHUniquenessStore`. In
 * production, supply a durable, atomic store — `D1SubHUniquenessStore`
 * from `@afauthhq/worker` — and release slots on expiry by passing the
 * store to `sweepExpiredAccounts` (see `sweep()` below). Pass
 * `subHUniqueness: false` to allow many agents per human (fleet operators).
 *
 * Opt out (`attestation: "off"`) for read-only or paid-only services
 * where a human signal is overkill. Use `"optional"` while migrating
 * an existing fleet: attestations are verified when present but not
 * required, so existing un-linked agents keep working. (Uniqueness is
 * NOT defaulted in `optional` mode — a migrating fleet may legitimately
 * run many agents per human.)
 */

import {
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  consoleEmailHandler,
  defineService,
  sweepExpiredAccounts,
} from "@afauthhq/server";

// --- Spam-resistant by default (the recommended path) -----------------

// Hoisted so the periodic `sweep()` below can reference the same store.
const accounts = new MemoryAccountStore();

const server = defineService({
  baseUrl: "https://api.example.com",
  serviceDid: "did:web:api.example.com",
  accounts,
  recipients: { email: consoleEmailHandler },
  // attestation: "required" is the default — wires trustAttestor(), sets
  // discovery.billing.unclaimed_mode = "attested_only", AND enforces
  // §10.4.4 per-principal uniqueness (default: process-local
  // MemorySubHUniquenessStore).
  //
  // Production deployments should supply persistent, atomic stores:
  nonceStore: new MemoryNonceStore(),
  revocationList: new MemoryRevocationList(),
  // subHUniqueness: new D1SubHUniquenessStore(env.AFAUTH_DB), // durable + atomic
  // subHUniqueness: false,                                    // allow agent fleets
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

// --- Periodic expiry sweep (frees per-principal slots) ----------------
//
// Run from your scheduler (cron / Workers scheduled trigger / Lambda).
// Passing `server.subHUniquenessStore` releases each expired account's
// `(iss, sub_h)` slot, so a human whose unclaimed trial lapsed can sign up
// again. Omit it and the policy hardens to "one account per human, ever".
export async function sweep(): Promise<void> {
  await sweepExpiredAccounts(accounts, {
    unclaimedTtlSeconds: 24 * 60 * 60,
    subHUniqueness: server.subHUniquenessStore,
  });
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
