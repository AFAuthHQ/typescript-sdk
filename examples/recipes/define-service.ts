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
 * The combination means a bad actor cannot mint 10,000 throwaway agent
 * keypairs and look like 10,000 customers. Every signup carries a trust
 * attestation tying the agent to a verified human via a per-service
 * pseudonym `sub_h` (§10.4) — and because all of that human's agents
 * present the SAME `sub_h`, they group onto ONE account (§10.4.4): "one
 * account, many devices", like signing into one account from a PC and a
 * phone. Bucket your free-tier quota / rate-limits / bans by the account
 * (or by `sub_h`) and all of a human's devices share one bucket — no
 * legitimate multi-device user is locked out.
 *
 * Grouping needs no option — it is intrinsic to every `AccountStore`. In
 * production, swap the `Memory*` stores for durable ones (`D1AccountStore`
 * from `@afauthhq/worker`, etc.).
 *
 * Opt out of attestation (`attestation: "off"`) for read-only or paid-only
 * services where a human signal is overkill. Use `"optional"` while
 * migrating an existing fleet: attestations are verified when present but
 * not required, so existing un-linked agents keep working.
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
  // attestation: "required" is the default — wires trustAttestor() and sets
  // discovery.billing.unclaimed_mode = "attested_only". A human's agents are
  // grouped onto one account by their `(iss, sub_h)` automatically.
  //
  // Production deployments should supply persistent stores (e.g.
  // D1AccountStore / KV stores from @afauthhq/worker):
  nonceStore: new MemoryNonceStore(),
  revocationList: new MemoryRevocationList(),
});

// --- Per-route hook-up (framework-agnostic Fetch handlers) ------------

export async function fetch(req: Request): Promise<Response> {
  const url = new URL(req.url);
  switch (url.pathname) {
    case "/.well-known/afauth":
      return server.handleDiscovery(req);
    // These paths match the synthesized discovery doc (`endpoints.accounts`
    // + "/me", and `endpoints.owner_invitation`) — i.e. the canonical §4.1
    // paths the agent SDK builders sign. A router that diverges from the
    // discovery it advertises 404s a default agent. (`@afauthhq/worker`
    // derives these routes from the discovery doc automatically.)
    case "/afauth/v1/accounts/me":
      return server.handleAccountIntrospection(req);
    case "/afauth/v1/accounts/me/owner-invitation":
      return server.handleOwnerInvitation(req);
    default:
      return new Response("not found", { status: 404 });
  }
}

// --- Periodic expiry sweep (§6.1, OPTIONAL) ---------------------------
//
// By default AFAuth accounts NEVER expire: an agent operates its account
// indefinitely whether or not a human ever claims it, so most services do
// not need this sweep at all. Reach for it only to garbage-collect
// abandoned accounts or to honour a data-retention mandate — then
// advertise an `unclaimed_ttl_seconds` limit (§4.4) and pass it here.
// With no TTL configured, `sweepExpiredAccounts` is a no-op.
export async function sweep(): Promise<void> {
  await sweepExpiredAccounts(accounts, {
    // unclaimedTtlSeconds: 30 * 24 * 60 * 60, // 30 days — opt in only if you must
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
