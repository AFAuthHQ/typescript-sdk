/**
 * Recipe: owner-driven revocation + re-key (§8.4 / §8.2).
 *
 * Two layers, pick the one that fits your service:
 *
 *  1. TURNKEY wire handlers — `Server.handleKeyRevocation(req, session)`
 *     and `Server.handleKeyReKey(req, session)`. You extract the owner
 *     session from your own auth layer and hand the request straight to
 *     the SDK; it parses the body, enforces the §7.5 freshness floor,
 *     checks that the session owns the account, and (for re-key) installs
 *     the new key while clearing the revoked flag atomically. This is the
 *     path the worker routes `key_revocation` / `key_rekey` to.
 *
 *  2. BARE primitive — `Server.revoke(did)`. Un-gated; mutates the
 *     account row + revocation list directly. Use it for abuse-handling
 *     staff tooling, NOT for owner-facing routes (it skips the §7.5
 *     gate, so YOU must gate it — see `revokeByDidDirect` below).
 *
 * None of these is an AFAuth-signed endpoint: the agent's key may be
 * stolen, so the two-step-verify invariant (§7.1) means the agent MUST
 * NOT be able to revoke or re-key its own account. They are
 * owner-authenticated.
 */

import {
  assertFreshOwnerSession,
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  Server,
  type OwnerSession,
} from "@afauthhq/server";
import type { Did } from "@afauthhq/core";

const server = new Server({
  nonceStore: new MemoryNonceStore(),
  revocationList: new MemoryRevocationList(),
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  baseUrl: "https://api.example.com",
  // Top of the §7.5 60–300s band; lower it for higher-assurance services.
  ownerSessionMaxAgeSeconds: 300,
  discovery: {
    afauth_version: "0.1",
    service_did: "did:web:api.example.com",
    endpoints: {
      accounts: "/afauth/v1/accounts",
      owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
      claim_page: "/claim",
      claim_completion: "/afauth/v1/claim",
      key_rotation: "/afauth/v1/accounts/me/keys/rotate",
      key_rekey: "/afauth/v1/accounts/me/keys/rekey",
      key_revocation: "/afauth/v1/accounts/me/keys/revoke",
    },
    signature_algorithms: ["ed25519"],
    recipient_types: ["email"],
  },
});

/**
 * Turnkey owner revoke. Your route extracts the owner session, then
 * hands the request to the SDK. The body carries `{ account_did }`.
 * Response: 200 `{ account_did, revoked_at }`; thereafter requests
 * signed by that key fail with 401 `revoked_key`.
 */
export async function handleOwnerRevoke(
  req: Request,
  session: OwnerSession,
): Promise<Response> {
  return server.handleKeyRevocation(req, session);
}

/**
 * Turnkey owner re-key (the resume half). Body carries
 * `{ current_account_did, new_account_did }`. Under did:key the account
 * identifier changes; the response returns the new DID. The owner
 * binding and `sub_h` carry forward.
 */
export async function handleOwnerReKey(
  req: Request,
  session: OwnerSession,
): Promise<Response> {
  return server.handleKeyReKey(req, session);
}

/**
 * Bare primitive, gated by hand. Use when you already hold the DID (not
 * a request body) — e.g. an internal admin/abuse tool. Still gate on a
 * fresh owner session for any owner-facing surface.
 */
export async function revokeByDidDirect(did: Did, session: OwnerSession): Promise<void> {
  assertFreshOwnerSession(session, { maxAgeSeconds: 120 });
  await server.revoke(did);
}
