/**
 * Recipe: owner-driven revocation (§8.4).
 *
 * `Server.revoke(did)` adds the DID to the revocation list and marks
 * the account row revoked. After this, every signed request from
 * that DID will fail with `401 revoked_key` at the `Verifier`.
 *
 * This method is NOT itself an AFAuth-signed endpoint — there is no
 * `/.well-known` route for it. You call it from your own
 * **owner-authenticated** route. The protocol's two-step verify
 * invariant (§7.1) means an agent's key MUST NOT be able to revoke
 * its own account; gate this route on a fresh owner session per §7.5.
 *
 * §7.5 freshness floor (60-300s) applies because revoking the agent
 * is an owner-binding operation — it changes which credentials can
 * authenticate as the account.
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
  },
});

/**
 * Service-defined route: revoke this agent's key. Owner-authenticated,
 * fresh-session-required. Not an AFAuth wire endpoint.
 */
export async function handleOwnerRevokeAgent(
  did: Did,
  session: OwnerSession,
): Promise<void> {
  // §7.5: require evidence of a fresh authentication event (60-300s).
  // The window is service-defined; 120s is a reasonable default.
  assertFreshOwnerSession(session, { maxAgeSeconds: 120 });

  // Storage-level mutation + revocation list update. Subsequent
  // requests signed by `did` will fail with 401 revoked_key.
  await server.revoke(did);
}
