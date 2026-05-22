/**
 * Recipe: pre-claim key rotation (§8.1).
 *
 * While an account is in `UNCLAIMED` or `INVITED` state, the agent
 * MAY rotate its verification key by signing a rotation request with
 * the OLD key. After successful rotation, the old key is revoked on
 * the service side (§8.3) and subsequent requests MUST be signed by
 * the new key.
 *
 * For `did:key`, the account identifier changes because the
 * identifier encodes the public key. External references to the
 * old DID will no longer resolve. Implementations operating
 * long-lived accounts SHOULD use `did:web` so the identifier remains
 * stable across rotations.
 *
 * Post-claim rotation is different (§8.2) — it requires owner
 * approval. This recipe covers pre-claim only.
 */

import { Agent } from "@afauthhq/agent";

const baseUrl = "https://api.example.com";

/**
 * Rotate the agent's key against the service. Returns the new Agent
 * instance; persist it (and discard the old one) on success.
 */
export async function rotateAgentKey(oldAgent: Agent): Promise<Agent> {
  // Generate the replacement keypair locally.
  const newAgent = await Agent.generate();

  // Sign the rotation request with the OLD key. The service replays
  // the old DID forward and marks the new DID as the live one.
  const signed = await oldAgent.buildKeyRotation({
    baseUrl,
    newDid: newAgent.did,
  });

  const res = await fetch(signed.url, {
    method: signed.method,
    headers: signed.headers,
    body: signed.body,
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`rotation failed: ${res.status} ${body}`);
  }

  // Service response includes the new account_did and old_revoked_at.
  // Subsequent calls MUST use `newAgent`.
  return newAgent;
}
