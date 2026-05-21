/**
 * Reference AFAuth Cloudflare Worker.
 *
 * Wires `@afauth/server` (Verifier, Server, MemoryAccountStore,
 * consoleEmailHandler) together with `@afauth/worker` (createWorker,
 * KvNonceStore) into a deployable Worker.
 *
 * M2 capability:
 *   - Serves /.well-known/afauth.
 *   - Accepts agent-signed owner-invitation; the email handler logs
 *     the magic link to the Worker's console (visible in `wrangler
 *     tail`).
 *   - Accepts POSTs to /afauth/v1/claim/<token> with an
 *     X-Owner-Session header carrying a JSON-encoded session blob —
 *     a stand-in for whatever auth your real claim page uses.
 *   - Returns the account record from GET /afauth/v1/accounts/me.
 *
 * The session-extraction strategy is intentionally trivial; production
 * deployments replace `extractOwnerSession` with their real auth.
 */

import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  type DiscoveryDocument,
  type OwnerSession,
} from "@afauth/server";
import { createWorker, KvNonceStore } from "@afauth/worker";

interface Env {
  /** Optional Cloudflare KV namespace for the production nonce store. */
  AFAUTH_NONCES?: KVNamespace;
  /** Service DID; e.g. "did:web:api.example.com". */
  SERVICE_DID?: string;
  /** Base URL of this Worker; used to compose claim-page URLs. */
  BASE_URL?: string;
}

const DEFAULT_BASE_URL = "https://example.com";

function buildDiscovery(env: Env): DiscoveryDocument {
  return {
    afauth_version: "0.1",
    service_did: env.SERVICE_DID ?? "did:web:example.com",
    endpoints: {
      accounts: "/afauth/v1/accounts",
      owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
      claim_page: "/claim",
      claim_completion: "/afauth/v1/claim",
      key_rotation: "/afauth/v1/accounts/me/keys/rotate",
    },
    signature_algorithms: ["ed25519"],
    features: ["key_rotation"],
    recipient_types: ["email"],
  };
}

// In-memory account store is fine for the example. Production deployments
// substitute a Cloudflare KV-backed or D1-backed implementation that
// upholds the §7.3 atomicity contract.
const accounts = new MemoryAccountStore();

/**
 * Header-based owner session for the example. The claim page passes the
 * authenticated identity as JSON in an `X-Owner-Session` header:
 *
 *   X-Owner-Session: {"authenticated":{"type":"email","value":"alice@example.com"},"userId":"usr_alice"}
 *
 * A real deployment replaces this with the session shape its own auth
 * system produces — typically a parsed cookie or IdP-issued JWT.
 */
async function extractOwnerSession(req: Request): Promise<OwnerSession | null> {
  const raw = req.headers.get("x-owner-session");
  if (!raw) return null;
  try {
    return JSON.parse(raw) as OwnerSession;
  } catch {
    return null;
  }
}

const exportedHandler: ExportedHandler<Env> = {
  fetch(req, env, ctx) {
    const discovery = buildDiscovery(env);
    const baseUrl = env.BASE_URL ?? DEFAULT_BASE_URL;
    const handler = createWorker({
      nonceStore: env.AFAUTH_NONCES ? new KvNonceStore(env.AFAUTH_NONCES) : new MemoryNonceStore(),
      serviceDid: discovery.service_did,
      accounts,
      recipients: { email: consoleEmailHandler },
      discovery,
      baseUrl,
      extractOwnerSession,
    });
    return handler.fetch!(req, env, ctx);
  },
};

export default exportedHandler;
