/**
 * Reference AFAuth Cloudflare Worker.
 *
 * Wires `@afauthhq/server` (Verifier, Server, MemoryAccountStore,
 * consoleEmailHandler) together with `@afauthhq/worker` (createWorker,
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
  MemoryRevocationList,
  type AccountStore,
  type DiscoveryDocument,
  type OwnerSession,
} from "@afauthhq/server";
import {
  createNonceDurableObject,
  createWorker,
  D1AccountStore,
  DurableObjectNonceStore,
  KvNonceStore,
  KvRevocationList,
} from "@afauthhq/worker";

// The §5.6 atomic nonce store is the Durable Object actor below.
// Export it so wrangler can register the class under the binding name
// declared in `wrangler.toml` ([[durable_objects.bindings]]).
export class AFAuthNonceDO extends createNonceDurableObject() {}

interface Env {
  /**
   * Recommended: Durable Object binding for the §5.6 atomic nonce
   * store. When set, the worker uses `DurableObjectNonceStore` which
   * provides spec-compliant atomic check-and-set for replay defence.
   */
  AFAUTH_NONCE_DO?: DurableObjectNamespace;
  /**
   * Fallback: Cloudflare KV namespace for the nonce store. KV is
   * eventually consistent — see the `KvNonceStore` JSDoc for the
   * known replay window. Prefer `AFAUTH_NONCE_DO` for production.
   */
  AFAUTH_NONCES?: KVNamespace;
  /** Optional Cloudflare KV namespace for the §8.3 revocation list. */
  AFAUTH_REVOCATIONS?: KVNamespace;
  /**
   * Optional Cloudflare D1 binding for the durable account store.
   * Apply `packages/worker/migrations/0001_init.sql` before first use
   * (`wrangler d1 migrations apply <db-name>`). When absent, the
   * worker falls back to MemoryAccountStore — a process-local map
   * that loses every account on isolate recycle. Suitable for demo,
   * NOT for production.
   */
  AFAUTH_ACCOUNTS?: D1Database;
  /** Service DID; e.g. "did:web:api.example.com". */
  SERVICE_DID?: string;
  /** Base URL of this Worker; used to compose claim-page URLs. */
  BASE_URL?: string;
  /**
   * Opt-in toggle for the demo-only X-Owner-Session extractor below.
   * MUST be left undefined in production; setting it to "true" enables
   * a trivially forgeable header path that should ONLY be used while
   * developing the claim page locally. See `extractOwnerSession`.
   */
  AFAUTH_DEV_TRUST_HEADER?: string;
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

// Account store: prefer D1 (durable; cross-isolate consistent) when
// the binding is present; fall back to MemoryAccountStore for demo
// runs. The Memory store loses every account on isolate recycle —
// `wrangler tail` will surface a one-time warning when that path
// is taken in production.
const memoryAccounts = new MemoryAccountStore();
function selectAccountStore(env: Env): AccountStore {
  if (env.AFAUTH_ACCOUNTS) return new D1AccountStore(env.AFAUTH_ACCOUNTS);
  return memoryAccounts;
}

/**
 * Owner-session extractor for the reference Worker.
 *
 * DEFAULT BEHAVIOUR: returns `null` so the §7.4 claim-completion path
 * fails closed with `401 owner_authentication_required`. A real
 * deployment replaces this function with one that verifies an
 * authenticated session (signed cookie, IdP-issued JWT, etc.).
 *
 * DEMO ESCAPE HATCH (gated): when the env var `AFAUTH_DEV_TRUST_HEADER`
 * is set to the literal string `"true"`, this function will accept an
 * `X-Owner-Session` header carrying a JSON-encoded `OwnerSession`. The
 * header is trivially forgeable by anyone who can reach the Worker, so
 * the gate exists only to make local end-to-end testing possible
 * without a real auth layer. NEVER set this var in production.
 *
 *   X-Owner-Session: {"authenticated":{"type":"email","value":"alice@example.com"},"userId":"usr_alice"}
 */
function makeExtractOwnerSession(env: Env) {
  const trustHeader = env.AFAUTH_DEV_TRUST_HEADER === "true";
  return async function extractOwnerSession(req: Request): Promise<OwnerSession | null> {
    if (!trustHeader) return null;
    const raw = req.headers.get("x-owner-session");
    if (!raw) return null;
    try {
      return JSON.parse(raw) as OwnerSession;
    } catch {
      return null;
    }
  };
}

// Process-wide revocation list (in-memory) used when no KV binding is
// configured. Production deployments set AFAUTH_REVOCATIONS so the
// list survives isolate recycling.
const memoryRevocationList = new MemoryRevocationList();

function selectNonceStore(env: Env) {
  // Prefer DO (atomic) → KV (eventually consistent) → Memory (dev).
  if (env.AFAUTH_NONCE_DO) return new DurableObjectNonceStore(env.AFAUTH_NONCE_DO);
  if (env.AFAUTH_NONCES) return new KvNonceStore(env.AFAUTH_NONCES);
  return new MemoryNonceStore();
}

const exportedHandler: ExportedHandler<Env> = {
  fetch(req, env, ctx) {
    const discovery = buildDiscovery(env);
    const baseUrl = env.BASE_URL ?? DEFAULT_BASE_URL;
    const handler = createWorker({
      nonceStore: selectNonceStore(env),
      revocationList: env.AFAUTH_REVOCATIONS
        ? new KvRevocationList(env.AFAUTH_REVOCATIONS)
        : memoryRevocationList,
      serviceDid: discovery.service_did,
      accounts: selectAccountStore(env),
      recipients: { email: consoleEmailHandler },
      discovery,
      baseUrl,
      extractOwnerSession: makeExtractOwnerSession(env),
    });
    return handler.fetch!(req, env, ctx);
  },
};

export default exportedHandler;
