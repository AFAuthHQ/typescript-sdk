/**
 * Reference AFAuth Cloudflare Worker.
 *
 * Composes `@afauth/server` (Verifier, Server, named-op AccountStore)
 * with `@afauth/worker` (createWorker, KvNonceStore). M0 placeholder:
 * once the underlying packages implement their stubs, this Worker will
 * route the five AFAuth endpoints end-to-end against a KV-backed
 * account store and an email RecipientHandler that logs the magic
 * link to console.
 *
 * For now, the Worker boots and returns the discovery document — that
 * is the M0 deliverable for the reference Worker.
 */

import {
  MemoryNonceStore,
  Server,
  type AccountStore,
  type DiscoveryDocument,
  type RecipientHandler,
} from "@afauth/server";

interface Env {
  /** Cloudflare KV namespace for the production nonce store. */
  AFAUTH_NONCES?: KVNamespace;
  /** Service did:web identifier, e.g. "did:web:api.example.com". */
  SERVICE_DID?: string;
  /** Base URL of this Worker, used to compose endpoint URLs. */
  BASE_URL?: string;
}

const DISCOVERY: DiscoveryDocument = {
  afauth_version: "0.1",
  service_did: "did:web:example.com",
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

// Placeholder AccountStore — replaced with a KV-backed implementation in M2.
const accountStore: AccountStore = {
  async get() { return null; },
  async createUnclaimed() { throw new Error("not_implemented: createUnclaimed"); },
  async setPendingInvitation() { throw new Error("not_implemented: setPendingInvitation"); },
  async completeClaimByToken() { return null; },
  async rotateKey() { throw new Error("not_implemented: rotateKey"); },
  async revoke() { throw new Error("not_implemented: revoke"); },
};

// Placeholder email recipient handler — replaced in M2 with one that
// logs the magic link to console.
const emailHandler: RecipientHandler = {
  async initiate() {
    throw new Error("not_implemented: emailHandler.initiate");
  },
  matches({ pending, authenticated }) {
    if (pending.type !== "email" || authenticated.type !== "email") return false;
    return pending.value.toLowerCase() === authenticated.value.toLowerCase();
  },
};

export default {
  async fetch(req: Request, _env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/.well-known/afauth") {
      // M0 deliverable: discovery boots and serves a valid document.
      return new Response(JSON.stringify(DISCOVERY), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    // The Server class below is constructed but not yet dispatched to —
    // wiring up the router happens in M1. This call exists to make sure
    // ServerOptions stays type-compatible with the placeholder values.
    const _server = new Server({
      nonceStore: new MemoryNonceStore(),
      serviceDid: DISCOVERY.service_did,
      accounts: accountStore,
      recipients: { email: emailHandler },
      discovery: DISCOVERY,
      baseUrl: "https://example.com",
    });
    void _server;

    return new Response("Not Found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
