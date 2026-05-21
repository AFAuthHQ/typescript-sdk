/**
 * @afauth/worker — Cloudflare Workers bindings for the AFAuth Protocol.
 *
 * Provides a `createWorker(opts)` factory that routes the five AFAuth
 * endpoints (discovery, owner-invitation, claim-completion, key-rotation,
 * account-introspection) to the corresponding `@afauth/server`
 * handlers, and a `KvNonceStore` for §5.6 replay detection backed by
 * Cloudflare KV.
 *
 * Routing is done with a small in-house router (no Hono / itty-router)
 * per ADR-0002.
 *
 * Function bodies throw `not_implemented` in this skeleton.
 */

import type { Did, AFAuthErrorCode } from "@afauth/core";
import type {
  NonceStore,
  OwnerSession,
  ServerOptions,
} from "@afauth/server";

export interface WorkerOptions extends ServerOptions {
  /**
   * Required. Bridges the Worker's uniform routing to the §7.4
   * claim-completion asymmetry — only that endpoint depends on a
   * human-authenticated session. Return `null` to reject with
   * `401 owner_authentication_required`.
   * See `implementation/adr/0004-sdk-api-shape.md` in the spec repo.
   */
  extractOwnerSession: (req: Request) => Promise<OwnerSession | null>;
}

/** Cloudflare Worker handler. Routes the five AFAuth endpoints; 404 otherwise. */
export function createWorker(_opts: WorkerOptions): ExportedHandler {
  throw new Error("not_implemented: createWorker");
}

/** Cloudflare KV–backed nonce store; uses KV TTL for §5.6 expiry. */
export class KvNonceStore implements NonceStore {
  constructor(_namespace: KVNamespace) {
    // intentionally empty in skeleton
  }

  async seen(_keyid: Did, _nonce: string, _ttlSeconds: number): Promise<boolean> {
    throw new Error("not_implemented: KvNonceStore.seen");
  }
}

// Re-export the error code type so worker consumers can switch on it
// without separately importing from @afauth/core.
export type { AFAuthErrorCode };
