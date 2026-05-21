/**
 * @afauth/worker — Cloudflare Workers bindings for the AFAuth Protocol.
 *
 * `createWorker(opts)` produces a Cloudflare `ExportedHandler` that
 * routes the five AFAuth endpoints (discovery, owner-invitation,
 * claim-completion, key-rotation, account-introspection) to the
 * matching `@afauth/server` handlers. Routing is done with a small
 * in-house router per ADR-0002 — no Hono, no itty-router.
 *
 * `KvNonceStore` wraps a Cloudflare KV namespace as a `NonceStore`,
 * using KV TTL for §5.6 expiry.
 */

import { AFAuthError, type Did, type AFAuthErrorCode } from "@afauth/core";
import {
  Server,
  type NonceStore,
  type OwnerSession,
  type ServerOptions,
} from "@afauth/server";

export interface WorkerOptions extends ServerOptions {
  /**
   * Required. Bridges the Worker's uniform routing to the §7.4
   * claim-completion asymmetry — only that endpoint depends on a
   * human-authenticated session. Return `null` to reject with
   * `401 owner_authentication_required`.
   */
  extractOwnerSession: (req: Request) => Promise<OwnerSession | null>;
}

interface Resolved {
  discovery: import("@afauth/server").DiscoveryDocument;
  ownerInvitationPath: string;
  claimCompletionPathPrefix: string;
  keyRotationPath?: string;
  accountsPath: string;
}

function pathOf(endpoint: string): string {
  // The discovery doc may carry absolute or relative endpoint URLs;
  // we route on path only.
  try {
    return new URL(endpoint, "http://_/").pathname;
  } catch {
    return endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  }
}

/** Cloudflare Worker handler. Routes the five AFAuth endpoints; 404 otherwise. */
export function createWorker(opts: WorkerOptions): ExportedHandler {
  const server = new Server(opts);

  let resolvedPromise: Promise<Resolved> | null = null;
  async function resolve(): Promise<Resolved> {
    if (!resolvedPromise) {
      resolvedPromise = (async () => {
        const discovery =
          typeof opts.discovery === "function" ? await opts.discovery() : opts.discovery;
        return {
          discovery,
          ownerInvitationPath: pathOf(discovery.endpoints.owner_invitation),
          claimCompletionPathPrefix: pathOf(discovery.endpoints.claim_completion),
          ...(discovery.endpoints.key_rotation
            ? { keyRotationPath: pathOf(discovery.endpoints.key_rotation) }
            : {}),
          accountsPath: pathOf(discovery.endpoints.accounts),
        };
      })();
    }
    return resolvedPromise;
  }

  return {
    async fetch(req: Request): Promise<Response> {
      try {
        const url = new URL(req.url);
        const path = url.pathname;

        // Discovery — well-known path, no resolve needed.
        if (path === "/.well-known/afauth") {
          return await server.handleDiscovery(req);
        }

        const routes = await resolve();

        if (path === routes.ownerInvitationPath && req.method === "POST") {
          return await server.handleOwnerInvitation(req);
        }

        if (path.startsWith(routes.claimCompletionPathPrefix + "/") && req.method === "POST") {
          const session = await opts.extractOwnerSession(req);
          if (!session) {
            throw new AFAuthError(
              "owner_authentication_required",
              401,
              "claim completion requires an owner-authenticated session",
            );
          }
          return await server.handleClaimCompletion(req, session);
        }

        if (routes.keyRotationPath && path === routes.keyRotationPath && req.method === "POST") {
          return await server.handleKeyRotation(req);
        }

        // /afauth/v1/accounts/me — account introspection.
        if (path === `${routes.accountsPath}/me` && req.method === "GET") {
          return await server.handleAccountIntrospection(req);
        }

        return new Response("Not Found", { status: 404 });
      } catch (err) {
        if (err instanceof AFAuthError) return err.toResponse();
        // Unknown failure — log and return a generic 500.
        console.error("[afauth] unhandled error in worker handler:", err);
        return new Response(
          JSON.stringify({
            error: { code: "malformed_request", message: "internal server error" },
          }),
          { status: 500, headers: { "content-type": "application/json" } },
        );
      }
    },
  } satisfies ExportedHandler;
}

/** Cloudflare KV–backed nonce store; uses KV TTL for §5.6 expiry. */
export class KvNonceStore implements NonceStore {
  constructor(private readonly namespace: KVNamespace) {}

  async seen(keyid: Did, nonce: string, ttlSeconds: number): Promise<boolean> {
    const key = `nonce:${keyid}:${nonce}`;
    const existing = await this.namespace.get(key);
    if (existing !== null) return false;
    // KV's `expirationTtl` must be ≥ 60 seconds; floor the v0.1 window.
    const ttl = Math.max(60, Math.ceil(ttlSeconds));
    await this.namespace.put(key, "1", { expirationTtl: ttl });
    return true;
  }
}

// Re-export the error code type so worker consumers can switch on it.
export type { AFAuthErrorCode };
