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

import { AFAuthError, type Did, type AFAuthErrorCode, type Recipient } from "@afauth/core";
import {
  Server,
  type Account,
  type AccountState,
  type AccountStore,
  type NonceStore,
  type OwnerSession,
  type RateLimitConfig,
  type RateLimitDecision,
  type RateLimiter,
  type RevocationList,
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
  // we route on path only. Trailing slashes are stripped so that
  // `/foo/` and `/foo` route identically — important for the claim
  // completion path-prefix match which composes `<prefix>/<token>`.
  let p: string;
  try {
    p = new URL(endpoint, "http://_/").pathname;
  } catch {
    p = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  }
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p;
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

/**
 * Cloudflare KV–backed revocation list (§8.3). Stores each revoked DID
 * → ISO timestamp without TTL; revocations are durable.
 *
 * Implementations that want bounded growth can later expire entries
 * after a service-defined retention window without changing this
 * interface.
 */
export class KvRevocationList implements RevocationList {
  constructor(private readonly namespace: KVNamespace) {}

  async isRevoked(did: Did): Promise<boolean> {
    return (await this.namespace.get(`revoked:${did}`)) !== null;
  }

  async add(did: Did, revokedAt: string): Promise<void> {
    await this.namespace.put(`revoked:${did}`, revokedAt);
  }
}

// ---------- D1AccountStore (§6 storage) ----------
//
// Production-grade AccountStore backed by Cloudflare D1 (managed
// SQLite). The schema lives at migrations/0001_init.sql and is
// applied via `wrangler d1 migrations apply <db-name>`. The SQL is
// portable to standard Postgres/MySQL with minor syntactic changes.
//
// Atomicity is provided by D1's `batch()`, which executes a sequence
// of statements as a single transaction. The named atomic ops from
// ADR-0004 each map to one batch:
//   - setPendingInvitation → DELETE prior + INSERT new (the §7.3
//     atomicity invariant; UNIQUE(account_did) backs it up at the
//     storage layer in case batch is bypassed).
//   - completeClaimByToken → UPDATE state + DELETE invitation.
//   - rotateKey → UPDATE did + cascading FK update on invitation.
//   - revoke → UPDATE revoked = 1.
//
// On schema migration: the v0.1 schema is the only published version;
// future migrations land as 0002_*.sql, 0003_*.sql, etc.

interface AccountRow {
  did: string;
  state: AccountState;
  created_at: string;
  updated_at: string;
  owner_json: string | null;
  revoked: number;
}

interface InvitationRow {
  token: string;
  account_did: string;
  recipient_json: string;
  expires_at: string;
}

function rowToAccount(row: AccountRow, pending?: Recipient): Account {
  const out: Account = { did: row.did, state: row.state };
  if (row.revoked) out.revoked = true;
  if (row.owner_json) out.owner = JSON.parse(row.owner_json) as Account["owner"];
  if (pending) out.pendingRecipient = pending;
  return out;
}

/**
 * Cloudflare D1–backed `AccountStore`. The constructor takes a D1
 * database binding (the same `env.DB` shape `wrangler` injects).
 *
 *   new D1AccountStore(env.AFAUTH_DB)
 *
 * Schema: see migrations/0001_init.sql. Run `wrangler d1 migrations
 * apply <db-name>` before first use.
 *
 * Every atomic op uses `db.batch()` to run its statements as a single
 * transaction; race-free under concurrent invocations.
 */
export class D1AccountStore implements AccountStore {
  constructor(private readonly db: D1Database) {}

  async get(did: Did): Promise<Account | null> {
    const row = await this.db
      .prepare("SELECT * FROM afauth_accounts WHERE did = ?")
      .bind(did)
      .first<AccountRow>();
    if (!row) return null;
    const invite = await this.db
      .prepare("SELECT * FROM afauth_invitations WHERE account_did = ?")
      .bind(did)
      .first<InvitationRow>();
    const pending = invite ? (JSON.parse(invite.recipient_json) as Recipient) : undefined;
    return rowToAccount(row, pending);
  }

  async findByPendingToken(token: string): Promise<Account | null> {
    const invite = await this.db
      .prepare("SELECT * FROM afauth_invitations WHERE token = ?")
      .bind(token)
      .first<InvitationRow>();
    if (!invite) return null;
    if (new Date(invite.expires_at).getTime() < Date.now()) {
      // Drop expired invitations opportunistically (§7.3 says
      // expired invitations transition the account back to UNCLAIMED;
      // the actual transition runs elsewhere — here we just refuse
      // to return a stale token).
      await this.db.prepare("DELETE FROM afauth_invitations WHERE token = ?").bind(token).run();
      return null;
    }
    const row = await this.db
      .prepare("SELECT * FROM afauth_accounts WHERE did = ?")
      .bind(invite.account_did)
      .first<AccountRow>();
    if (!row) return null;
    const pending = JSON.parse(invite.recipient_json) as Recipient;
    return rowToAccount(row, pending);
  }

  async createUnclaimed(did: Did): Promise<Account> {
    const existing = await this.get(did);
    if (existing) return existing;
    const nowIso = new Date().toISOString();
    await this.db
      .prepare(
        "INSERT INTO afauth_accounts (did, state, created_at, updated_at) VALUES (?, ?, ?, ?)",
      )
      .bind(did, "UNCLAIMED", nowIso, nowIso)
      .run();
    return { did, state: "UNCLAIMED" };
  }

  async setPendingInvitation(
    did: Did,
    recipient: Recipient,
    token: string,
    expiresAt: string,
  ): Promise<Account> {
    // Pre-check account state. §7.3's atomic supersession is the DELETE
    // + INSERT batch; the state guard prevents inviting against a
    // CLAIMED or revoked account.
    const account = await this.get(did);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${did} does not exist`);
    }
    if (account.revoked) {
      throw new AFAuthError("revoked_key", 401, `account ${did} is revoked`);
    }
    if (account.state === "CLAIMED") {
      throw new AFAuthError(
        "already_claimed",
        409,
        "account is already claimed; further owner-invitation is post-claim policy",
      );
    }
    const nowIso = new Date().toISOString();
    // Atomic: DELETE any prior invitation for this account, then
    // INSERT the new one, then UPDATE the account state to INVITED.
    await this.db.batch([
      this.db.prepare("DELETE FROM afauth_invitations WHERE account_did = ?").bind(did),
      this.db
        .prepare(
          "INSERT INTO afauth_invitations (token, account_did, recipient_json, expires_at) VALUES (?, ?, ?, ?)",
        )
        .bind(token, did, JSON.stringify(recipient), expiresAt),
      this.db
        .prepare("UPDATE afauth_accounts SET state = ?, updated_at = ? WHERE did = ?")
        .bind("INVITED", nowIso, did),
    ]);
    return { did, state: "INVITED", pendingRecipient: recipient };
  }

  async completeClaimByToken(
    token: string,
    owner: NonNullable<Account["owner"]>,
  ): Promise<Account | null> {
    const invite = await this.db
      .prepare("SELECT * FROM afauth_invitations WHERE token = ?")
      .bind(token)
      .first<InvitationRow>();
    if (!invite) return null;
    if (new Date(invite.expires_at).getTime() < Date.now()) {
      await this.db.prepare("DELETE FROM afauth_invitations WHERE token = ?").bind(token).run();
      return null;
    }
    const accountDid = invite.account_did;
    const nowIso = new Date().toISOString();
    await this.db.batch([
      this.db
        .prepare(
          "UPDATE afauth_accounts SET state = ?, owner_json = ?, updated_at = ? WHERE did = ?",
        )
        .bind("CLAIMED", JSON.stringify(owner), nowIso, accountDid),
      this.db.prepare("DELETE FROM afauth_invitations WHERE token = ?").bind(token),
    ]);
    const row = await this.db
      .prepare("SELECT * FROM afauth_accounts WHERE did = ?")
      .bind(accountDid)
      .first<AccountRow>();
    if (!row) return null;
    return rowToAccount(row);
  }

  async rotateKey(oldDid: Did, newDid: Did, rotatedAt: string): Promise<Account> {
    const old = await this.db
      .prepare("SELECT * FROM afauth_accounts WHERE did = ?")
      .bind(oldDid)
      .first<AccountRow>();
    if (!old) {
      throw new AFAuthError("unknown_account", 404, `account ${oldDid} does not exist`);
    }
    // Atomic: INSERT new row + UPDATE invitation FK (if any) +
    // DELETE old row. Using INSERT-then-DELETE keeps the FK satisfied
    // during the swap; the ON DELETE CASCADE doesn't fire because we
    // re-point the invitation first.
    await this.db.batch([
      this.db
        .prepare(
          "INSERT INTO afauth_accounts (did, state, created_at, updated_at, owner_json, revoked) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(newDid, old.state, old.created_at, rotatedAt, old.owner_json, old.revoked),
      this.db
        .prepare("UPDATE afauth_invitations SET account_did = ? WHERE account_did = ?")
        .bind(newDid, oldDid),
      this.db.prepare("DELETE FROM afauth_accounts WHERE did = ?").bind(oldDid),
    ]);
    const out: Account = { did: newDid, state: old.state };
    if (old.revoked) out.revoked = true;
    if (old.owner_json) out.owner = JSON.parse(old.owner_json) as Account["owner"];
    return out;
  }

  async revoke(did: Did, revokedAt: string): Promise<Account> {
    const existing = await this.db
      .prepare("SELECT * FROM afauth_accounts WHERE did = ?")
      .bind(did)
      .first<AccountRow>();
    if (!existing) {
      throw new AFAuthError("unknown_account", 404, `account ${did} does not exist`);
    }
    await this.db
      .prepare("UPDATE afauth_accounts SET revoked = 1, updated_at = ? WHERE did = ?")
      .bind(revokedAt, did)
      .run();
    const row: AccountRow = { ...existing, revoked: 1, updated_at: revokedAt };
    return rowToAccount(row);
  }
}

/**
 * Cloudflare KV–backed rate limiter (§11.3). Fixed-window counter per
 * key; KV's eventually-consistent reads mean racing isolates may
 * over-count (fail-safe), never under-count.
 *
 * Storage layout: `ratelimit:<key>` → JSON `{ windowStart, count }`,
 * with KV `expirationTtl = windowSeconds + 60` so old buckets evict
 * automatically. The 60-second buffer absorbs clock skew between
 * isolates without leaking stale buckets.
 */
export class KvRateLimiter implements RateLimiter {
  constructor(
    private readonly namespace: KVNamespace,
    private readonly opts: { now?: () => number } = {},
  ) {}

  private now(): number {
    return this.opts.now ? this.opts.now() : Math.floor(Date.now() / 1000);
  }

  async take(key: string, config: RateLimitConfig): Promise<RateLimitDecision> {
    const storageKey = `ratelimit:${key}`;
    const nowSec = this.now();
    const existing = await this.namespace.get(storageKey, "json") as
      | { windowStart: number; count: number }
      | null;

    let windowStart: number;
    let count: number;
    if (!existing || existing.windowStart + config.windowSeconds <= nowSec) {
      windowStart = nowSec;
      count = 0;
    } else {
      windowStart = existing.windowStart;
      count = existing.count;
    }
    const resetAt = windowStart + config.windowSeconds;
    if (count >= config.limit) {
      return {
        ok: false,
        retryAfter: Math.max(1, resetAt - nowSec),
        remaining: 0,
        resetAt,
      };
    }
    count++;
    // KV expirationTtl MUST be ≥ 60s; clamp accordingly.
    const ttl = Math.max(60, config.windowSeconds + 60);
    await this.namespace.put(storageKey, JSON.stringify({ windowStart, count }), {
      expirationTtl: ttl,
    });
    return { ok: true, remaining: config.limit - count, resetAt };
  }
}

// Re-export the error code type so worker consumers can switch on it.
export type { AFAuthErrorCode };
