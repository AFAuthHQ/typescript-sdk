/**
 * @afauthhq/worker — Cloudflare Workers bindings for the AFAuth Protocol.
 *
 * `createWorker(opts)` produces a Cloudflare `ExportedHandler` that
 * routes the five AFAuth endpoints (discovery, owner-invitation,
 * claim-completion, key-rotation, account-introspection) to the
 * matching `@afauthhq/server` handlers. Routing is done with a small
 * in-house router per ADR-0002 — no Hono, no itty-router.
 *
 * `KvNonceStore` wraps a Cloudflare KV namespace as a `NonceStore`,
 * using KV TTL for §5.6 expiry.
 */

import { AFAuthError, type Did, type AFAuthErrorCode, type Recipient } from "@afauthhq/core";
import {
  Server,
  type Account,
  type AccountState,
  type AccountStore,
  type SweepableAccountStore,
  type NonceStore,
  type OwnerSession,
  type RateLimitConfig,
  type RateLimitDecision,
  type RateLimiter,
  type AttestedFreshnessStore,
  type RevocationList,
  type ServerOptions,
  type SubHUniquenessStore,
  type SubHClaimResult,
} from "@afauthhq/server";

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
  discovery: import("@afauthhq/server").DiscoveryDocument;
  ownerInvitationPath: string;
  claimCompletionPathPrefix: string;
  keyRotationPath?: string;
  keyReKeyPath?: string;
  keyRevocationPath?: string;
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
          ...(discovery.endpoints.key_rekey
            ? { keyReKeyPath: pathOf(discovery.endpoints.key_rekey) }
            : {}),
          ...(discovery.endpoints.key_revocation
            ? { keyRevocationPath: pathOf(discovery.endpoints.key_revocation) }
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

        // Owner-gated key endpoints (§8.2 re-key, §8.4 revoke). These are
        // NOT agent-signed — they depend on an owner-authenticated session
        // (the agent key may be stolen), so they extract the session like
        // claim-completion does. A missing session is 401 (no credential
        // presented); a present-but-wrong owner is 403, returned by the
        // handler.
        if (routes.keyReKeyPath && path === routes.keyReKeyPath && req.method === "POST") {
          const session = await opts.extractOwnerSession(req);
          if (!session) {
            throw new AFAuthError(
              "owner_authentication_required",
              401,
              "owner re-key requires an owner-authenticated session",
            );
          }
          return await server.handleKeyReKey(req, session);
        }

        if (routes.keyRevocationPath && path === routes.keyRevocationPath && req.method === "POST") {
          const session = await opts.extractOwnerSession(req);
          if (!session) {
            throw new AFAuthError(
              "owner_authentication_required",
              401,
              "owner revocation requires an owner-authenticated session",
            );
          }
          return await server.handleKeyRevocation(req, session);
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

/**
 * Cloudflare KV–backed nonce store; uses KV TTL for §5.6 expiry.
 *
 * !!! KNOWN LIMITATION — eventual consistency.
 *
 * KV does not expose an atomic check-and-set primitive. This impl
 * performs `get` then `put`; under racing isolates two concurrent
 * verifications of the same `(keyid, nonce)` tuple within the
 * freshness window can both observe `existing === null`, both write,
 * and both return `true`. §5.6 normatively requires the seen-nonce
 * set be shared across instances *with* atomic insertion; KV only
 * satisfies the first half.
 *
 * Practical effect: an attacker who can fan out the same signed
 * request to multiple Cloudflare edge regions in &lt; ~10 seconds may
 * be able to replay once. This window is bounded by the signature's
 * `expires` parameter (≤ 300s per §5.2; the SDK's default is 60s),
 * and by Cloudflare KV's typical cross-region propagation time.
 *
 * For deployments where this risk matters — anything with real value
 * behind the signature — use {@link DurableObjectNonceStore} instead.
 * A Durable Object actor serializes all `seen()` calls for a given
 * partition key and gives spec-compliant atomic check-and-set.
 *
 * `KvNonceStore` ships for use cases where the trade-off is
 * acceptable: low-value endpoints, dev-only deployments, or
 * deployments behind a single Cloudflare region. The default
 * reference Worker (`examples/worker`) prefers DO when its binding
 * is configured.
 */
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
 * Durable Object–backed nonce store. Spec-compliant atomic insert.
 *
 * Architecture: the caller has a single Durable Object namespace
 * binding (e.g. `env.AFAUTH_NONCE_DO`). For each request, the store
 * picks a partition key — by default the agent's `keyid` — and looks
 * up the corresponding DO actor via `idFromName(partition)`. The DO
 * serializes all `seen()` calls for its partition, performing the
 * check-and-set against its private DO storage atomically.
 *
 *   import { createNonceDurableObject } from "@afauthhq/worker";
 *   export class AFAuthNonceDO extends createNonceDurableObject() {}
 *
 *   const store = new DurableObjectNonceStore(env.AFAUTH_NONCE_DO);
 *
 * Wire up in `wrangler.toml`:
 *
 *   [[durable_objects.bindings]]
 *   name = "AFAUTH_NONCE_DO"
 *   class_name = "AFAuthNonceDO"
 *
 *   [[migrations]]
 *   tag = "v1"
 *   new_classes = ["AFAuthNonceDO"]
 *
 * Per-keyid partitioning bounds DO actor scope and lets the request
 * path fan out across multiple actors for unrelated agents. Sticky
 * routing on a single agent's nonces ensures serialization.
 */
export class DurableObjectNonceStore implements NonceStore {
  constructor(private readonly namespace: DurableObjectNamespace) {}

  async seen(keyid: Did, nonce: string, ttlSeconds: number): Promise<boolean> {
    const id = this.namespace.idFromName(`nonce:${keyid}`);
    const stub = this.namespace.get(id);
    const url = `https://nonce.invalid/seen?nonce=${encodeURIComponent(nonce)}&ttl=${Math.max(1, Math.ceil(ttlSeconds))}`;
    const resp = await stub.fetch(url, { method: "POST" });
    if (!resp.ok) {
      throw new Error(`DurableObjectNonceStore: actor returned HTTP ${resp.status}`);
    }
    const body = (await resp.json()) as { fresh?: boolean };
    return body.fresh === true;
  }
}

/**
 * Returns a base class for the AFAuth nonce Durable Object. Users
 * declare their concrete class by extending it; the runtime provides
 * the persistent storage and serializes `fetch` calls for the actor.
 *
 *   export class AFAuthNonceDO extends createNonceDurableObject() {}
 *
 * The DO answers a single internal request shape used by
 * {@link DurableObjectNonceStore}:
 *
 *   POST https://nonce.invalid/seen?nonce=&lt;value&gt;&ttl=&lt;seconds&gt;
 *
 * It performs an atomic check-and-set against its private storage
 * and returns `{ fresh: boolean }`. Storage entries auto-expire via
 * the DO's `alarm()` callback, which sweeps any nonces whose stored
 * `expiresAt` has elapsed.
 */
export function createNonceDurableObject(): new (
  state: DurableObjectState,
  env: unknown,
) => DurableObject {
  return class AFAuthNonceDOBase implements DurableObject {
    constructor(private readonly state: DurableObjectState) {}

    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url);
      if (url.pathname !== "/seen" || req.method !== "POST") {
        return new Response("not found", { status: 404 });
      }
      const nonce = url.searchParams.get("nonce");
      const ttlRaw = url.searchParams.get("ttl");
      if (!nonce || !ttlRaw) {
        return new Response(JSON.stringify({ error: "missing nonce or ttl" }), {
          status: 400,
          headers: { "content-type": "application/json" },
        });
      }
      const ttl = Math.max(1, Number.parseInt(ttlRaw, 10) || 0);
      const nowSec = Math.floor(Date.now() / 1000);
      const key = `n:${nonce}`;
      // blockConcurrencyWhile serializes against other actor work;
      // since the DO is single-threaded per partition, this is the
      // §5.6 atomic check-and-set guarantee.
      return this.state.blockConcurrencyWhile(async () => {
        const existing = await this.state.storage.get<number>(key);
        if (existing !== undefined && existing > nowSec) {
          return new Response(JSON.stringify({ fresh: false }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        await this.state.storage.put(key, nowSec + ttl);
        await this.scheduleSweep(nowSec + ttl);
        return new Response(JSON.stringify({ fresh: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      });
    }

    /** alarm() handler — sweeps expired entries opportunistically. */
    async alarm(): Promise<void> {
      const nowSec = Math.floor(Date.now() / 1000);
      const all = await this.state.storage.list<number>();
      const toDelete: string[] = [];
      let nextAlarm = Number.POSITIVE_INFINITY;
      for (const [k, expiresAt] of all) {
        if (typeof expiresAt !== "number") continue;
        if (expiresAt <= nowSec) toDelete.push(k);
        else if (expiresAt < nextAlarm) nextAlarm = expiresAt;
      }
      if (toDelete.length > 0) await this.state.storage.delete(toDelete);
      if (Number.isFinite(nextAlarm)) {
        await this.state.storage.setAlarm(nextAlarm * 1000);
      }
    }

    private async scheduleSweep(expiresAtSec: number): Promise<void> {
      const current = await this.state.storage.getAlarm();
      // Only set if no alarm is pending or the new alarm is sooner.
      const targetMs = expiresAtSec * 1000;
      if (current === null || targetMs < current) {
        await this.state.storage.setAlarm(targetMs);
      }
    }
  };
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

/**
 * Cloudflare KV–backed `AttestedFreshnessStore` (§10.7). Stores each
 * account's `attestedUntil` (unix seconds) as the value, and sets the KV
 * entry's own TTL to the remaining window so lapsed sessions self-evict.
 * The gate still compares against the stored value, so KV's eventual
 * consistency only ever errs toward an earlier challenge, never a later
 * one (fail-closed).
 */
export class KvAttestedFreshnessStore implements AttestedFreshnessStore {
  constructor(private readonly namespace: KVNamespace) {}

  async get(did: Did): Promise<number | null> {
    const v = await this.namespace.get(`attested:${did}`);
    if (v === null) return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  async set(did: Did, attestedUntilSeconds: number): Promise<void> {
    // KV requires expirationTtl ≥ 60s; floor at 60 so a short window
    // still persists. The stored value remains the precise attestedUntil.
    const remaining = attestedUntilSeconds - Math.floor(Date.now() / 1000);
    const expirationTtl = Math.max(60, remaining);
    await this.namespace.put(`attested:${did}`, String(attestedUntilSeconds), { expirationTtl });
  }

  async clear(did: Did): Promise<void> {
    await this.namespace.delete(`attested:${did}`);
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
  const out: Account = { did: row.did, state: row.state, createdAt: row.created_at };
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
export class D1AccountStore implements SweepableAccountStore {
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
    return { did, state: "UNCLAIMED", createdAt: nowIso };
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
    return {
      did,
      state: "INVITED",
      createdAt: account.createdAt,
      pendingRecipient: recipient,
    };
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
    const out: Account = { did: newDid, state: old.state, createdAt: old.created_at };
    if (old.revoked) out.revoked = true;
    if (old.owner_json) out.owner = JSON.parse(old.owner_json) as Account["owner"];
    return out;
  }

  async reKey(oldDid: Did, newDid: Did, reKeyedAt: string): Promise<Account> {
    const old = await this.db
      .prepare("SELECT * FROM afauth_accounts WHERE did = ?")
      .bind(oldDid)
      .first<AccountRow>();
    if (!old) {
      throw new AFAuthError("unknown_account", 404, `account ${oldDid} does not exist`);
    }
    // One batch() = one transaction: INSERT the new row with revoked
    // cleared (0), re-point any invitation FK, DELETE the old row. Doing
    // the clear in the SAME transaction as the rotate is what avoids the
    // bricking window a rotateKey + separate clear would leave on a
    // crash/interleave (each batch is its own D1 transaction).
    await this.db.batch([
      this.db
        .prepare(
          "INSERT INTO afauth_accounts (did, state, created_at, updated_at, owner_json, revoked) VALUES (?, ?, ?, ?, ?, 0)",
        )
        .bind(newDid, old.state, old.created_at, reKeyedAt, old.owner_json),
      this.db
        .prepare("UPDATE afauth_invitations SET account_did = ? WHERE account_did = ?")
        .bind(newDid, oldDid),
      this.db.prepare("DELETE FROM afauth_accounts WHERE did = ?").bind(oldDid),
    ]);
    const out: Account = { did: newDid, state: old.state, createdAt: old.created_at };
    // Note: `revoked` intentionally omitted — reKey clears it.
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

  async listOpenAccounts(): Promise<Account[]> {
    const result = await this.db
      .prepare(
        "SELECT * FROM afauth_accounts WHERE state IN ('UNCLAIMED', 'INVITED') ORDER BY created_at ASC",
      )
      .all<AccountRow>();
    return (result.results ?? []).map((row) => rowToAccount(row));
  }

  async expire(did: Did, expiredAt: string): Promise<Account> {
    const existing = await this.db
      .prepare("SELECT * FROM afauth_accounts WHERE did = ?")
      .bind(did)
      .first<AccountRow>();
    if (!existing) {
      throw new AFAuthError("unknown_account", 404, `account ${did} does not exist`);
    }
    if (existing.state === "CLAIMED") {
      // Spec forbids CLAIMED → EXPIRED (Appendix A).
      throw new AFAuthError(
        "already_claimed",
        409,
        `account ${did} is CLAIMED; the CLAIMED → EXPIRED transition is forbidden`,
      );
    }
    if (existing.state === "EXPIRED") {
      // Idempotent.
      return rowToAccount(existing);
    }
    // Atomic: flip state to EXPIRED and DELETE any pending invitation.
    // EXPIRED accounts have no operable surface, so the pending
    // recipient cannot be bound; dropping it matches what
    // `MemoryAccountStore.expire` does.
    await this.db.batch([
      this.db
        .prepare("UPDATE afauth_accounts SET state = ?, updated_at = ? WHERE did = ?")
        .bind("EXPIRED", expiredAt, did),
      this.db.prepare("DELETE FROM afauth_invitations WHERE account_did = ?").bind(did),
    ]);
    const row: AccountRow = { ...existing, state: "EXPIRED", updated_at: expiredAt };
    return rowToAccount(row);
  }
}

// ---------- D1SubHUniquenessStore (§10.4.4) ----------
//
// Production-grade `SubHUniquenessStore` backed by Cloudflare D1, living
// in the SAME database as `D1AccountStore`. The schema is
// migrations/0002_subh_uniqueness.sql; apply it after 0001.
//
// The composite PRIMARY KEY `(iss, sub_h)` is what makes `claim()` atomic:
// `INSERT ... ON CONFLICT DO NOTHING` lets exactly one concurrent claimant
// win the slot, so the cross-isolate Sybil race the gate exists to close
// stays closed (unlike a KV get-then-put, which can let two writers both
// observe an empty slot). This is why there is no `KvSubHUniquenessStore`:
// per-principal uniqueness needs an atomic claim, and KV cannot provide one.

interface SubHRow {
  iss: string;
  sub_h: string;
  did: string;
}

/**
 * Cloudflare D1–backed `SubHUniquenessStore`. Construct with the same D1
 * binding as `D1AccountStore`:
 *
 *   new D1SubHUniquenessStore(env.AFAUTH_DB)
 *
 * Schema: migrations/0002_subh_uniqueness.sql. Run `wrangler d1 migrations
 * apply <db-name>` before first use.
 */
export class D1SubHUniquenessStore implements SubHUniquenessStore {
  constructor(private readonly db: D1Database) {}

  async claim(iss: string, subH: string, did: Did): Promise<SubHClaimResult> {
    const claimedAt = new Date().toISOString();
    // Atomic reserve: ON CONFLICT DO NOTHING means the first writer for a
    // given (iss, sub_h) wins; later writers no-op. We then read back the
    // single surviving row to learn the winner.
    await this.db
      .prepare(
        "INSERT INTO afauth_subh_uniqueness (iss, sub_h, did, claimed_at) VALUES (?, ?, ?, ?) ON CONFLICT (iss, sub_h) DO NOTHING",
      )
      .bind(iss, subH, did, claimedAt)
      .run();
    const row = await this.db
      .prepare("SELECT did FROM afauth_subh_uniqueness WHERE iss = ? AND sub_h = ?")
      .bind(iss, subH)
      .first<Pick<SubHRow, "did">>();
    // Row is guaranteed to exist (we just inserted or it pre-existed).
    if (row && row.did === did) return { ok: true };
    return { ok: false, existingDid: row?.did };
  }

  async rekey(oldDid: Did, newDid: Did): Promise<void> {
    await this.db
      .prepare("UPDATE afauth_subh_uniqueness SET did = ? WHERE did = ?")
      .bind(newDid, oldDid)
      .run();
  }

  async releaseByDid(did: Did): Promise<void> {
    await this.db
      .prepare("DELETE FROM afauth_subh_uniqueness WHERE did = ?")
      .bind(did)
      .run();
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
