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
  type SignupResult,
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
// Production-grade `AccountStore` backed by Cloudflare D1 (managed SQLite),
// reworked for multi-agent accounts (§10.4.4): an account is keyed on an
// opaque `account_id` and groups every agent credential (device) of one
// human. Schema: migrations/0001_init.sql. The `(iss, sub_h)` UNIQUE index
// makes `signupAgent` atomic — concurrent first-signups of the same human
// converge on ONE account via `INSERT ... ON CONFLICT(iss, sub_h)`.
// Multi-statement ops use D1's `batch()` for transactional grouping.

interface AccountRow {
  account_id: string;
  iss: string | null;
  sub_h: string | null;
  state: AccountState;
  created_at: string;
  updated_at: string;
  owner_json: string | null;
  revoked: number;
}

interface AgentRow {
  agent_did: string;
  account_id: string;
  added_at: string;
  revoked: number;
}

interface InvitationRow {
  token: string;
  account_id: string;
  recipient_json: string;
  expires_at: string;
}

/** Generate an opaque, service-local account id (mirrors the server store). */
function generateAccountId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return "acct_" + btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function rowToAccount(row: AccountRow, agents: AgentRow[], pending?: Recipient): Account {
  const out: Account = {
    accountId: row.account_id,
    agents: agents.map((a) => ({
      did: a.agent_did,
      addedAt: a.added_at,
      ...(a.revoked ? { revoked: true } : {}),
    })),
    state: row.state,
    createdAt: row.created_at,
  };
  if (row.iss && row.sub_h) out.principal = { iss: row.iss, subH: row.sub_h };
  if (row.revoked) out.revoked = true;
  if (row.owner_json) out.owner = JSON.parse(row.owner_json) as Account["owner"];
  if (pending) out.pendingRecipient = pending;
  return out;
}

/**
 * Cloudflare D1–backed `AccountStore` (multi-agent model).
 *
 *   new D1AccountStore(env.AFAUTH_DB)
 *
 * Schema: migrations/0001_init.sql. Run `wrangler d1 migrations apply
 * <db-name>` before first use.
 */
export class D1AccountStore implements SweepableAccountStore {
  constructor(private readonly db: D1Database) {}

  private async loadAgents(accountId: string): Promise<AgentRow[]> {
    const r = await this.db
      .prepare("SELECT * FROM afauth_account_agents WHERE account_id = ? ORDER BY added_at ASC")
      .bind(accountId)
      .all<AgentRow>();
    return r.results ?? [];
  }

  private async loadPending(accountId: string): Promise<Recipient | undefined> {
    const invite = await this.db
      .prepare("SELECT * FROM afauth_invitations WHERE account_id = ?")
      .bind(accountId)
      .first<InvitationRow>();
    if (!invite) return undefined;
    if (new Date(invite.expires_at).getTime() < Date.now()) return undefined;
    return JSON.parse(invite.recipient_json) as Recipient;
  }

  async getById(accountId: string): Promise<Account | null> {
    const row = await this.db
      .prepare("SELECT * FROM afauth_accounts WHERE account_id = ?")
      .bind(accountId)
      .first<AccountRow>();
    if (!row) return null;
    return rowToAccount(row, await this.loadAgents(accountId), await this.loadPending(accountId));
  }

  async getByAgentDid(did: Did): Promise<Account | null> {
    const agent = await this.db
      .prepare("SELECT account_id FROM afauth_account_agents WHERE agent_did = ?")
      .bind(did)
      .first<{ account_id: string }>();
    if (!agent) return null;
    return this.getById(agent.account_id);
  }

  async findByPrincipal(iss: string, subH: string): Promise<Account | null> {
    const row = await this.db
      .prepare("SELECT * FROM afauth_accounts WHERE iss = ? AND sub_h = ?")
      .bind(iss, subH)
      .first<AccountRow>();
    if (!row) return null;
    return rowToAccount(
      row,
      await this.loadAgents(row.account_id),
      await this.loadPending(row.account_id),
    );
  }

  async findByPendingToken(token: string): Promise<Account | null> {
    const invite = await this.db
      .prepare("SELECT * FROM afauth_invitations WHERE token = ?")
      .bind(token)
      .first<InvitationRow>();
    if (!invite) return null;
    if (new Date(invite.expires_at).getTime() < Date.now()) {
      await this.db.prepare("DELETE FROM afauth_invitations WHERE token = ?").bind(token).run();
      return null;
    }
    return this.getById(invite.account_id);
  }

  async signupAgent(input: {
    did: Did;
    principal?: { iss: string; subH: string };
  }): Promise<SignupResult> {
    const { did, principal } = input;
    // Idempotent: an already-attached credential returns its account.
    const existing = await this.getByAgentDid(did);
    if (existing) return { account: existing, attached: false };

    const now = new Date().toISOString();
    if (principal) {
      const newId = generateAccountId();
      // Atomic grouping: only one account per (iss, sub_h) survives.
      await this.db
        .prepare(
          "INSERT INTO afauth_accounts (account_id, iss, sub_h, state, created_at, updated_at) VALUES (?, ?, ?, 'UNCLAIMED', ?, ?) ON CONFLICT (iss, sub_h) DO NOTHING",
        )
        .bind(newId, principal.iss, principal.subH, now, now)
        .run();
      const winner = await this.db
        .prepare("SELECT account_id FROM afauth_accounts WHERE iss = ? AND sub_h = ?")
        .bind(principal.iss, principal.subH)
        .first<{ account_id: string }>();
      const accountId = winner!.account_id;
      await this.db
        .prepare("INSERT INTO afauth_account_agents (agent_did, account_id, added_at) VALUES (?, ?, ?)")
        .bind(did, accountId, now)
        .run();
      return { account: (await this.getById(accountId))!, attached: accountId !== newId };
    }
    // No principal → singleton account.
    const accountId = generateAccountId();
    await this.db.batch([
      this.db
        .prepare("INSERT INTO afauth_accounts (account_id, state, created_at, updated_at) VALUES (?, 'UNCLAIMED', ?, ?)")
        .bind(accountId, now, now),
      this.db
        .prepare("INSERT INTO afauth_account_agents (agent_did, account_id, added_at) VALUES (?, ?, ?)")
        .bind(did, accountId, now),
    ]);
    return { account: (await this.getById(accountId))!, attached: false };
  }

  async attachAgent(accountId: string, did: Did, addedAt: string): Promise<Account> {
    const account = await this.getById(accountId);
    if (!account) throw new AFAuthError("unknown_account", 404, `account ${accountId} does not exist`);
    await this.db
      .prepare("INSERT OR IGNORE INTO afauth_account_agents (agent_did, account_id, added_at) VALUES (?, ?, ?)")
      .bind(did, accountId, addedAt)
      .run();
    return (await this.getById(accountId))!;
  }

  async revokeAgent(did: Did, _revokedAt: string): Promise<Account> {
    const account = await this.getByAgentDid(did);
    if (!account) throw new AFAuthError("unknown_account", 404, `no account for agent ${did}`);
    await this.db
      .prepare("UPDATE afauth_account_agents SET revoked = 1 WHERE agent_did = ?")
      .bind(did)
      .run();
    return (await this.getById(account.accountId))!;
  }

  async setPendingInvitation(
    accountId: string,
    recipient: Recipient,
    token: string,
    expiresAt: string,
  ): Promise<Account> {
    const account = await this.getById(accountId);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${accountId} does not exist`);
    }
    if (account.revoked) {
      throw new AFAuthError("revoked_key", 401, `account ${accountId} is revoked`);
    }
    if (account.state === "CLAIMED") {
      throw new AFAuthError("already_claimed", 409, `account ${accountId} is already claimed`);
    }
    const nowIso = new Date().toISOString();
    // §7.3 atomic supersession: DELETE prior + INSERT new + UPDATE state.
    await this.db.batch([
      this.db.prepare("DELETE FROM afauth_invitations WHERE account_id = ?").bind(accountId),
      this.db
        .prepare(
          "INSERT INTO afauth_invitations (token, account_id, recipient_json, expires_at) VALUES (?, ?, ?, ?)",
        )
        .bind(token, accountId, JSON.stringify(recipient), expiresAt),
      this.db
        .prepare("UPDATE afauth_accounts SET state = 'INVITED', updated_at = ? WHERE account_id = ?")
        .bind(nowIso, accountId),
    ]);
    return { ...account, state: "INVITED", pendingRecipient: recipient };
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
    const accountId = invite.account_id;
    const nowIso = new Date().toISOString();
    await this.db.batch([
      this.db
        .prepare("UPDATE afauth_accounts SET state = 'CLAIMED', owner_json = ?, updated_at = ? WHERE account_id = ?")
        .bind(JSON.stringify(owner), nowIso, accountId),
      this.db.prepare("DELETE FROM afauth_invitations WHERE token = ?").bind(token),
    ]);
    return this.getById(accountId);
  }

  async rotateAgent(oldDid: Did, newDid: Did, _rotatedAt: string): Promise<Account> {
    const agent = await this.db
      .prepare("SELECT account_id FROM afauth_account_agents WHERE agent_did = ?")
      .bind(oldDid)
      .first<{ account_id: string }>();
    if (!agent) {
      throw new AFAuthError("unknown_account", 404, `no account for agent ${oldDid}`);
    }
    // Swap the credential DID; account_id is stable across rotation.
    await this.db
      .prepare("UPDATE afauth_account_agents SET agent_did = ? WHERE agent_did = ?")
      .bind(newDid, oldDid)
      .run();
    return (await this.getById(agent.account_id))!;
  }

  async revoke(accountId: string, revokedAt: string): Promise<Account> {
    const existing = await this.getById(accountId);
    if (!existing) {
      throw new AFAuthError("unknown_account", 404, `account ${accountId} does not exist`);
    }
    await this.db
      .prepare("UPDATE afauth_accounts SET revoked = 1, updated_at = ? WHERE account_id = ?")
      .bind(revokedAt, accountId)
      .run();
    return { ...existing, revoked: true };
  }

  async reKey(oldDid: Did, newDid: Did, reKeyedAt: string): Promise<Account> {
    const agent = await this.db
      .prepare("SELECT account_id FROM afauth_account_agents WHERE agent_did = ?")
      .bind(oldDid)
      .first<{ account_id: string }>();
    if (!agent) {
      throw new AFAuthError("unknown_account", 404, `no account for agent ${oldDid}`);
    }
    // One batch (one transaction): swap credential DID + clear the per-agent
    // and whole-account revoked flags. The atomic clear is the resume step.
    await this.db.batch([
      this.db
        .prepare("UPDATE afauth_account_agents SET agent_did = ?, revoked = 0 WHERE agent_did = ?")
        .bind(newDid, oldDid),
      this.db
        .prepare("UPDATE afauth_accounts SET revoked = 0, updated_at = ? WHERE account_id = ?")
        .bind(reKeyedAt, agent.account_id),
    ]);
    return (await this.getById(agent.account_id))!;
  }

  async listOpenAccounts(): Promise<Account[]> {
    const result = await this.db
      .prepare(
        "SELECT * FROM afauth_accounts WHERE state IN ('UNCLAIMED', 'INVITED') ORDER BY created_at ASC",
      )
      .all<AccountRow>();
    const rows = result.results ?? [];
    const out: Account[] = [];
    for (const row of rows) {
      out.push(rowToAccount(row, await this.loadAgents(row.account_id)));
    }
    return out;
  }

  async expire(accountId: string, expiredAt: string): Promise<Account> {
    const existing = await this.db
      .prepare("SELECT * FROM afauth_accounts WHERE account_id = ?")
      .bind(accountId)
      .first<AccountRow>();
    if (!existing) {
      throw new AFAuthError("unknown_account", 404, `account ${accountId} does not exist`);
    }
    if (existing.state === "CLAIMED") {
      throw new AFAuthError(
        "already_claimed",
        409,
        `account ${accountId} is CLAIMED; the CLAIMED → EXPIRED transition is forbidden`,
      );
    }
    if (existing.state === "EXPIRED") {
      return rowToAccount(existing, await this.loadAgents(accountId)); // idempotent
    }
    await this.db.batch([
      this.db
        .prepare("UPDATE afauth_accounts SET state = 'EXPIRED', updated_at = ? WHERE account_id = ?")
        .bind(expiredAt, accountId),
      this.db.prepare("DELETE FROM afauth_invitations WHERE account_id = ?").bind(accountId),
    ]);
    const row: AccountRow = { ...existing, state: "EXPIRED", updated_at: expiredAt };
    return rowToAccount(row, await this.loadAgents(accountId));
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
