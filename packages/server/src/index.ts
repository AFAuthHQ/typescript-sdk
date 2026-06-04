/**
 * @afauthhq/server — Server SDK for the AFAuth Protocol.
 *
 * Provides:
 *   - `Verifier`: standalone request verification per §5.5 + §5.6.
 *     Useful as an edge plugin (Appendix E) or as the front half of
 *     a full `Server`.
 *   - `Server`: full per-endpoint handlers for discovery, owner
 *     invitation, claim completion, key rotation, and account
 *     introspection.
 *   - `NonceStore`, `MemoryNonceStore`: replay protection per §5.6.
 *   - `AccountStore`: storage contract with named atomic operations
 *     per ADR-0004.
 *   - `RecipientHandler`: per-type ceremony hook for §7.7.
 *
 * `Server.handleClaimCompletion` takes an explicit `session` parameter
 * — the human-auth asymmetry is part of the API surface, not a
 * configuration concern. See ADR-0004.
 *
 * Endpoint handler bodies throw `not_implemented` in M1; they land in
 * M2 and M3.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTVerifyResult,
} from "jose";
import {
  AFAuthError,
  buildCanonicalInput,
  decodeDidKey,
  deriveInvitationId,
  DidKeyResolver,
  normaliseRecipient,
  sha256ContentDigest,
  type CoveredComponent,
  type Did,
  type DidResolver,
  type DiscoveryDocument,
  type Ed25519PublicKey,
  type Recipient,
  type SignatureParams,
} from "@afauthhq/core";

// Re-export DiscoveryDocument so server consumers don't need to also
// import from @afauthhq/core for this type.
export type { DiscoveryDocument };

// ---------- Nonce store (§5.6) ----------

export interface NonceStore {
  /**
   * Inserts (keyid, nonce). Returns `true` if it was new, `false` if a
   * replay. Implementations MUST enforce a TTL ≥ `(expires - created) +
   * clockSkew`.
   */
  seen(keyid: Did, nonce: string, ttlSeconds: number): Promise<boolean>;
}

/**
 * Single-process Map-backed nonce store. Suitable for tests and small
 * single-process deployments.
 *
 * Lazily garbage-collects expired entries on every Nth insert
 * (default N = 256) so the map can't grow unbounded in long-running
 * processes. The sweep is O(size) but amortises to O(1) per insert.
 * Production deployments that need durability across process
 * restarts should use a KV-backed `NonceStore` (e.g.
 * `@afauthhq/worker`'s `KvNonceStore`).
 */
export class MemoryNonceStore implements NonceStore {
  private readonly seenSet = new Map<string, number>();
  private inserts = 0;
  private readonly gcEvery: number;

  constructor(opts: { gcEvery?: number } = {}) {
    this.gcEvery = opts.gcEvery ?? 256;
  }

  async seen(keyid: Did, nonce: string, ttlSeconds: number): Promise<boolean> {
    const key = `${keyid}\x00${nonce}`;
    const now = Math.floor(Date.now() / 1000);
    const existingExpiry = this.seenSet.get(key);
    if (existingExpiry !== undefined && existingExpiry > now) return false;
    this.seenSet.set(key, now + ttlSeconds);
    this.inserts++;
    if (this.inserts % this.gcEvery === 0) this.sweep(now);
    return true;
  }

  /** Number of currently-tracked entries (post any sweep). */
  size(): number {
    return this.seenSet.size;
  }

  private sweep(now: number): void {
    for (const [k, expiry] of this.seenSet) {
      if (expiry <= now) this.seenSet.delete(k);
    }
  }
}

// ---------- Account store (§6) ----------

export type AccountState = "UNCLAIMED" | "INVITED" | "CLAIMED" | "EXPIRED";

/**
 * A single agent credential (a `did:key` — one "device") attached to an
 * account. A human's PC and phone agents are two `AccountAgent`s on the
 * same `Account` (§10.4.4): same human, same account, many devices.
 */
export interface AccountAgent {
  did: Did;
  /** ISO-8601 timestamp this credential was attached (§6.4). */
  addedAt: string;
  /** Set once this specific credential is revoked (§8.4); the account survives. */
  revoked?: boolean;
}

export interface Account {
  /**
   * Opaque, service-local, stable identifier for the account — NOT a DID.
   * One account groups every agent credential of a single human (§10.4.4),
   * so the account identity is decoupled from any one verification key.
   */
  accountId: string;
  /**
   * Per-service human pseudonym this account is grouped under, present iff
   * the account was created from an attested binding (§10.4). Absent for
   * singleton accounts (attestation `off`/`optional`, or a runtime-only
   * attestation that carries no `sub_h`). The `(iss, subH)` pair is the
   * grouping key — a second agent presenting the same pair joins THIS
   * account rather than creating a new one.
   */
  principal?: { iss: string; subH: string };
  /** Attached agent credentials (devices). At least one while the account is live. */
  agents: AccountAgent[];
  state: AccountState;
  /** ISO-8601 timestamp the account was first materialised (§6.4/§6.5). */
  createdAt: string;
  pendingRecipient?: Recipient;
  /** Owner binding (§7) — bound once, shared by every device on the account. */
  owner?: { identity: Recipient; userId: string; claimedAt: string };
  /** Whole-account revoke (§8.4) — distinct from a single credential's `AccountAgent.revoked`. */
  revoked?: boolean;
}

/** Result of `AccountStore.signupAgent`. */
export interface SignupResult {
  account: Account;
  /**
   * `true` if `did` attached to an account that already existed (a second
   * device of a known human); `false` if this call created the account.
   */
  attached: boolean;
}

/**
 * Storage contract for AFAuth accounts. See ADR-0004.
 *
 * Accounts are keyed on an opaque `accountId` and resolved from a request
 * via `getByAgentDid` (the signature's `keyid` authenticates a credential,
 * which resolves to its account). Multiple agent DIDs may attach to one
 * account; `signupAgent` groups them by the `(iss, sub_h)` principal.
 */
export interface AccountStore {
  // ----- Reads -----
  /** Resolve the account that `did` is a credential of, or null. */
  getByAgentDid(did: Did): Promise<Account | null>;
  /** Fetch by opaque account id, or null. */
  getById(accountId: string): Promise<Account | null>;
  /** Find the account grouped under `(iss, subH)`, or null (the §10.4.4 grouping key). */
  findByPrincipal(iss: string, subH: string): Promise<Account | null>;

  /**
   * Read-only lookup by pending invitation token. Returns the account
   * iff the token is currently associated with a pending invitation
   * that has not yet expired. Returns null otherwise. Used by
   * Server.handleClaimCompletion to inspect pendingRecipient and apply
   * the §7.7 match relation before the atomic commit.
   */
  findByPendingToken(token: string): Promise<Account | null>;

  // ----- Atomic mutations -----
  /**
   * Find-or-create + attach `did`, atomically on the `(iss, subH)` key:
   *   - `principal` given and an account exists for it → attach `did`
   *     (a new device of a known human) and return `{ attached: true }`.
   *   - otherwise → create a new UNCLAIMED account (carrying `principal`
   *     if given) with `did` as its first credential, `{ attached: false }`.
   * Idempotent: re-signing-up an already-attached `did` is a no-op.
   */
  signupAgent(input: {
    did: Did;
    principal?: { iss: string; subH: string };
  }): Promise<SignupResult>;
  /** Attach another credential (device) to an existing account. Idempotent on `did`. */
  attachAgent(accountId: string, did: Did, addedAt: string): Promise<Account>;
  /** Revoke a single credential (§8.4 per-device); the account survives if others remain. */
  revokeAgent(did: Did, revokedAt: string): Promise<Account>;

  setPendingInvitation(
    accountId: string,
    recipient: Recipient,
    token: string,
    expiresAt: string,
  ): Promise<Account>;
  completeClaimByToken(
    token: string,
    owner: NonNullable<Account["owner"]>,
  ): Promise<Account | null>;
  /**
   * §8.1 rotation: swap credential `oldDid` for `newDid` within its account.
   * The `accountId` is STABLE across rotation (the account is no longer the
   * DID), which is the key simplification of the multi-agent model.
   */
  rotateAgent(oldDid: Did, newDid: Did, rotatedAt: string): Promise<Account>;
  /** Whole-account revoke (§8.4). */
  revoke(accountId: string, revokedAt: string): Promise<Account>;
  /**
   * Owner-initiated re-key resume (§8.2): atomically swap credential
   * `oldDid` for `newDid` AND clear the account `revoked` flag, in a single
   * write / transaction. The resume half of revoke → re-key — a revoked
   * CLAIMED account comes back under a fresh key. Doing the clear in the
   * SAME atomic step as the swap is the whole point: a `rotateAgent`
   * followed by a separate clear would, on a crash/interleave (notably on
   * D1, where each is its own transaction), leave the new DID live but
   * still flagged revoked. `accountId` is stable; throws `unknown_account`
   * if `oldDid` is absent. The caller guards against a `newDid` that
   * already names a credential.
   */
  reKey(oldDid: Did, newDid: Did, reKeyedAt: string): Promise<Account>;
}

/**
 * Optional extension of `AccountStore` for stores that can enumerate
 * un-terminal accounts (UNCLAIMED + INVITED) and atomically transition
 * them to EXPIRED.
 *
 * Required by `sweepExpiredAccounts`; not required by the rest of the
 * SDK. Backends that cannot list (opaque KV with no index) skip
 * implementing this and run TTL enforcement via storage-layer
 * mechanisms instead — KV `expirationTtl` on each row, for example.
 *
 * Both built-in stores implement this:
 *   - `MemoryAccountStore` (this package)
 *   - `D1AccountStore` (`@afauthhq/worker`)
 */
export interface SweepableAccountStore extends AccountStore {
  /**
   * List every account in `UNCLAIMED` or `INVITED` state. The sweep
   * helper calls this to find candidates for the EXPIRED transition.
   *
   * Implementations MAY paginate internally; the return value is the
   * full set. Production deployments with very large numbers of open
   * accounts should batch by `createdAt` to keep this bounded — see
   * the `D1AccountStore` implementation as a reference.
   */
  listOpenAccounts(): Promise<Account[]>;

  /**
   * Transition the account (by `accountId`) to `EXPIRED`. Idempotent —
   * calling on an already-EXPIRED account is a no-op. Calling on a CLAIMED
   * or unknown account throws (the spec forbids CLAIMED → EXPIRED).
   */
  expire(accountId: string, expiredAt: string): Promise<Account>;
}

/** Generate an opaque, service-local account id (`acct_<22-char base64url>`). */
function generateAccountId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return "acct_" + btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function principalKey(iss: string, subH: string): string {
  return `${iss}\x00${subH}`;
}

/**
 * Single-process in-memory implementation of `AccountStore`. Suitable
 * for tests and small examples; production deployments should use a
 * durable backend (e.g. a KV-backed implementation).
 */
export class MemoryAccountStore implements SweepableAccountStore {
  private readonly accounts = new Map<string, Account>(); // accountId → Account
  private readonly agentToAccount = new Map<Did, string>(); // credential did → accountId
  private readonly principalToAccount = new Map<string, string>(); // (iss\x00subH) → accountId
  private readonly tokens = new Map<string, { accountId: string; expiresAt: string }>();
  /** Reverse index: accountId → its current pending-invitation token, if any (§7.3 O(1)). */
  private readonly accountToToken = new Map<string, string>();

  async getByAgentDid(did: Did): Promise<Account | null> {
    const accountId = this.agentToAccount.get(did);
    if (accountId === undefined) return null;
    const a = this.accounts.get(accountId);
    return a ?? null;
  }

  async getById(accountId: string): Promise<Account | null> {
    const a = this.accounts.get(accountId);
    return a ?? null;
  }

  async findByPrincipal(iss: string, subH: string): Promise<Account | null> {
    const accountId = this.principalToAccount.get(principalKey(iss, subH));
    if (accountId === undefined) return null;
    const a = this.accounts.get(accountId);
    return a ?? null;
  }

  async findByPendingToken(token: string): Promise<Account | null> {
    const entry = this.tokens.get(token);
    if (!entry) return null;
    if (new Date(entry.expiresAt).getTime() < Date.now()) {
      this.tokens.delete(token);
      return null;
    }
    const a = this.accounts.get(entry.accountId);
    return a ?? null;
  }

  async signupAgent(input: {
    did: Did;
    principal?: { iss: string; subH: string };
  }): Promise<SignupResult> {
    const { did, principal } = input;
    // Idempotent: a credential already attached returns its account.
    const known = this.agentToAccount.get(did);
    if (known !== undefined) {
      return { account: this.accounts.get(known)!, attached: false };
    }
    // Group by principal when present.
    if (principal) {
      const pk = principalKey(principal.iss, principal.subH);
      const existingId = this.principalToAccount.get(pk);
      if (existingId !== undefined) {
        const account = this.accounts.get(existingId)!;
        account.agents.push({ did, addedAt: new Date().toISOString() });
        this.agentToAccount.set(did, existingId);
        return { account, attached: true };
      }
    }
    // Create a fresh account with `did` as its first credential.
    const account: Account = {
      accountId: generateAccountId(),
      ...(principal ? { principal } : {}),
      agents: [{ did, addedAt: new Date().toISOString() }],
      state: "UNCLAIMED",
      createdAt: new Date().toISOString(),
    };
    this.accounts.set(account.accountId, account);
    this.agentToAccount.set(did, account.accountId);
    if (principal) {
      this.principalToAccount.set(principalKey(principal.iss, principal.subH), account.accountId);
    }
    return { account, attached: false };
  }

  async attachAgent(accountId: string, did: Did, addedAt: string): Promise<Account> {
    const account = this.accounts.get(accountId);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${accountId} does not exist`);
    }
    if (!account.agents.some((a) => a.did === did)) {
      account.agents.push({ did, addedAt });
      this.agentToAccount.set(did, accountId);
    }
    return { ...account, agents: [...account.agents] };
  }

  async revokeAgent(did: Did, _revokedAt: string): Promise<Account> {
    const accountId = this.agentToAccount.get(did);
    if (accountId === undefined) {
      throw new AFAuthError("unknown_account", 404, `no account for agent ${did}`);
    }
    const account = this.accounts.get(accountId)!;
    const agent = account.agents.find((a) => a.did === did);
    if (agent) agent.revoked = true;
    return { ...account, agents: [...account.agents] };
  }

  async setPendingInvitation(
    accountId: string,
    recipient: Recipient,
    token: string,
    expiresAt: string,
  ): Promise<Account> {
    const account = this.accounts.get(accountId);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${accountId} does not exist`);
    }
    if (account.revoked) {
      throw new AFAuthError("revoked_key", 401, `account ${accountId} is revoked`);
    }
    if (account.state === "CLAIMED") {
      throw new AFAuthError("already_claimed", 409, `account ${accountId} is already claimed`);
    }

    // §7.3 atomic replacement: invalidate any prior pending invitation for
    // this account before installing the new one. O(1) via reverse index.
    const existing = this.accountToToken.get(accountId);
    if (existing !== undefined) this.tokens.delete(existing);

    this.tokens.set(token, { accountId, expiresAt });
    this.accountToToken.set(accountId, token);
    account.state = "INVITED";
    account.pendingRecipient = recipient;
    return { ...account, agents: [...account.agents] };
  }

  async completeClaimByToken(
    token: string,
    owner: NonNullable<Account["owner"]>,
  ): Promise<Account | null> {
    const entry = this.tokens.get(token);
    if (!entry) return null;
    if (new Date(entry.expiresAt).getTime() < Date.now()) {
      this.tokens.delete(token);
      return null;
    }
    const account = this.accounts.get(entry.accountId);
    if (!account) return null;

    account.state = "CLAIMED";
    account.owner = owner;
    delete account.pendingRecipient;
    this.tokens.delete(token);
    this.accountToToken.delete(entry.accountId);
    return { ...account, agents: [...account.agents] };
  }

  async rotateAgent(oldDid: Did, newDid: Did, _rotatedAt: string): Promise<Account> {
    const accountId = this.agentToAccount.get(oldDid);
    if (accountId === undefined) {
      throw new AFAuthError("unknown_account", 404, `no account for agent ${oldDid}`);
    }
    const account = this.accounts.get(accountId)!;
    const agent = account.agents.find((a) => a.did === oldDid);
    if (agent) agent.did = newDid;
    this.agentToAccount.delete(oldDid);
    this.agentToAccount.set(newDid, accountId);
    return { ...account, agents: [...account.agents] };
  }

  async revoke(accountId: string, _revokedAt: string): Promise<Account> {
    const account = this.accounts.get(accountId);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${accountId} does not exist`);
    }
    account.revoked = true;
    return { ...account, agents: [...account.agents] };
  }

  async reKey(oldDid: Did, newDid: Did, _reKeyedAt: string): Promise<Account> {
    const accountId = this.agentToAccount.get(oldDid);
    if (accountId === undefined) {
      throw new AFAuthError("unknown_account", 404, `no account for agent ${oldDid}`);
    }
    const account = this.accounts.get(accountId)!;
    const agent = account.agents.find((a) => a.did === oldDid);
    if (agent) {
      agent.did = newDid;
      delete agent.revoked;
    }
    // Clear the whole-account revoke too — this is the resume step.
    delete account.revoked;
    this.agentToAccount.delete(oldDid);
    this.agentToAccount.set(newDid, accountId);
    return { ...account, agents: [...account.agents] };
  }

  async listOpenAccounts(): Promise<Account[]> {
    const out: Account[] = [];
    for (const account of this.accounts.values()) {
      if (account.state === "UNCLAIMED" || account.state === "INVITED") {
        out.push({ ...account, agents: [...account.agents] });
      }
    }
    return out;
  }

  async expire(accountId: string, _expiredAt: string): Promise<Account> {
    const account = this.accounts.get(accountId);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${accountId} does not exist`);
    }
    if (account.state === "CLAIMED") {
      throw new AFAuthError(
        "already_claimed",
        409,
        `account ${accountId} is CLAIMED; the CLAIMED → EXPIRED transition is forbidden`,
      );
    }
    if (account.state === "EXPIRED") {
      return { ...account, agents: [...account.agents] }; // idempotent
    }
    account.state = "EXPIRED";
    // Drop the pending invitation (if any) — EXPIRED accounts have no
    // operable surface, and the pending recipient is no longer bindable.
    if (account.pendingRecipient) delete account.pendingRecipient;
    const tok = this.accountToToken.get(accountId);
    if (tok !== undefined) {
      this.tokens.delete(tok);
      this.accountToToken.delete(accountId);
    }
    return { ...account, agents: [...account.agents] };
  }
}

// ---------- TTL sweep (§6.1 / Appendix A) ----------

export interface SweepOptions {
  /**
   * Service's `unclaimed_ttl_seconds` from §4.4 — the maximum age
   * before an UNCLAIMED or INVITED account transitions to EXPIRED.
   * OMIT for no expiry: the default and recommended posture, under which
   * unclaimed accounts operate indefinitely and this sweep is a no-op.
   * Set it only to garbage-collect abandoned accounts or to meet a
   * data-retention mandate; if set, it MUST be a positive number.
   */
  unclaimedTtlSeconds?: number;
  /**
   * Function returning the current `Date`. Overridable for tests.
   * Defaults to `() => new Date()`.
   */
  now?: () => Date;
}

export interface SweepResult {
  /** Account ids transitioned to EXPIRED in this run. */
  expired: string[];
  /** Total accounts considered (UNCLAIMED + INVITED). */
  scanned: number;
}

/**
 * Periodic sweep that transitions UNCLAIMED / INVITED accounts to
 * `EXPIRED` once they exceed `unclaimedTtlSeconds` from their
 * `createdAt`. Expiry is opt-in (§4.4): when `unclaimedTtlSeconds` is
 * omitted — the default — unclaimed accounts never expire and this sweep
 * is a no-op that scans nothing. The SDK never runs it automatically;
 * *when* to sweep is service policy.
 *
 * USAGE
 *
 *   // Only services that opt into a TTL need this. Passing the discovery
 *   // value straight through is safe: undefined → no-op.
 *   const result = await sweepExpiredAccounts(accountStore, {
 *     unclaimedTtlSeconds: discovery.limits?.unclaimed_ttl_seconds,
 *   });
 *   console.log(`expired ${result.expired.length} of ${result.scanned}`);
 *
 * SCOPE
 *
 *   - Sweeps UNCLAIMED → EXPIRED and INVITED → EXPIRED (Appendix A),
 *     only when a TTL is configured.
 *   - Does NOT sweep INVITED → UNCLAIMED (the per-invitation TTL
 *     transition). That transition is purely cosmetic — the account
 *     remains operable, and the next owner-invitation atomically
 *     supersedes the stale pending recipient anyway (§7.3). Storage
 *     backends MAY drop the stale invitation row opportunistically on
 *     read; `D1AccountStore.findByPendingToken` does this.
 *   - CLAIMED accounts are never touched (Appendix A forbids
 *     CLAIMED → EXPIRED).
 *
 * The transition itself is delegated to `store.expire()`, which is
 * idempotent. A concurrent invocation of the sweep is safe: each `expire`
 * call is atomic at the storage layer, and the second invocation is a
 * no-op.
 */
export async function sweepExpiredAccounts(
  store: SweepableAccountStore,
  opts: SweepOptions = {},
): Promise<SweepResult> {
  // Expiry is opt-in (§4.4). With no TTL configured — the default — an
  // unclaimed account never expires, so the sweep scans nothing.
  if (opts.unclaimedTtlSeconds == null) {
    return { expired: [], scanned: 0 };
  }
  if (!Number.isFinite(opts.unclaimedTtlSeconds) || opts.unclaimedTtlSeconds <= 0) {
    throw new Error(
      `sweepExpiredAccounts: unclaimedTtlSeconds must be a positive number; got ${opts.unclaimedTtlSeconds}`,
    );
  }
  const now = opts.now ? opts.now() : new Date();
  const cutoffMs = now.getTime() - opts.unclaimedTtlSeconds * 1000;
  const expiredAt = now.toISOString();

  const candidates = await store.listOpenAccounts();
  const expired: string[] = [];

  for (const account of candidates) {
    const createdMs = Date.parse(account.createdAt);
    if (!Number.isFinite(createdMs)) continue;
    if (createdMs <= cutoffMs) {
      await store.expire(account.accountId, expiredAt);
      expired.push(account.accountId);
    }
  }

  return { expired, scanned: candidates.length };
}

// ---------- Recipient handlers (§7.7) ----------

export interface RecipientHandler<R extends Recipient = Recipient> {
  initiate(opts: {
    recipient: R;
    claimToken: string;
    claimPageUrl: string;
    redirectUrl?: string;
  }): Promise<void>;
  matches(opts: { pending: R; authenticated: R }): boolean;
}

/**
 * Reference `email` `RecipientHandler` for local development and
 * tests. `initiate` logs the magic link to `console.error` (stderr, so
 * it doesn't pollute stdout) with a recognisable prefix; `matches`
 * applies case-insensitive equality per §7.7.1.
 *
 * Production deployments substitute their own implementation that
 * sends a real email through a mail provider.
 */
export const consoleEmailHandler: RecipientHandler = {
  async initiate({ recipient, claimToken, claimPageUrl, redirectUrl }) {
    if (recipient.type !== "email") {
      throw new AFAuthError(
        "unsupported_recipient_type",
        400,
        `consoleEmailHandler received non-email recipient: ${recipient.type}`,
      );
    }
    const url = new URL(claimPageUrl);
    url.searchParams.set("token", claimToken);
    if (redirectUrl) url.searchParams.set("redirect_url", redirectUrl);
    // eslint-disable-next-line no-console
    console.error(`[afauth] magic link for ${recipient.value}: ${url.toString()}`);
  },
  matches({ pending, authenticated }) {
    if (pending.type !== "email" || authenticated.type !== "email") return false;
    // §7.7.1: case-insensitive equality after NFKC normalisation per
    // RFC 5321 §2.4. Normalise both sides so this handler works
    // correctly even if either input has not already been routed
    // through `normaliseRecipient`.
    const norm = (v: string) => v.normalize("NFKC").toLowerCase();
    return norm(pending.value) === norm(authenticated.value);
  },
};

// ---------- Header parsing (RFC 9421) ----------

function unquote(s: string): string {
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1);
  return s;
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

interface ParsedSignatureInput {
  label: string;
  covered: CoveredComponent[];
  params: SignatureParams;
}

/**
 * Parse one signature from the `Signature-Input` header.
 * Format: `<label>=(<components>);created=N;expires=N;nonce="…";keyid="…";alg="…"`
 *
 * v0.1 expects exactly one signature labelled `sig1` (the only label
 * the agent SDK emits). Multi-signature headers are not supported.
 */
function parseSignatureInput(header: string): ParsedSignatureInput {
  const match = /^(\w+)=\(([^)]*)\)\s*(?:;\s*(.*))?$/.exec(header.trim());
  if (!match) {
    throw new AFAuthError("invalid_signature", 401, "malformed Signature-Input header");
  }
  const [, label, componentsStr, paramsStr = ""] = match;

  const covered: CoveredComponent[] = [];
  for (const raw of componentsStr!.split(/\s+/).filter(Boolean)) {
    const c = unquote(raw);
    if (c === "@method" || c === "@target-uri" || c === "content-digest") {
      covered.push(c);
    } else {
      throw new AFAuthError(
        "invalid_signature",
        401,
        `unsupported covered component: ${c}`,
      );
    }
  }

  // §5.2 / §5.5 step 1: `@method` and `@target-uri` are REQUIRED covered
  // components ("Required when: Always"). The verifier MUST enforce their
  // presence rather than trust the signer to self-select which
  // security-critical inputs are bound. A signature that omits
  // `@target-uri` verifies against ANY URL, silently defeating the §12.2
  // cross-service replay binding for any under-covering signer (portable
  // DIDs are the §3.3/D.1 default). conformance.md requires rejecting
  // "missing components".
  for (const required of ["@method", "@target-uri"] as const) {
    if (!covered.includes(required)) {
      throw new AFAuthError(
        "invalid_signature",
        401,
        `missing required covered component: ${required} (§5.2)`,
      );
    }
  }

  const partial: Partial<SignatureParams> = {};
  for (const part of paramsStr.split(";").map((p) => p.trim()).filter(Boolean)) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const rawVal = part.slice(eq + 1).trim();
    if (key === "created" || key === "expires") {
      const n = Number(rawVal);
      if (!Number.isInteger(n)) {
        throw new AFAuthError("invalid_signature", 401, `${key} must be an integer`);
      }
      partial[key] = n;
    } else if (key === "nonce") {
      partial.nonce = unquote(rawVal);
    } else if (key === "keyid") {
      partial.keyid = unquote(rawVal);
    } else if (key === "alg") {
      const v = unquote(rawVal);
      if (v !== "ed25519") {
        throw new AFAuthError("invalid_signature", 401, `unsupported alg: ${v}`);
      }
      partial.alg = "ed25519";
    }
  }
  for (const k of ["created", "expires", "nonce", "keyid", "alg"] as const) {
    if (partial[k] === undefined) {
      throw new AFAuthError("invalid_signature", 401, `missing signature param: ${k}`);
    }
  }
  return { label: label!, covered, params: partial as SignatureParams };
}

/** Extract the signature bytes for `label` from a Signature header. */
function parseSignature(header: string, label: string): Uint8Array {
  // Signature: <label>=:<base64>:
  const re = new RegExp(`(?:^|,)\\s*${label}=:([A-Za-z0-9+/=]+):`);
  const m = re.exec(header);
  if (!m) {
    throw new AFAuthError(
      "invalid_signature",
      401,
      `Signature header missing label "${label}"`,
    );
  }
  return base64ToBytes(m[1]!);
}

// ---------- Revocation list (§8.3) ----------

export interface RevocationList {
  /** Returns true iff `did` has been revoked (via rotation or §8.4). */
  isRevoked(did: Did): Promise<boolean>;
  /** Atomically mark `did` as revoked with the given timestamp. */
  add(did: Did, revokedAt: string): Promise<void>;
}

/** In-memory `RevocationList`. Suitable for tests and small examples. */
export class MemoryRevocationList implements RevocationList {
  private readonly revoked = new Map<Did, string>();
  async isRevoked(did: Did): Promise<boolean> {
    return this.revoked.has(did);
  }
  async add(did: Did, revokedAt: string): Promise<void> {
    this.revoked.set(did, revokedAt);
  }
}

// ---------- Attestation (§10) ----------
//
// §10 defines `AFAuth-Attestation: <JWT>` as the wire surface for
// attestors. §9.2 makes attestation MANDATORY when the service
// advertises `billing.unclaimed_mode = "attested_only"`. The SDK
// ships two reference attestors:
//
//   - HmacAttestor — HS256 with a service-operator shared secret.
//   - JwksAttestor — generic asymmetric verification against the
//                    attestor's published JWKS endpoint (ES256, RS256,
//                    EdDSA supported via `jose`).
//
// MultiAttestor dispatches by JWT `iss` so a single service can
// accept tokens from multiple attestors.
//
// Named attestors (microsoft-entra-agent-id, stripe-projects, etc.)
// are vendor-specific configurations of JwksAttestor; they ship as
// satellite packages outside `@afauthhq/server` to keep core lean.

export interface AttestationClaims {
  /** §10.2: attestor identifier (e.g. "stripe-projects", "microsoft-entra-agent-id"). */
  iss: string;
  /** §10.2: requesting agent's account DID. */
  sub: string;
  /** §10.2: token expiry (unix seconds). */
  exp: number;
  /**
   * §10.4 pairwise human pseudonym. Present whenever the attestor
   * asserts a binding to a stable principal (the trust attestor
   * signals this by emitting `verification`). Opaque base64url
   * string, 22–86 chars; safe to use as a per-service uniqueness
   * key for the human behind the agent (§10.4.4). Services that
   * accept multiple attestors MUST scope this by `(iss, sub_h)`.
   */
  sub_h?: string;
  /** Attestor-specific extra claims (raw). */
  [key: string]: unknown;
}

export interface VerifyOptions {
  /**
   * If supplied, the JWT's `aud` claim MUST equal this value.
   * AFAP-0006 §10.3.1 makes audience binding mandatory for the
   * `afauth-trust` attestor ("A service MUST reject a token whose
   * `aud` does not match its own `service_did`"). Other attestors
   * with `aud` semantics should pass their `service_did` here.
   *
   * Omitted: no aud check (preserves pre-AFAP-0006 behavior).
   */
  audience?: string;
}

export interface Attestor {
  /**
   * Verifies an attestation JWT for `agentDid`. Returns the parsed
   * claims on success. Throws `AFAuthError("invalid_attestation", …)`
   * on signature/claim violation, including the case where the token's
   * `iss` is not one this attestor accepts (`MultiAttestor` and
   * single-issuer attestors both report unknown issuers as
   * `invalid_attestation` per §11.3 — there is no separate
   * `unsupported_attestor` code).
   */
  verify(jwt: string, agentDid: Did, opts?: VerifyOptions): Promise<AttestationClaims>;
}

interface BaseAttestorOpts {
  /** Attestor identifier — must match the JWT's `iss`. */
  iss: string;
  /** Function returning current unix-second time. Overridable for tests. */
  now?: () => number;
  /**
   * Optional hard ceiling on attestation lifetime (`exp - iat`), in
   * seconds. When set, the verifier requires `iat` to be present and
   * rejects any token whose `exp - iat` exceeds this value. The
   * afauth-trust attestor pins this to 900s per §10.3.1 so a long-lived
   * token from a compromised/misconfigured attestor key cannot outlive
   * the §10.7 revocation window. Generic attestors leave it unset
   * (§10.2 imposes no generic ceiling).
   */
  maxLifetimeSeconds?: number;
}

/**
 * Verifies HS256 attestation JWTs against a shared secret. Suitable
 * for first-party service-operator attestors per §10.3. The secret
 * MUST be at least 32 bytes; we do not enforce length here because
 * production deployments may bring their own validation.
 */
export class HmacAttestor implements Attestor {
  private readonly key: Uint8Array;
  readonly iss: string;
  private readonly now: () => number;
  private readonly maxLifetimeSeconds?: number;

  constructor(opts: BaseAttestorOpts & { secret: Uint8Array | string }) {
    this.iss = opts.iss;
    this.key = typeof opts.secret === "string" ? new TextEncoder().encode(opts.secret) : opts.secret;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.maxLifetimeSeconds = opts.maxLifetimeSeconds;
  }

  async verify(jwt: string, agentDid: Did, opts: VerifyOptions = {}): Promise<AttestationClaims> {
    let result: JWTVerifyResult;
    try {
      result = await jwtVerify(jwt, this.key, {
        algorithms: ["HS256"],
        issuer: this.iss,
        ...(opts.audience ? { audience: opts.audience } : {}),
        currentDate: new Date(this.now() * 1000),
      });
    } catch (err) {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        `HmacAttestor: ${(err as Error).message}`,
      );
    }
    return validateClaims(result.payload, this.iss, agentDid, opts.audience, this.maxLifetimeSeconds);
  }
}

/**
 * Verifies attestation JWTs signed by an asymmetric attestor whose
 * keys are published at a JWKS URL. Supports ES256, RS256, and EdDSA
 * via `jose`'s key resolver.
 *
 * The JWKS is cached internally by `jose`'s `createRemoteJWKSet` with
 * its default behaviour (caches valid keys; respects rotation).
 */
export class JwksAttestor implements Attestor {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  readonly iss: string;
  private readonly now: () => number;
  private readonly algorithms: readonly string[];
  private readonly maxLifetimeSeconds?: number;

  constructor(opts: BaseAttestorOpts & {
    /** URL of the attestor's JWKS document. MUST be https. */
    jwksUrl: string;
    /** Default: ["ES256", "RS256", "EdDSA"]. Constrain per attestor for tighter alg pinning. */
    algorithms?: readonly string[];
  }) {
    if (!opts.jwksUrl.startsWith("https://")) {
      throw new Error(`JwksAttestor: jwksUrl MUST be https; got ${opts.jwksUrl}`);
    }
    this.iss = opts.iss;
    this.jwks = createRemoteJWKSet(new URL(opts.jwksUrl));
    this.algorithms = opts.algorithms ?? ["ES256", "RS256", "EdDSA"];
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.maxLifetimeSeconds = opts.maxLifetimeSeconds;
  }

  async verify(jwt: string, agentDid: Did, opts: VerifyOptions = {}): Promise<AttestationClaims> {
    let result: JWTVerifyResult;
    try {
      result = await jwtVerify(jwt, this.jwks, {
        algorithms: this.algorithms as string[],
        issuer: this.iss,
        ...(opts.audience ? { audience: opts.audience } : {}),
        currentDate: new Date(this.now() * 1000),
      });
    } catch (err) {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        `JwksAttestor: ${(err as Error).message}`,
      );
    }
    return validateClaims(result.payload, this.iss, agentDid, opts.audience, this.maxLifetimeSeconds);
  }
}

// ---------- afauth-trust (AFAP-0006) -----------------------------
//
// `afauth-trust` is the v0.1 default attestor operated by afauth.org
// at trust.afauth.org. AFAP-0006 §10.3.1 pins:
//   - iss = "afauth-trust"
//   - JWKS published at https://trust.afauth.org/.well-known/jwks.json
//   - EdDSA-signed, exp - iat ≤ 900s
//   - audience-bound (aud = service_did)
//   - categorical `verification` claim ∈ {"email","oauth","payment"}
//
// `trustAttestor()` returns a JwksAttestor pre-configured against the
// AFAP-pinned identifier and URL. Drop into MultiAttestor alongside
// any service-operator HMAC or platform attestor you also accept:
//
//   const attestor = new MultiAttestor([
//     trustAttestor(),
//     new HmacAttestor({ iss: "my-service", secret: SHARED_SECRET }),
//   ]);

export const AFAUTH_TRUST_ISS = "afauth-trust" as const;
export const AFAUTH_TRUST_JWKS_URL =
  "https://trust.afauth.org/.well-known/jwks.json" as const;

export function trustAttestor(opts: {
  /** Override for staging / local dev. Defaults to the AFAP-pinned URL. */
  jwksUrl?: string;
  now?: () => number;
  /** Override the §10.3.1 lifetime cap (default 900s). */
  maxLifetimeSeconds?: number;
} = {}): JwksAttestor {
  return new JwksAttestor({
    iss: AFAUTH_TRUST_ISS,
    jwksUrl: opts.jwksUrl ?? AFAUTH_TRUST_JWKS_URL,
    algorithms: ["EdDSA"],
    maxLifetimeSeconds: opts.maxLifetimeSeconds ?? 900,
    now: opts.now,
  });
}

/**
 * Dispatches to per-issuer attestors. Construct one per service with
 * every accepted attestor pre-configured:
 *
 *   const multi = new MultiAttestor([
 *     new HmacAttestor({ iss: "my-service", secret: env.ATTESTATION_SECRET }),
 *     new JwksAttestor({ iss: "stripe-projects", jwksUrl: "https://.../jwks.json" }),
 *   ]);
 *
 * Unknown issuers throw `invalid_attestation` per §10.3.
 */
export class MultiAttestor implements Attestor {
  private readonly byIss: Map<string, Attestor>;

  constructor(attestors: ReadonlyArray<Attestor & { readonly iss: string }>) {
    this.byIss = new Map();
    for (const a of attestors) {
      if (!a.iss) {
        throw new Error("MultiAttestor: each attestor must carry an iss field");
      }
      this.byIss.set(a.iss, a);
    }
  }

  async verify(jwt: string, agentDid: Did, opts: VerifyOptions = {}): Promise<AttestationClaims> {
    // Peek at the iss claim without verifying the signature first.
    // jose's `decodeJwt` does this safely; we just split + base64 the
    // payload to avoid pulling another export in.
    const parts = jwt.split(".");
    if (parts.length !== 3) {
      throw new AFAuthError("invalid_attestation", 401, "JWT must have three parts");
    }
    let payload: { iss?: string };
    try {
      const decoded = atob(parts[1]!.replace(/-/g, "+").replace(/_/g, "/"));
      payload = JSON.parse(decoded) as { iss?: string };
    } catch {
      throw new AFAuthError("invalid_attestation", 401, "JWT payload is not valid base64url JSON");
    }
    if (typeof payload.iss !== "string") {
      throw new AFAuthError("invalid_attestation", 401, "JWT missing iss claim");
    }
    const attestor = this.byIss.get(payload.iss);
    if (!attestor) {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        `attestor ${payload.iss} not accepted by this service`,
      );
    }
    return attestor.verify(jwt, agentDid, opts);
  }
}

function validateClaims(
  payload: unknown,
  iss: string,
  agentDid: Did,
  audience?: string,
  maxLifetimeSeconds?: number,
): AttestationClaims {
  if (!payload || typeof payload !== "object") {
    throw new AFAuthError("invalid_attestation", 401, "JWT payload is not an object");
  }
  const p = payload as Record<string, unknown>;
  if (p.iss !== iss) {
    throw new AFAuthError("invalid_attestation", 401, `iss mismatch: want ${iss}, got ${String(p.iss)}`);
  }
  if (typeof p.sub !== "string") {
    throw new AFAuthError("invalid_attestation", 401, "JWT missing sub claim");
  }
  if (p.sub !== agentDid) {
    throw new AFAuthError(
      "invalid_attestation",
      401,
      `sub mismatch: token sub=${p.sub} does not match request agent ${agentDid}`,
    );
  }
  if (typeof p.exp !== "number") {
    throw new AFAuthError("invalid_attestation", 401, "JWT missing exp claim");
  }
  // §10.3.1 — when the attestor bounds its token lifetime (afauth-trust:
  // exp - iat ≤ 900s), `iat` MUST be present and `exp - iat` MUST NOT
  // exceed the cap. This stops a long-lived token from a compromised or
  // misconfigured attestor key from outliving the §10.7 attested-session
  // revocation window. Generic attestors leave the cap unset (§10.2).
  if (maxLifetimeSeconds !== undefined) {
    if (typeof p.iat !== "number") {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        "JWT missing iat claim (required when attestation lifetime is bounded, §10.3.1)",
      );
    }
    if (p.exp < p.iat) {
      throw new AFAuthError("invalid_attestation", 401, "attestation exp precedes iat");
    }
    if (p.exp - p.iat > maxLifetimeSeconds) {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        `attestation lifetime ${p.exp - p.iat}s exceeds maximum ${maxLifetimeSeconds}s (§10.3.1)`,
      );
    }
  }
  // Belt-and-suspenders: jose's jwtVerify already enforces audience
  // when supplied. We re-check here so the post-verify return value
  // can't drift if a future jose option lands that bypasses the lib's
  // check (and to give a stable error message shape).
  if (audience !== undefined) {
    const aud = p.aud;
    const audOk =
      aud === audience ||
      (Array.isArray(aud) && (aud as unknown[]).includes(audience));
    if (!audOk) {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        `aud mismatch: want ${audience}, got ${JSON.stringify(aud)}`,
      );
    }
  }

  // §10.4.1 — when the attestor asserts a binding to a stable
  // principal (signalled by the presence of `verification`), it MUST
  // include a well-formed `sub_h`. Reject the JWT otherwise so a
  // misbehaving attestor cannot silently strip the dedup signal.
  if (p.verification !== undefined && !isWellFormedSubH(p.sub_h)) {
    throw new AFAuthError(
      "invalid_attestation",
      401,
      "attestation carries `verification` but `sub_h` is missing or malformed (§10.4.1)",
    );
  }
  // If `sub_h` is present at all, it MUST satisfy §10.4.2 shape so
  // consumers can rely on it as an opaque base64url key.
  if (p.sub_h !== undefined && !isWellFormedSubH(p.sub_h)) {
    throw new AFAuthError(
      "invalid_attestation",
      401,
      "attestation `sub_h` is not a base64url string within [22,86] chars (§10.4.2)",
    );
  }

  return p as AttestationClaims;
}

// §10.4.2 — `sub_h` MUST be base64url with ≥128 bits of entropy
// (22 chars at the floor, 86 at the ceiling). The regex pins the
// alphabet (URL-safe, no padding) and length band; the entropy
// floor is the attestor's responsibility.
const SUB_H_RE = /^[A-Za-z0-9_-]{22,86}$/;
function isWellFormedSubH(v: unknown): v is string {
  return typeof v === "string" && SUB_H_RE.test(v);
}

// ---------- Attested sessions (§10.7) ----------
//
// §10.7 lets an `attested_only` service keep a currently-valid
// attestation ON FILE for an account and challenge with
// `attestation_required` once it lapses, instead of demanding a fresh
// attestation on every request (§10.6) or only at signup (the §8.5
// blind spot). The agent re-presents a freshly-minted attestation; the
// service verifies it offline and slides the freshness window forward.
// Revocation latency is bounded by the window: once the binding is
// revoked/disabled at the attestor the agent can no longer mint, so the
// session lapses within the window.
//
//   - strict   : window = the attestation's own `exp` (≤ the §10.2
//                ceiling). Never serves past a token's `exp`; introduces
//                no relaxation of §10.6.
//   - extended : window = `sessionTtlSeconds`, refreshed on each
//                presentation; MAY serve that long past the last `exp`.
//                Use only when strict mode's re-mint cadence is too
//                costly — it trades a longer revocation latency.

export type AttestedSessionMode = "strict" | "extended";

/**
 * Per-account record of how long an attested session stays fresh.
 * `attestedUntil` is a unix-SECONDS timestamp (matching attestation
 * `exp` and the Verifier clock). Mirrors `RevocationList`: an in-memory
 * default ships here; `@afauthhq/worker` provides a KV-backed impl.
 */
export interface AttestedFreshnessStore {
  /** The account's `attestedUntil` (unix seconds), or null if none on file. */
  get(did: Did): Promise<number | null>;
  /** Record/refresh the account's `attestedUntil` (unix seconds). */
  set(did: Did, attestedUntilSeconds: number): Promise<void>;
  /** Drop the account's session (e.g. on teardown). */
  clear(did: Did): Promise<void>;
}

/** In-memory `AttestedFreshnessStore`. Suitable for tests and single-process services. */
export class MemoryAttestedFreshnessStore implements AttestedFreshnessStore {
  private readonly until = new Map<Did, number>();
  async get(did: Did): Promise<number | null> {
    return this.until.get(did) ?? null;
  }
  async set(did: Did, attestedUntilSeconds: number): Promise<void> {
    this.until.set(did, attestedUntilSeconds);
  }
  async clear(did: Did): Promise<void> {
    this.until.delete(did);
  }
}

/**
 * Pure §10.7 window function: the `attestedUntil` (unix seconds) a
 * service records after verifying a freshly-presented attestation.
 *
 *   - strict   : the attestation's own `exp` (the attestor already
 *                rejected an already-expired token, so `exp > now`).
 *   - extended : `now + sessionTtlSeconds`, which MAY exceed `exp`.
 */
export function attestedUntilAfter(
  claims: { exp: number },
  mode: AttestedSessionMode,
  nowSeconds: number,
  sessionTtlSeconds?: number,
): number {
  if (mode === "extended") {
    if (!sessionTtlSeconds || sessionTtlSeconds <= 0) {
      throw new Error("attestedUntilAfter: extended mode requires a positive sessionTtlSeconds");
    }
    return nowSeconds + sessionTtlSeconds;
  }
  return claims.exp;
}

/** True iff a session recorded as `attestedUntil` (unix seconds) is still fresh at `nowSeconds`. */
export function isAttestationFresh(attestedUntil: number | null, nowSeconds: number): boolean {
  return attestedUntil !== null && nowSeconds < attestedUntil;
}

export interface AttestedSessionOptions {
  /** Verifies presented attestations (the same attestor the Server uses at signup). */
  attestor: Attestor;
  /** Where per-account `attestedUntil` lives. */
  store: AttestedFreshnessStore;
  /** This service's DID — pinned as the attestation `aud` (AFAP-0006 §10.3.1). */
  serviceDid: Did;
  /** Freshness mode. Default `"strict"`. */
  mode?: AttestedSessionMode;
  /** Window length for `"extended"` mode (seconds). Required when mode is extended. */
  sessionTtlSeconds?: number;
  /** Unix-seconds clock. Overridable for tests. */
  now?: () => number;
  /** Optional: surfaced in the challenge's `details.accepted_attestors`. */
  acceptedAttestors?: readonly string[];
}

/**
 * §10.7 attested-session gate. Call `check()` on each authenticated
 * BUSINESS request to an established `attested_only` account, after
 * signature verification:
 *
 *   - If an `AFAuth-Attestation` header is present, verify it
 *     (audience-pinned) and slide the freshness window forward. An
 *     already-expired token is rejected by the attestor as
 *     `invalid_attestation` (§10.2) — the window never extends a token
 *     past its own `exp`.
 *   - Then, if the account's session is not fresh, throw
 *     `401 attestation_required` so the agent re-mints and retries.
 *
 * The per-request signature (§5) remains the authenticator; this gate
 * is an additional liveness check, not a substitute for it.
 */
export class AttestedSessionGate {
  private readonly attestor: Attestor;
  private readonly store: AttestedFreshnessStore;
  private readonly serviceDid: Did;
  private readonly mode: AttestedSessionMode;
  private readonly sessionTtlSeconds?: number;
  private readonly now: () => number;
  private readonly acceptedAttestors?: readonly string[];

  constructor(opts: AttestedSessionOptions) {
    if (opts.mode === "extended" && !(opts.sessionTtlSeconds && opts.sessionTtlSeconds > 0)) {
      throw new Error("AttestedSessionGate: extended mode requires a positive sessionTtlSeconds");
    }
    this.attestor = opts.attestor;
    this.store = opts.store;
    this.serviceDid = opts.serviceDid;
    this.mode = opts.mode ?? "strict";
    this.sessionTtlSeconds = opts.sessionTtlSeconds;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.acceptedAttestors = opts.acceptedAttestors;
  }

  /** Process any presented attestation, then enforce freshness. Throws `401 attestation_required` when stale. */
  async check(req: { headers: Headers }, agentDid: Did): Promise<void> {
    const nowS = this.now();
    const header = req.headers.get("afauth-attestation");
    if (header) {
      // Throws `invalid_attestation` (401) on a bad/expired token (§10.2).
      const claims = await this.attestor.verify(header, agentDid, { audience: this.serviceDid });
      await this.store.set(agentDid, attestedUntilAfter(claims, this.mode, nowS, this.sessionTtlSeconds));
    }
    const attestedUntil = await this.store.get(agentDid);
    if (!isAttestationFresh(attestedUntil, nowS)) {
      throw new AFAuthError(
        "attestation_required",
        401,
        "attested session has lapsed; present a fresh AFAuth-Attestation (§10.7)",
        this.acceptedAttestors ? { accepted_attestors: this.acceptedAttestors } : undefined,
      );
    }
  }
}

// ---------- Rate limiter (§11.3 rate_limit_exceeded) ----------
//
// The protocol reserves `rate_limit_exceeded` (429) in §11.3 but takes
// no position on policy. The interface below is intentionally minimal
// — one `take(key, config)` returning a decision — so operators can
// plug in production rate limiters (Redis token bucket, Durable
// Object actor, Cloudflare Rate Limiting binding) without changing
// the Server's call sites.
//
// Two reference impls land in v0.1: `MemoryRateLimiter` (single-process,
// for tests + small examples) and `KvRateLimiter` in `@afauthhq/worker`
// (fixed-window counter backed by Workers KV; best-effort across
// isolates, sufficient for §11.3 enforcement).

export interface RateLimitConfig {
  /** Maximum events permitted per `windowSeconds`. */
  limit: number;
  /** Window length in seconds. */
  windowSeconds: number;
}

export interface RateLimitDecision {
  ok: boolean;
  /**
   * Seconds until the next slot becomes available. Populated when
   * `ok` is false; the value drives the `Retry-After` header on the
   * 429 response.
   */
  retryAfter?: number;
  /** Slots remaining in the current window. */
  remaining?: number;
  /** Unix-second when the current window resets. */
  resetAt?: number;
}

export interface RateLimiter {
  /**
   * Atomically consume one slot for `key` against `config`. Returns
   * `{ ok: true }` when consumed; `{ ok: false, retryAfter }` when
   * the limit has been hit.
   *
   * Implementations MAY over-count under racing isolates (fail-safe)
   * but MUST NOT under-count — skipping takes during a race breaks
   * the §11.3 contract.
   */
  take(key: string, config: RateLimitConfig): Promise<RateLimitDecision>;
}

/**
 * Single-process fixed-window rate limiter. Suitable for tests and
 * small single-instance deployments; horizontally-scaled deployments
 * need a shared backend (e.g. `KvRateLimiter` in `@afauthhq/worker`).
 */
export class MemoryRateLimiter implements RateLimiter {
  private readonly windows = new Map<string, { windowStart: number; count: number }>();
  private readonly now: () => number;

  constructor(opts: { now?: () => number } = {}) {
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async take(key: string, config: RateLimitConfig): Promise<RateLimitDecision> {
    const nowSec = this.now();
    let w = this.windows.get(key);
    if (!w || w.windowStart + config.windowSeconds <= nowSec) {
      w = { windowStart: nowSec, count: 0 };
      this.windows.set(key, w);
    }
    const resetAt = w.windowStart + config.windowSeconds;
    if (w.count >= config.limit) {
      return {
        ok: false,
        retryAfter: Math.max(1, resetAt - nowSec),
        remaining: 0,
        resetAt,
      };
    }
    w.count++;
    return { ok: true, remaining: config.limit - w.count, resetAt };
  }
}

/**
 * Per-route rate-limit configuration on `ServerOptions.rateLimits`.
 * Each route's key is the agent DID extracted from `keyid`. Routes
 * without a config skip rate limiting.
 */
export interface ServerRateLimits {
  /** §6.4 explicit signup (POST /accounts). Keyed by agent DID. */
  accounts?: RateLimitConfig;
  /** §6.5 account introspection (GET /accounts/me). Keyed by agent DID. */
  account_introspection?: RateLimitConfig;
  /** §7.2 owner invitation. Keyed by agent DID. */
  owner_invitation?: RateLimitConfig;
  /** §7.4 claim completion. Keyed by token (one shot per token). */
  claim_completion?: RateLimitConfig;
  /** §8.1 / §8.2 key rotation. Keyed by agent DID. */
  key_rotation?: RateLimitConfig;
  /**
   * §8.2 owner re-key + §8.4 owner revoke (the owner-gated key
   * endpoints). Keyed by owner `userId`, not agent DID — these are
   * owner-authenticated, not agent-signed.
   */
  owner_key_operation?: RateLimitConfig;
}

// ---------- Verifier (§5.5) ----------

export interface VerifierOptions {
  nonceStore: NonceStore;
  serviceDid: Did;
  /** Default: 5. */
  clockSkewSeconds?: number;
  /** Default: 300. Max allowed `expires - created`. */
  maxSignatureLifetimeSeconds?: number;
  /**
   * Optional. When supplied, the Verifier rejects requests signed by
   * a revoked DID with `401 revoked_key`. When omitted (e.g., in unit
   * tests), the Verifier skips the revocation check.
   */
  revocationList?: RevocationList;
  /**
   * Optional DID resolver. Defaults to a `did:key`-only resolver.
   * Agent account identifiers are `did:key` in v0.1; supply a custom
   * `DidResolver` only if you choose to accept additional agent DID
   * methods.
   */
  didResolver?: DidResolver;
  /**
   * Function returning the current unix epoch in seconds. Overridable
   * for tests; defaults to `Date.now() / 1000`.
   */
  now?: () => number;
}

export interface VerifiedRequest {
  agentDid: Did;
  method: string;
  url: string;
  body: string | Uint8Array | null;
}

let warnedAboutDefaultRevocationList = false;

export class Verifier {
  private readonly nonceStore: NonceStore;
  private readonly revocationList: RevocationList;
  private readonly clockSkew: number;
  private readonly maxLifetime: number;
  private readonly didResolver: DidResolver;
  private readonly now: () => number;

  constructor(opts: VerifierOptions) {
    this.nonceStore = opts.nonceStore;
    if (opts.revocationList) {
      this.revocationList = opts.revocationList;
    } else {
      // §8.3 requires services to maintain a local revocation list.
      // Default to an in-memory list so the Verifier always honours
      // revocation; warn once so production deployments without a
      // durable list don't silently rely on the in-process default.
      this.revocationList = new MemoryRevocationList();
      if (!warnedAboutDefaultRevocationList) {
        warnedAboutDefaultRevocationList = true;
        // eslint-disable-next-line no-console
        console.warn(
          "[afauth] No revocationList configured on Verifier/Server. Defaulting to MemoryRevocationList (process-local; lost on restart). Configure VerifierOptions.revocationList for production deployments.",
        );
      }
    }
    this.clockSkew = opts.clockSkewSeconds ?? 5;
    this.maxLifetime = opts.maxSignatureLifetimeSeconds ?? 300;
    // Agent account identifiers are did:key in v0.1; the default
    // resolver decodes the key from the DID with no I/O.
    this.didResolver = opts.didResolver ?? new DidKeyResolver();
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async verify(req: {
    method: string;
    url: string;
    headers: Headers;
    /**
     * Raw request body. Accept `Uint8Array` (preferred — RFC 9421 §2
     * defines `Content-Digest` over BYTES, so reading the body via
     * `req.arrayBuffer()` is byte-accurate even for non-UTF-8 payloads
     * like multipart, protobuf, or ZIP) or `string` (legacy ergonomic
     * for ASCII/JSON callers — encoded via TextEncoder before hashing).
     */
    body: string | Uint8Array | null;
  }): Promise<VerifiedRequest> {
    const sigInputHeader = req.headers.get("signature-input");
    const sigHeader = req.headers.get("signature");
    if (!sigInputHeader) {
      throw new AFAuthError("invalid_signature", 401, "missing Signature-Input header");
    }
    if (!sigHeader) {
      throw new AFAuthError("invalid_signature", 401, "missing Signature header");
    }

    const { label, covered, params } = parseSignatureInput(sigInputHeader);
    const signatureBytes = parseSignature(sigHeader, label);

    // Revocation check (§8.3). Done before signature verification so
    // revoked-key requests are rejected without burning Ed25519
    // verification cycles. Revocation status is not secret —
    // services may publish their lists per §8.3 — so the timing
    // signal is acceptable.
    if (await this.revocationList.isRevoked(params.keyid)) {
      throw new AFAuthError("revoked_key", 401, "account key has been revoked");
    }

    // Time bounds (§5.6).
    if (!Number.isInteger(params.created) || !Number.isInteger(params.expires)) {
      throw new AFAuthError("invalid_signature", 401, "created/expires must be integers");
    }
    if (params.expires <= params.created) {
      throw new AFAuthError("invalid_signature", 401, "expires must be > created");
    }
    if (params.expires - params.created > this.maxLifetime) {
      throw new AFAuthError(
        "invalid_signature",
        401,
        `signature lifetime exceeds maximum (${this.maxLifetime}s)`,
      );
    }
    const now = this.now();
    if (now < params.created - this.clockSkew) {
      throw new AFAuthError("invalid_signature", 401, "signature is future-dated");
    }
    if (now > params.expires + this.clockSkew) {
      throw new AFAuthError("expired_signature", 401, "signature has expired");
    }

    // §5.2 / §5.5 step 7: the request body MUST be cryptographically
    // bound to the signature. The verifier MUST NOT trust the signer to
    // self-select whether `content-digest` is covered (same rationale as
    // the @method/@target-uri presence check at parse time). Concretely:
    //   - a request WITH a body MUST cover `content-digest`; otherwise
    //     the body is unauthenticated and an on-path attacker can inject
    //     or rewrite it under an otherwise-valid signature (the covered
    //     LIST is bound via @signature-params, so the attacker can't add
    //     coverage — only exploit its absence);
    //   - a request WITHOUT a body MUST NOT carry a Content-Digest header
    //     nor cover `content-digest` ("Content-Digest ... MUST be omitted
    //     otherwise").
    const hasBody =
      req.body != null &&
      (typeof req.body === "string" ? req.body.length > 0 : req.body.byteLength > 0);
    const digestCovered = covered.includes("content-digest");
    const digestHeaderPresent = req.headers.get("content-digest") != null;
    if (hasBody && !digestCovered) {
      throw new AFAuthError(
        "invalid_signature",
        401,
        "request has a body but content-digest is not a covered component (§5.2)",
      );
    }
    if (!hasBody && (digestCovered || digestHeaderPresent)) {
      throw new AFAuthError(
        "invalid_signature",
        401,
        "Content-Digest must be absent when the request has no body (§5.5 step 7)",
      );
    }

    // Content digest (verified when covered; presence is enforced above).
    let contentDigest: string | undefined;
    if (digestCovered) {
      contentDigest = req.headers.get("content-digest") ?? undefined;
      if (!contentDigest) {
        throw new AFAuthError(
          "invalid_signature",
          401,
          "Content-Digest header missing but covered_components includes content-digest",
        );
      }
      const expected = sha256ContentDigest(req.body ?? "");
      if (contentDigest !== expected) {
        throw new AFAuthError(
          "invalid_signature",
          401,
          "Content-Digest does not match SHA-256 of body",
        );
      }
    }

    // Rebuild canonical input and verify Ed25519 signature.
    const canonicalInput = buildCanonicalInput(
      {
        method: req.method,
        targetUri: req.url,
        ...(contentDigest ? { contentDigest } : {}),
      },
      params,
      covered,
    );
    const publicKey = await this.didResolver.resolve(params.keyid);
    const sigValid = ed25519.verify(
      signatureBytes,
      new TextEncoder().encode(canonicalInput),
      publicKey,
    );
    if (!sigValid) {
      throw new AFAuthError("invalid_signature", 401, "Ed25519 signature did not verify");
    }

    // Nonce check — atomic insert-if-absent.
    const ttl = params.expires - params.created + this.clockSkew;
    const fresh = await this.nonceStore.seen(params.keyid, params.nonce, ttl);
    if (!fresh) {
      throw new AFAuthError("replayed_nonce", 401, "nonce has been seen before");
    }

    return {
      agentDid: params.keyid,
      method: req.method,
      url: req.url,
      body: req.body,
    };
  }
}

// ---------- Server (full endpoint handlers) ----------

export interface OwnerSession {
  authenticated: Recipient;
  userId: string;
  /**
   * ISO-8601 timestamp of the most recent authentication event this
   * session evidences.
   *
   * Required by `assertFreshOwnerSession` (§7.5 freshness floor for
   * post-claim owner-binding operations).
   *
   * NOT read by `handleClaimCompletion`: §7.5 applies post-claim
   * only, so the claim ceremony itself has no freshness requirement.
   * That's why the field is optional on the type — sessions used
   * solely for claim completion don't need it.
   *
   * Recommendation: populate this on every session your auth layer
   * issues. Any owner-binding route your service exposes (rotate
   * key, revoke key, change bound email, add recovery contact)
   * MUST call `assertFreshOwnerSession`, and that helper requires
   * this field.
   */
  authenticatedAt?: string;
}

/**
 * §7.5 freshness check for post-claim owner-binding operations.
 *
 * Throws `AFAuthError("owner_session_too_stale", 403, …)` if
 * `session.authenticatedAt` is missing or older than `maxAgeSeconds`
 * relative to `now`.
 *
 * WHERE TO CALL THIS
 *
 * Only from service-defined routes that perform §7.5 "owner-binding
 * operations" — operations that modify which credentials can
 * authenticate as the owner. The protocol's enumerated list:
 *
 *   - revoking the agent's key (§8.4)
 *   - changing the bound owner identity
 *   - enrolling additional authentication credentials
 *   - adding or modifying recovery contacts
 *   - linking federated identities
 *   - adding additional principals to the account
 *
 * The mapping from this category to your concrete service routes is
 * a service policy decision — `Verifier` cannot know which of your
 * routes are owner-binding, so this helper is yours to call.
 *
 * WHERE NOT TO CALL THIS
 *
 * NOT from inside `handleClaimCompletion`. §7.5 explicitly applies
 * post-claim only; the claim ceremony's freshness requirement is
 * the §7.4 match relation, which `handleClaimCompletion` already
 * enforces against `session.authenticated`. The SDK does not call
 * `assertFreshOwnerSession` automatically anywhere.
 *
 * NOT from agent-signed routes. The §7.5 freshness floor is about
 * the *human* re-proving recent authentication, not the agent
 * re-signing the request. An agent-signed request's freshness is
 * already covered by §5.6 (signature `expires` + nonce).
 *
 * §7.5 mandates 60–300s as the recommended window; the SDK does
 * not pin a default — pick the freshness your threat model warrants.
 *
 * Example:
 *
 *   // POST /me/revoke (service route — owner-authenticated, not agent-signed)
 *   const session = await myAuthLayer.extractOwnerSession(req);
 *   if (!session) throw new AFAuthError("owner_authentication_required", 401, "...");
 *   assertFreshOwnerSession(session, { maxAgeSeconds: 300 });
 *   await server.revoke(targetDid);
 */
export function assertFreshOwnerSession(
  session: OwnerSession,
  opts: { maxAgeSeconds: number; now?: () => number },
): void {
  if (!session.authenticatedAt) {
    throw new AFAuthError(
      "owner_session_too_stale",
      403,
      "owner session does not evidence an authentication event (authenticatedAt missing)",
    );
  }
  const authMs = Date.parse(session.authenticatedAt);
  if (!Number.isFinite(authMs)) {
    throw new AFAuthError(
      "owner_session_too_stale",
      403,
      "owner session authenticatedAt is not a valid ISO-8601 timestamp",
    );
  }
  const nowMs = (opts.now ? opts.now() : Math.floor(Date.now() / 1000)) * 1000;
  const ageSeconds = (nowMs - authMs) / 1000;
  if (ageSeconds > opts.maxAgeSeconds) {
    throw new AFAuthError(
      "owner_session_too_stale",
      403,
      `owner session is ${Math.floor(ageSeconds)}s old; freshness window is ${opts.maxAgeSeconds}s`,
    );
  }
}

// DiscoveryDocument is defined in @afauthhq/core (single source of truth)
// and re-exported at the top of this module.

export interface ServerOptions extends VerifierOptions {
  accounts: AccountStore;
  recipients: Partial<Record<"email" | "phone" | "oidc" | "did", RecipientHandler>>;
  discovery: DiscoveryDocument | (() => Promise<DiscoveryDocument>);
  baseUrl: string;
  /**
   * Allow-list of hosts that may appear in `redirect_url` on owner
   * invitation requests, per §7.2 ("Services MUST validate it against
   * an allow-list of service-controlled hosts and MUST NOT honour
   * redirects to hosts outside that list").
   *
   * - Undefined or `[]` → `redirect_url` is forbidden (any value
   *   produces 400 malformed_request). This is the safe default.
   * - Non-empty list → only URLs whose host matches an entry are
   *   passed through to the recipient handler.
   */
  redirectAllowList?: readonly string[];
  /**
   * Whether to permit implicit signup (§6.3) — creating an UNCLAIMED
   * account on the first authenticated operation. Default `true`.
   * When `false`, operations against an unknown account return
   * `404 unknown_account`, matching the spec's §11.3 use of that code
   * for "only when implicit signup is disabled".
   */
  implicitSignup?: boolean;
  /**
   * Optional rate limiter. When supplied alongside `rateLimits`, each
   * named route enforces its limit and returns `429 rate_limit_exceeded`
   * (§11.3) with `Retry-After` when the limit is hit.
   *
   * The limiter check fires AFTER signature verification so unauthenticated
   * traffic cannot burn budget, but BEFORE any account-state mutation
   * so over-limit calls don't pollute the §6 state machine.
   */
  rateLimiter?: RateLimiter;
  /**
   * Per-route limit configs. Routes without an entry skip the check.
   * The reference defaults (used if a config is supplied but no
   * windowSeconds/limit is provided) are 60/hour for owner-invitation,
   * 1000/hour for account introspection, 10/hour for explicit signup,
   * 60/hour for key rotation.
   */
  rateLimits?: ServerRateLimits;
  /**
   * §10: optional attestation verifier. When the discovery doc
   * declares `billing.unclaimed_mode = "attested_only"` (§9.2), the
   * Server REQUIRES this to be set — implicit signup paths reject
   * with `attestation_required` until a valid AFAuth-Attestation
   * header is presented.
   *
   * When the discovery mode is anything else, the attestor is consulted
   * only when an attestation header IS present (lax mode for upgrade
   * paths and audit logging).
   */
  attestor?: Attestor;
  /**
   * §7.5 freshness floor (seconds) for the owner-gated key endpoints
   * (`handleKeyReKey`, `handleKeyRevocation`). Default 300 — the top of
   * the §7.5 60–300s band. Lower it for higher-assurance services.
   */
  ownerSessionMaxAgeSeconds?: number;
  /**
   * §10.7: opt in to attested sessions. When set (and an `attestor` is
   * configured), `Server.verifyAttested()` gates business requests on a
   * currently-valid attestation — refreshing the window when the agent
   * re-presents one and challenging with `attestation_required` when it
   * lapses. Requires `attestor` (the same one used at signup).
   */
  attestedSession?: {
    store: AttestedFreshnessStore;
    /** Default `"strict"` (window = the attestation's own `exp`). */
    mode?: AttestedSessionMode;
    /** Window length for `"extended"` mode (seconds). */
    sessionTtlSeconds?: number;
  };
}

// Default invitation TTL: 24 hours (§7.3 says "service-defined";
// 24-72h is typical for consumer accounts).
const DEFAULT_INVITATION_TTL_SECONDS = 24 * 60 * 60;

function generateInvitationToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  // base64url, no padding
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function jsonResponse(body: unknown, status: number, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders },
  });
}

export class Server {
  private readonly verifier: Verifier;
  private readonly accounts: AccountStore;
  private readonly recipients: ServerOptions["recipients"];
  private readonly discovery: ServerOptions["discovery"];
  private readonly baseUrl: string;
  private readonly revocationList: RevocationList;
  private readonly invitationTtlSeconds: number;
  private readonly redirectAllowList: ReadonlySet<string>;
  private readonly implicitSignup: boolean;
  private readonly rateLimiter?: RateLimiter;
  private readonly rateLimits: ServerRateLimits;
  private readonly attestor?: Attestor;
  private readonly serviceDid: Did;
  private readonly ownerSessionMaxAgeSeconds: number;
  private readonly attestedGate?: AttestedSessionGate;

  constructor(opts: ServerOptions) {
    // Verifier already defaults a missing revocationList to
    // MemoryRevocationList (with a one-time warning); reuse the same
    // instance here so handleKeyRotation and revoke() write into the
    // list the Verifier reads from.
    const revocationList = opts.revocationList ?? new MemoryRevocationList();
    this.verifier = new Verifier({ ...opts, revocationList });
    this.accounts = opts.accounts;
    this.recipients = opts.recipients;
    this.discovery = opts.discovery;
    this.baseUrl = opts.baseUrl;
    this.revocationList = revocationList;
    this.invitationTtlSeconds = DEFAULT_INVITATION_TTL_SECONDS;
    this.redirectAllowList = new Set(opts.redirectAllowList ?? []);
    this.implicitSignup = opts.implicitSignup ?? true;
    this.rateLimiter = opts.rateLimiter;
    this.rateLimits = opts.rateLimits ?? {};
    this.attestor = opts.attestor;
    this.serviceDid = opts.serviceDid;
    this.ownerSessionMaxAgeSeconds = opts.ownerSessionMaxAgeSeconds ?? 300;

    if (opts.attestedSession) {
      if (!this.attestor) {
        throw new Error(
          "ServerOptions.attestedSession requires an attestor to verify re-presented attestations (§10.7).",
        );
      }
      this.attestedGate = new AttestedSessionGate({
        attestor: this.attestor,
        store: opts.attestedSession.store,
        serviceDid: this.serviceDid,
        mode: opts.attestedSession.mode,
        sessionTtlSeconds: opts.attestedSession.sessionTtlSeconds,
        now: opts.now,
      });
    }
  }

  /**
   * §10.7 business-request entry for attested-session services. Verifies
   * the signed request (like the bare Verifier), then — when
   * `attestedSession` is configured — processes any presented
   * `AFAuth-Attestation` header (sliding the freshness window forward)
   * and enforces freshness, throwing `401 attestation_required` once the
   * session has lapsed so the agent re-mints and retries.
   *
   * Use this on your service's OWN authenticated endpoints; the AFAuth
   * protocol endpoints (introspection, claim, key ops) self-verify.
   */
  async verifyAttested(
    req: Request,
    body: string | Uint8Array | null = null,
  ): Promise<VerifiedRequest> {
    if (!this.attestedGate) {
      throw new Error(
        "Server.verifyAttested requires ServerOptions.attestedSession to be configured (§10.7).",
      );
    }
    const verified = await this.verifier.verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body,
    });
    await this.attestedGate.check(req, verified.agentDid);
    return verified;
  }

  /**
   * §9.2 + §10 enforcement at signup. Called from the implicit-signup
   * branch in `handleAccountIntrospection` and any future explicit
   * signup handler.
   *
   * Behaviour:
   *   - discovery.billing.unclaimed_mode === "attested_only":
   *     * header MUST be present and valid; otherwise 401 attestation_required
   *       (no attestor configured → 503 — operator misconfiguration)
   *   - other modes:
   *     * if header present, validate; reject on invalid (`401 invalid_attestation`)
   *     * if header absent, silently allow
   *
   * Returns the verified `AttestationClaims` (so the caller can pass the
   * `(iss, sub_h)` principal to `AccountStore.signupAgent` for §10.4.4
   * device grouping), or `null` when no attestation was processed (absent
   * header in a lax mode). Does NOT itself mutate any store.
   */
  private async enforceAttestationOnSignup(
    req: Request,
    agentDid: Did,
  ): Promise<AttestationClaims | null> {
    const disc = await this.resolveDiscovery();
    const required = disc.billing?.unclaimed_mode === "attested_only";
    const header = req.headers.get("afauth-attestation");

    if (required && !header) {
      throw new AFAuthError(
        "attestation_required",
        401,
        "service declares attested_only mode; AFAuth-Attestation header is required",
        { accepted_attestors: disc.billing?.accepted_attestors },
      );
    }
    if (required && !this.attestor) {
      // Misconfiguration: service ADVERTISED attested_only but supplied
      // no attestor to verify against. 503 because it's a server fault,
      // not a client fault.
      throw new AFAuthError(
        "attestation_required",
        503,
        "service is misconfigured: attested_only declared but no attestor supplied",
      );
    }
    if (header && this.attestor) {
      // Pin audience to this service's DID — AFAP-0006 §10.3.1 makes
      // it MUST for the afauth-trust attestor, and platform/commerce
      // attestors all benefit from the same defense against
      // cross-service token replay.
      return await this.attestor.verify(header, agentDid, { audience: this.serviceDid });
    }
    return null;
  }

  /**
   * §10.4.4 device grouping. Turn verified attestation `claims` into the
   * `(iss, sub_h)` principal that `AccountStore.signupAgent` groups by — so
   * a human's second agent attaches to their existing account instead of
   * creating a new one. Returns `undefined` for runtime-only attestations
   * (no `sub_h`) and lax-mode no-header signups, which get singleton accounts.
   */
  private principalOf(
    claims: AttestationClaims | null,
  ): { iss: string; subH: string } | undefined {
    if (!claims || typeof claims.sub_h !== "string") return undefined;
    return { iss: claims.iss, subH: claims.sub_h };
  }

  /**
   * Per-route rate-limit gate. No-op when no limiter is configured or
   * the route has no config. Throws `429 rate_limit_exceeded` (with
   * `Retry-After`) when the limit is hit.
   */
  private async enforceRateLimit(
    route: keyof ServerRateLimits,
    key: string,
  ): Promise<void> {
    if (!this.rateLimiter) return;
    const config = this.rateLimits[route];
    if (!config) return;
    const decision = await this.rateLimiter.take(`${route}:${key}`, config);
    if (!decision.ok) {
      const retryAfter = decision.retryAfter ?? config.windowSeconds;
      throw new AFAuthError(
        "rate_limit_exceeded",
        429,
        `rate limit for ${route} hit; retry in ${retryAfter}s`,
        { retry_after: retryAfter, reset_at: decision.resetAt },
        { "retry-after": String(retryAfter) },
      );
    }
  }

  // The Verifier is shared with handlers — exposed so the Worker layer
  // can use it directly for endpoints that just need the verified DID
  // (e.g. account-introspection on GET).
  get verifierInstance(): Verifier {
    return this.verifier;
  }

  // ----- Discovery (§4) -----

  async handleDiscovery(_req: Request): Promise<Response> {
    const doc = await this.resolveDiscovery();
    return jsonResponse(doc, 200, { "cache-control": "max-age=300" });
  }

  private async resolveDiscovery(): Promise<DiscoveryDocument> {
    return typeof this.discovery === "function" ? this.discovery() : this.discovery;
  }

  /**
   * §7.2 redirect_url validation. Throws `400 malformed_request` if:
   *   - the value is not a parseable URL,
   *   - the URL's scheme is not http/https,
   *   - the URL's host is not in the configured `redirectAllowList`.
   * Throws if `redirectAllowList` is undefined or empty — failing
   * closed matches the spec's intent that unvalidated redirects are
   * rejected at the protocol's wire surface.
   */
  private validateRedirectUrl(value: string): void {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(value);
    } catch {
      throw new AFAuthError("malformed_request", 400, "redirect_url is not a valid URL");
    }
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      throw new AFAuthError(
        "malformed_request",
        400,
        `redirect_url scheme "${parsedUrl.protocol}" is not http/https`,
      );
    }
    if (this.redirectAllowList.size === 0) {
      throw new AFAuthError(
        "malformed_request",
        400,
        "redirect_url is not permitted: no redirectAllowList configured",
      );
    }
    if (!this.redirectAllowList.has(parsedUrl.host)) {
      throw new AFAuthError(
        "malformed_request",
        400,
        `redirect_url host "${parsedUrl.host}" is not in redirectAllowList`,
      );
    }
  }

  // ----- Owner invitation (§7.2) -----

  async handleOwnerInvitation(req: Request): Promise<Response> {
    if (req.method !== "POST") {
      throw new AFAuthError("malformed_request", 405, `method ${req.method} not allowed`);
    }
    // RFC 9421 §2: Content-Digest is computed over the raw body bytes.
    // Read via arrayBuffer() so non-UTF-8 bodies (binary uploads,
    // multipart, protobuf) preserve byte-identity through verification.
    const bodyBytes = new Uint8Array(await req.arrayBuffer());
    const verified = await this.verifier.verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: bodyBytes.length === 0 ? null : bodyBytes,
    });
    await this.enforceRateLimit("owner_invitation", verified.agentDid);

    let parsed: { recipient?: Recipient; email?: string; redirect_url?: string };
    try {
      parsed = JSON.parse(new TextDecoder().decode(bodyBytes)) as typeof parsed;
    } catch {
      throw new AFAuthError("malformed_request", 400, "request body is not valid JSON");
    }

    // §7.2 backward-compat: bare `email` → typed recipient. Both
    // forms together is an error (§7.2 normative).
    let recipient: Recipient;
    if (parsed.recipient && parsed.email) {
      throw new AFAuthError(
        "malformed_request",
        400,
        "request body MUST NOT contain both `recipient` and bare `email`",
      );
    } else if (parsed.recipient) {
      recipient = parsed.recipient;
    } else if (parsed.email) {
      recipient = { type: "email", value: parsed.email };
    } else {
      throw new AFAuthError("malformed_request", 400, "request body missing `recipient`");
    }

    // §7.7: normalise the recipient to its canonical form before
    // storage and §7.7 match-relation checks. Throws
    // malformed_request on values that violate the type's rule
    // (e.g., phone with extension syntax, did with DID URL component,
    // oidc issuer with fragment/query).
    recipient = normaliseRecipient(recipient);

    // §7.2: redirect_url MUST be validated against an allow-list of
    // service-controlled hosts. Failing closed when no list is
    // configured matches the spec's intent — an unvalidated redirect
    // is "rejected from the protocol's wire surface".
    if (parsed.redirect_url !== undefined) {
      this.validateRedirectUrl(parsed.redirect_url);
    }

    // §4.4: reject types not in the service's declared list.
    const disc = await this.resolveDiscovery();
    const declared = disc.recipient_types ?? ["email"];
    if (!declared.includes(recipient.type)) {
      throw new AFAuthError(
        "unsupported_recipient_type",
        400,
        `recipient type "${recipient.type}" not in declared recipient_types`,
      );
    }
    const handler = this.recipients[recipient.type];
    if (!handler) {
      throw new AFAuthError(
        "unsupported_recipient_type",
        400,
        `no handler configured for recipient type "${recipient.type}"`,
      );
    }

    let account = await this.accounts.getByAgentDid(verified.agentDid);
    if (!account) {
      if (!this.implicitSignup) {
        throw new AFAuthError("unknown_account", 404, "account does not exist (implicit signup disabled)");
      }
      // §9.2: owner-invitation against an unknown agent is an implicit signup
      // too — gate it on attestation exactly like introspection, otherwise
      // `attested_only` could be bypassed by inviting first. The agent's
      // `(iss, sub_h)` groups it onto an existing account if its human
      // already has one (§10.4.4).
      const claims = await this.enforceAttestationOnSignup(req, verified.agentDid);
      ({ account } = await this.accounts.signupAgent({
        did: verified.agentDid,
        ...(this.principalOf(claims) ? { principal: this.principalOf(claims)! } : {}),
      }));
    }
    if (account.revoked) {
      throw new AFAuthError("revoked_key", 401, "account key has been revoked");
    }
    if (account.state === "EXPIRED") {
      throw new AFAuthError(
        "account_expired",
        410,
        "account exceeded unclaimed_ttl_seconds and is no longer operable",
      );
    }
    if (account.state === "CLAIMED") {
      throw new AFAuthError(
        "already_claimed",
        409,
        "account is already claimed; further owner-invitation is post-claim policy",
      );
    }

    const token = generateInvitationToken();
    const expiresAt = new Date(Date.now() + this.invitationTtlSeconds * 1000).toISOString();
    await this.accounts.setPendingInvitation(account.accountId, recipient, token, expiresAt);

    // Compose the claim-page URL the recipient will be directed to.
    const claimPageUrl = new URL(disc.endpoints.claim_page, this.baseUrl).toString();

    // Fire the ceremony — the handler chooses how (email, SMS, OIDC, etc.).
    await handler.initiate({
      recipient,
      claimToken: token,
      claimPageUrl,
      ...(parsed.redirect_url ? { redirectUrl: parsed.redirect_url } : {}),
    });

    return jsonResponse(
      {
        // §7.2: returns a non-secret `invitation_id` derived from the
        // token via SHA-256. The raw token is the secret carried by
        // the magic link and MUST NOT be returned to the agent.
        invitation_id: deriveInvitationId(token),
        expires_at: expiresAt,
        state: "INVITED",
      },
      202,
    );
  }

  // ----- Claim completion (§7.4) -----

  async handleClaimCompletion(req: Request, session: OwnerSession): Promise<Response> {
    if (req.method !== "POST") {
      throw new AFAuthError("malformed_request", 405, `method ${req.method} not allowed`);
    }
    const url = new URL(req.url);
    const segments = url.pathname.split("/").filter(Boolean);
    const token = segments[segments.length - 1];
    if (!token) {
      throw new AFAuthError("malformed_request", 400, "claim token missing from URL path");
    }
    // §7.4: claim completion is one-shot per token. Rate-limit on the
    // token itself to throttle brute-force token guessing (the token
    // is 128 random bits so guessing is already infeasible, but this
    // adds defense-in-depth against pathological retry loops).
    await this.enforceRateLimit("claim_completion", token);

    const account = await this.accounts.findByPendingToken(token);
    if (!account || account.state !== "INVITED" || !account.pendingRecipient) {
      // §11.3: invitation_not_found / invitation_expired use 410.
      throw new AFAuthError(
        "invitation_not_found",
        410,
        "invitation not found, expired, or already consumed",
      );
    }

    const pending = account.pendingRecipient;
    const handler = this.recipients[pending.type];
    if (!handler) {
      throw new AFAuthError(
        "owner_authentication_required",
        403,
        `no handler configured for recipient type "${pending.type}"`,
      );
    }

    // §7.7 match relation — the only place where service policy meets
    // the §7.5 invariant. If this returns false the invitation stays
    // pending (per §7.4) so the human can retry with a different IdP.
    if (!handler.matches({ pending, authenticated: session.authenticated })) {
      throw new AFAuthError(
        "owner_authentication_required",
        403,
        "authenticated identity does not match pending recipient",
      );
    }

    const claimedAt = new Date().toISOString();
    const owner: NonNullable<Account["owner"]> = {
      identity: pending,
      userId: session.userId,
      claimedAt,
    };
    const updated = await this.accounts.completeClaimByToken(token, owner);
    if (!updated) {
      // The token was consumed in the gap between findByPendingToken
      // and completeClaimByToken — a benign race; report as expired.
      throw new AFAuthError(
        "invitation_expired",
        410,
        "invitation was consumed by another claim attempt",
      );
    }

    return jsonResponse(
      {
        account_id: updated.accountId,
        state: updated.state,
        owner: {
          identity: updated.owner!.identity,
          user_id: updated.owner!.userId,
          claimed_at: updated.owner!.claimedAt,
        },
      },
      200,
    );
  }

  // ----- Key rotation (§8.1, pre-claim) -----

  async handleKeyRotation(req: Request): Promise<Response> {
    if (req.method !== "POST") {
      throw new AFAuthError("malformed_request", 405, `method ${req.method} not allowed`);
    }
    const bodyBytes = new Uint8Array(await req.arrayBuffer());
    // Verify the request was signed by the agent's *current* key. If
    // that key was already revoked, the verifier rejects here.
    const verified = await this.verifier.verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: bodyBytes.length === 0 ? null : bodyBytes,
    });
    await this.enforceRateLimit("key_rotation", verified.agentDid);

    let parsed: { new_account_did?: string };
    try {
      parsed = JSON.parse(new TextDecoder().decode(bodyBytes)) as typeof parsed;
    } catch {
      throw new AFAuthError("malformed_request", 400, "request body is not valid JSON");
    }
    const newDid = parsed.new_account_did;
    if (typeof newDid !== "string" || newDid.length === 0) {
      throw new AFAuthError("malformed_request", 400, "missing `new_account_did`");
    }
    if (newDid === verified.agentDid) {
      throw new AFAuthError(
        "malformed_request",
        400,
        "new_account_did must differ from current account DID",
      );
    }
    // Validate that the new DID is a parseable did:key.
    try {
      decodeDidKey(newDid);
    } catch (err) {
      const reason = err instanceof Error ? err.message : "unknown";
      throw new AFAuthError(
        "malformed_request",
        400,
        `new_account_did is not a valid did:key: ${reason}`,
      );
    }

    const account = await this.accounts.getByAgentDid(verified.agentDid);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, "account not found");
    }
    if (account.revoked) {
      // Defensive — the verifier should have rejected first.
      throw new AFAuthError("revoked_key", 401, "account key has been revoked");
    }
    if (account.state === "EXPIRED") {
      throw new AFAuthError(
        "account_expired",
        410,
        "account exceeded unclaimed_ttl_seconds and is no longer operable",
      );
    }
    // Guard against a new DID that already names a credential anywhere.
    if (await this.accounts.getByAgentDid(newDid)) {
      throw new AFAuthError("already_claimed", 409, "new_account_did already names an existing credential");
    }
    // Pre-claim rotation only. Post-claim key changes are owner-binding
    // operations and cannot be driven by the agent signature alone — the
    // owner re-keys via the owner-session-gated `handleKeyReKey` (§8.2).
    if (account.state === "CLAIMED") {
      // §11.3: an agent-signed owner-binding operation post-claim is
      // `owner_binding_blocked`, NOT `owner_authentication_required`. The
      // distinction is load-bearing for recovery clients — this path can
      // never complete with any session (the agent signature is the wrong
      // actor); the owner must drive the owner-session-gated re-key (§8.2).
      throw new AFAuthError(
        "owner_binding_blocked",
        403,
        "post-claim key changes are owner-binding; the agent signature cannot complete them — the owner must re-key via the owner-session-gated endpoint (§8.2)",
      );
    }

    const rotatedAt = new Date().toISOString();
    // §8.1: swap the calling credential's DID within the account. The
    // `account_id` is STABLE across rotation (the account is not the DID).
    await this.accounts.rotateAgent(verified.agentDid, newDid, rotatedAt);
    // §8.3: register the old DID on the local revocation list so
    // subsequent requests signed by the old key are rejected.
    await this.revocationList.add(verified.agentDid, rotatedAt);

    return jsonResponse(
      {
        account_id: account.accountId,
        agent_did: newDid,
        old_revoked_at: rotatedAt,
      },
      200,
    );
  }

  // ----- Owner-initiated re-key (§8.2) -----

  /**
   * §8.2 owner-initiated re-key — the resume half of revoke → re-key.
   * The OWNER (not the agent) installs a fresh key on a CLAIMED account.
   * Owner-session-gated and NOT agent-signed: the old key may be stolen,
   * so this never calls `verifier.verify`. The account is named in the
   * body (there is no verified agentDid) and ownership is checked against
   * the session — that check is the sole multi-tenant guard on this path.
   *
   * Under did:key the account identifier necessarily changes (the DID is
   * the key); the new DID is returned. The owner binding and `sub_h`
   * carry forward via `AccountStore.reKey`, which also clears the revoked
   * flag atomically.
   */
  async handleKeyReKey(req: Request, session: OwnerSession): Promise<Response> {
    if (req.method !== "POST") {
      throw new AFAuthError("malformed_request", 405, `method ${req.method} not allowed`);
    }
    // §7.5 freshness floor — re-keying is an owner-binding operation.
    assertFreshOwnerSession(session, { maxAgeSeconds: this.ownerSessionMaxAgeSeconds });
    await this.enforceRateLimit("owner_key_operation", session.userId);

    const bodyBytes = new Uint8Array(await req.arrayBuffer());
    let parsed: { current_account_did?: string; new_account_did?: string };
    try {
      parsed = JSON.parse(new TextDecoder().decode(bodyBytes)) as typeof parsed;
    } catch {
      throw new AFAuthError("malformed_request", 400, "request body is not valid JSON");
    }
    const currentDid = parsed.current_account_did;
    const newDid = parsed.new_account_did;
    if (typeof currentDid !== "string" || currentDid.length === 0) {
      throw new AFAuthError("malformed_request", 400, "missing `current_account_did`");
    }
    if (typeof newDid !== "string" || newDid.length === 0) {
      throw new AFAuthError("malformed_request", 400, "missing `new_account_did`");
    }
    if (newDid === currentDid) {
      throw new AFAuthError(
        "malformed_request",
        400,
        "new_account_did must differ from current_account_did",
      );
    }
    try {
      decodeDidKey(newDid);
    } catch (err) {
      const reason = err instanceof Error ? err.message : "unknown";
      throw new AFAuthError("malformed_request", 400, `new_account_did is not a valid did:key: ${reason}`);
    }

    // `current_account_did` names the credential (device) being re-keyed; it
    // resolves to the account, which `account_id` stably identifies.
    const account = await this.accounts.getByAgentDid(currentDid);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, "account not found");
    }
    if (account.state === "EXPIRED") {
      throw new AFAuthError("account_expired", 410, "account is EXPIRED and cannot be re-keyed");
    }
    if (account.state !== "CLAIMED") {
      throw new AFAuthError("not_claimed", 409, "owner re-key applies only to CLAIMED accounts (§8.2)");
    }
    // The sole multi-tenant guard on this non-agent-signed path: the
    // session owner MUST match the account owner. `owner` is always set
    // for CLAIMED, but guard defensively so an undefined owner can never
    // match a real userId.
    if (!account.owner || session.userId !== account.owner.userId) {
      throw new AFAuthError("owner_authentication_required", 403, "owner session does not own this account");
    }
    // Collision guard: refuse a new DID that already names a credential
    // (Memory would silently clobber it; D1 would throw a raw PK error).
    if (await this.accounts.getByAgentDid(newDid)) {
      throw new AFAuthError("already_claimed", 409, "new_account_did already names an existing credential");
    }

    const reKeyedAt = new Date().toISOString();
    // §8.2: swap the credential DID and clear the account `revoked` flag
    // atomically; `account_id` is stable.
    await this.accounts.reKey(currentDid, newDid, reKeyedAt);
    // Lock out the old key for defense-in-depth.
    await this.revocationList.add(currentDid, reKeyedAt);

    return jsonResponse(
      { account_id: account.accountId, agent_did: newDid, old_revoked_at: reKeyedAt, state: "CLAIMED" },
      200,
    );
  }

  // ----- Owner-initiated revocation (§8.4) -----

  /**
   * Revoke the agent's key entirely. Called by the service from its
   * own owner-authenticated dashboard or admin route — not from a
   * signed AFAuth endpoint. The caller is responsible for verifying
   * the owner is authenticated; this method performs the storage-level
   * mutation and updates the revocation list.
   *
   * Note: §8.4 ("The owner of a CLAIMED account MAY revoke …")
   * describes the owner-driven use case. This method intentionally
   * accepts any account state so services can also use it for
   * abuse-driven revocation. Production services should restrict
   * access to this method to owner-authenticated callers (for §8.4)
   * or to abuse-handling staff (for service-driven revocation).
   */
  async revoke(accountId: string): Promise<void> {
    const account = await this.accounts.getById(accountId);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${accountId} not found`);
    }
    const revokedAt = new Date().toISOString();
    await this.accounts.revoke(accountId, revokedAt);
    // Block every credential (device) of the account at the Verifier (§8.3).
    for (const agent of account.agents) await this.revocationList.add(agent.did, revokedAt);
  }

  /**
   * §8.4 owner-initiated revocation as an owner-session-gated wire
   * endpoint — the turnkey form of the `examples/recipes/revoke.ts`
   * pattern. NOT agent-signed. The bare `Server.revoke(did)` primitive
   * above stays available for un-gated abuse tooling.
   *
   * Idempotent: re-revoking an already-revoked account returns 200.
   */
  async handleKeyRevocation(req: Request, session: OwnerSession): Promise<Response> {
    if (req.method !== "POST") {
      throw new AFAuthError("malformed_request", 405, `method ${req.method} not allowed`);
    }
    assertFreshOwnerSession(session, { maxAgeSeconds: this.ownerSessionMaxAgeSeconds });
    await this.enforceRateLimit("owner_key_operation", session.userId);

    const bodyBytes = new Uint8Array(await req.arrayBuffer());
    let parsed: { account_id?: string; agent_did?: string };
    try {
      parsed = JSON.parse(new TextDecoder().decode(bodyBytes)) as typeof parsed;
    } catch {
      throw new AFAuthError("malformed_request", 400, "request body is not valid JSON");
    }
    // Name the account directly by `account_id`, or by any of its agent
    // credentials via `agent_did` (revoke the account a device belongs to).
    const accountId = parsed.account_id;
    const agentDid = parsed.agent_did;
    if ((typeof accountId !== "string" || !accountId) && (typeof agentDid !== "string" || !agentDid)) {
      throw new AFAuthError("malformed_request", 400, "missing `account_id` (or `agent_did`)");
    }

    const account = accountId
      ? await this.accounts.getById(accountId)
      : await this.accounts.getByAgentDid(agentDid!);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, "account not found");
    }
    if (account.state === "EXPIRED") {
      throw new AFAuthError("account_expired", 410, "account is EXPIRED");
    }
    if (account.state !== "CLAIMED") {
      // §8.4 is "the owner of a CLAIMED account MAY revoke". A pre-claim
      // account has no owner to authenticate, so there is nothing to
      // owner-revoke.
      throw new AFAuthError("not_claimed", 409, "owner revocation applies only to CLAIMED accounts (§8.4)");
    }
    if (!account.owner || session.userId !== account.owner.userId) {
      throw new AFAuthError("owner_authentication_required", 403, "owner session does not own this account");
    }

    const revokedAt = new Date().toISOString();
    await this.accounts.revoke(account.accountId, revokedAt);
    // Block every credential (device) of the account at the Verifier (§8.3).
    for (const agent of account.agents) await this.revocationList.add(agent.did, revokedAt);

    return jsonResponse({ account_id: account.accountId, revoked_at: revokedAt }, 200);
  }

  // ----- Account introspection (§6.5) -----

  async handleAccountIntrospection(req: Request): Promise<Response> {
    if (req.method !== "GET") {
      throw new AFAuthError("malformed_request", 405, `method ${req.method} not allowed`);
    }
    const verified = await this.verifier.verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: null,
    });
    await this.enforceRateLimit("account_introspection", verified.agentDid);

    let account = await this.accounts.getByAgentDid(verified.agentDid);
    if (!account) {
      if (!this.implicitSignup) {
        throw new AFAuthError("unknown_account", 404, "account does not exist (implicit signup disabled)");
      }
      // §9.2: enforce attested_only mode (and validate any present
      // header in lax mode) BEFORE creating the account row. A
      // rejected attestation MUST NOT leave a side-effect.
      const claims = await this.enforceAttestationOnSignup(req, verified.agentDid);
      // Implicit signup also goes through the `accounts` rate-limit
      // bucket since it creates an account row.
      await this.enforceRateLimit("accounts", verified.agentDid);
      // §10.4.4: group by the verified `(iss, sub_h)` principal — a known
      // human's second agent attaches to their existing account ("same
      // human, same account, many devices"); a no-`sub_h` agent gets a
      // singleton account.
      ({ account } = await this.accounts.signupAgent({
        did: verified.agentDid,
        ...(this.principalOf(claims) ? { principal: this.principalOf(claims)! } : {}),
      }));
    }

    // §7.2 / §13.2: agent-signed responses MUST NOT expose pending fields.
    const disc = await this.resolveDiscovery();
    const body: Record<string, unknown> = {
      account_id: account.accountId,
      agent_did: verified.agentDid,
      state: account.state,
      created_at: account.createdAt,
    };
    if (account.state === "UNCLAIMED" && disc.limits?.unclaimed_ttl_seconds) {
      const expiresMs =
        Date.parse(account.createdAt) + disc.limits.unclaimed_ttl_seconds * 1000;
      if (Number.isFinite(expiresMs)) {
        body.unclaimed_expires_at = new Date(expiresMs).toISOString();
      }
    }
    if (account.owner) {
      body.owner = {
        identity: account.owner.identity,
        user_id: account.owner.userId,
        claimed_at: account.owner.claimedAt,
      };
    }
    if (account.revoked) {
      body.revoked = true;
    }

    return jsonResponse(body, 200);
  }
}

// ---------------------------------------------------------------------
// defineService — opinionated convenience factory (§9.2 / §10 default-on)
// ---------------------------------------------------------------------
//
// `new Server({...})` is the low-level escape hatch: pass an explicit
// discovery doc, attestor, nonce store, revocation list, etc. It makes
// no assumptions about attestation mode.
//
// `defineService({...})` is the recommended path for new integrations.
// It flips the protocol's spam-resistance switches to ON by default:
//
//   - attestation: 'required' (default)
//       → discovery.billing.unclaimed_mode = 'attested_only'
//       → attestor = trustAttestor() (afauth-trust)
//       → un-attested implicit signups → 401 attestation_required
//   - attestation: 'optional'
//       → discovery.billing.unclaimed_mode unset (open)
//       → attestor = trustAttestor() (verifies when present, allows when absent)
//   - attestation: 'off'
//       → no attestor, no enforcement (matches `new Server({...})` defaults)
//
// Services that need MultiAttestor, custom HMAC attestors, or a fully
// custom discovery doc should fall back to `new Server({...})`.

export type AttestationMode = "required" | "optional" | "off";

export interface DefineServiceOptions {
  /** Public base URL of the service (e.g. "https://api.example.com"). */
  baseUrl: string;
  /** Service DID. Used as `aud` for attestation verification and in discovery. */
  serviceDid: Did;
  /** Persistent account store. */
  accounts: AccountStore;
  /** Recipient handlers for owner invitations. */
  recipients: ServerOptions["recipients"];

  /**
   * Attestation policy. Defaults to `'required'` — spam-resistant out
   * of the box. Set `'off'` to opt out (read-only or paid-only services).
   */
  attestation?: AttestationMode;
  /**
   * Override the default attestor. When omitted and `attestation` is
   * `'required'` or `'optional'`, this defaults to `trustAttestor()`.
   * Useful for pointing at a staging trust attestor, swapping in
   * `MultiAttestor`, or layering an HMAC service-operator attestor.
   */
  attestor?: Attestor;
  /**
   * Partial discovery overrides merged on top of the synthesized
   * document. Use this to customize endpoint paths, advertise extra
   * `accepted_attestors`, declare `limits`, etc.
   */
  discovery?: Partial<DiscoveryDocument>;

  // Pass-throughs to ServerOptions for less common knobs:
  nonceStore?: NonceStore;
  revocationList?: RevocationList;
  rateLimiter?: RateLimiter;
  rateLimits?: ServerRateLimits;
  redirectAllowList?: readonly string[];
  implicitSignup?: boolean;
  didResolver?: DidResolver;
  clockSkewSeconds?: number;
  maxSignatureLifetimeSeconds?: number;
  now?: () => number;
}

/**
 * Build a `Server` with attestation-required defaults (§9.2).
 *
 *   const server = defineService({
 *     baseUrl: 'https://api.example.com',
 *     serviceDid: 'did:web:api.example.com',
 *     accounts, recipients,
 *   });
 *
 * Equivalent to wiring `unclaimed_mode: 'attested_only'`,
 * `accepted_attestors: ['afauth-trust']`, and `attestor: trustAttestor()`
 * by hand. Override `attestation: 'off'` to opt out.
 *
 * §10.4.4 device grouping ("one account, many devices") needs no option: it
 * is intrinsic to every `AccountStore` — a second agent presenting the same
 * verified `(iss, sub_h)` attaches to its human's existing account.
 */
export function defineService(opts: DefineServiceOptions): Server {
  const mode: AttestationMode = opts.attestation ?? "required";

  const attestor: Attestor | undefined =
    opts.attestor ?? (mode === "off" ? undefined : trustAttestor());

  const discovery = synthesizeDiscovery({
    baseUrl: opts.baseUrl,
    serviceDid: opts.serviceDid,
    mode,
    override: opts.discovery,
  });

  return new Server({
    baseUrl: opts.baseUrl,
    serviceDid: opts.serviceDid,
    accounts: opts.accounts,
    recipients: opts.recipients,
    discovery,
    nonceStore: opts.nonceStore ?? new MemoryNonceStore(),
    revocationList: opts.revocationList,
    rateLimiter: opts.rateLimiter,
    rateLimits: opts.rateLimits,
    redirectAllowList: opts.redirectAllowList,
    implicitSignup: opts.implicitSignup,
    didResolver: opts.didResolver,
    clockSkewSeconds: opts.clockSkewSeconds,
    maxSignatureLifetimeSeconds: opts.maxSignatureLifetimeSeconds,
    now: opts.now,
    ...(attestor ? { attestor } : {}),
  });
}

function synthesizeDiscovery(args: {
  baseUrl: string;
  serviceDid: Did;
  mode: AttestationMode;
  override?: Partial<DiscoveryDocument>;
}): DiscoveryDocument {
  const base = args.baseUrl.replace(/\/+$/, "");
  // Canonical §4.1 / Appendix B paths. These MUST match the request paths
  // the agent SDK builders construct (`@afauthhq/agent`'s
  // buildAccountIntrospection / buildOwnerInvitation / buildKeyRotation),
  // which `@afauthhq/worker` also derives its routes from — a service that
  // synthesizes divergent paths 404s a default agent (the introspection
  // route is `<accounts>/me`). Operators can still override any path via
  // `discovery.endpoints`; a discovery-aware agent follows whatever is
  // advertised.
  const endpoints = {
    accounts: `${base}/afauth/v1/accounts`,
    owner_invitation: `${base}/afauth/v1/accounts/me/owner-invitation`,
    claim_page: `${base}/claim`,
    claim_completion: `${base}/afauth/v1/claim`,
    key_rotation: `${base}/afauth/v1/accounts/me/keys/rotate`,
    ...args.override?.endpoints,
  };

  const billing: NonNullable<DiscoveryDocument["billing"]> = {
    ...(args.mode === "required" ? { unclaimed_mode: "attested_only" } : {}),
    ...(args.mode !== "off" ? { accepted_attestors: [AFAUTH_TRUST_ISS] } : {}),
    ...args.override?.billing,
  };

  const { endpoints: _ignoreEndpoints, billing: _ignoreBilling, ...overrideRest } =
    args.override ?? {};

  const doc: DiscoveryDocument = {
    afauth_version: "0.1",
    service_did: args.serviceDid,
    signature_algorithms: ["ed25519"],
    ...overrideRest,
    endpoints,
    ...(Object.keys(billing).length > 0 ? { billing } : {}),
  };
  return doc;
}
