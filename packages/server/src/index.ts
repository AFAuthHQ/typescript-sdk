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
  CompositeDidResolver,
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

export interface Account {
  did: Did;
  state: AccountState;
  /** ISO-8601 timestamp the account was first materialised (§6.4/§6.5). */
  createdAt: string;
  pendingRecipient?: Recipient;
  owner?: { identity: Recipient; userId: string; claimedAt: string };
  revoked?: boolean;
}

/**
 * Storage contract for AFAuth accounts. See ADR-0004.
 */
export interface AccountStore {
  // ----- Reads -----
  get(did: Did): Promise<Account | null>;

  /**
   * Read-only lookup by pending invitation token. Returns the account
   * iff the token is currently associated with a pending invitation
   * that has not yet expired. Returns null otherwise. Used by
   * Server.handleClaimCompletion to inspect pendingRecipient and apply
   * the §7.7 match relation before the atomic commit.
   */
  findByPendingToken(token: string): Promise<Account | null>;

  // ----- Atomic mutations -----
  createUnclaimed(did: Did): Promise<Account>;
  setPendingInvitation(
    did: Did,
    recipient: Recipient,
    token: string,
    expiresAt: string,
  ): Promise<Account>;
  completeClaimByToken(
    token: string,
    owner: NonNullable<Account["owner"]>,
  ): Promise<Account | null>;
  rotateKey(oldDid: Did, newDid: Did, rotatedAt: string): Promise<Account>;
  revoke(did: Did, revokedAt: string): Promise<Account>;
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
   * Transition the account to `EXPIRED`. Idempotent — calling on an
   * already-EXPIRED account is a no-op. Calling on a CLAIMED or
   * unknown account throws (the spec forbids CLAIMED → EXPIRED).
   */
  expire(did: Did, expiredAt: string): Promise<Account>;
}

/**
 * Single-process in-memory implementation of `AccountStore`. Suitable
 * for tests and small examples; production deployments should use a
 * durable backend (e.g. a KV-backed implementation).
 */
export class MemoryAccountStore implements SweepableAccountStore {
  private readonly accounts = new Map<Did, Account>();
  private readonly tokens = new Map<string, { did: Did; expiresAt: string }>();
  /** Reverse index: did → its current pending-invitation token, if any.
   *  Lets §7.3 atomic supersession run in O(1) instead of scanning
   *  every token on every new invitation. */
  private readonly didToToken = new Map<Did, string>();

  async get(did: Did): Promise<Account | null> {
    return this.accounts.get(did) ?? null;
  }

  async findByPendingToken(token: string): Promise<Account | null> {
    const entry = this.tokens.get(token);
    if (!entry) return null;
    if (new Date(entry.expiresAt).getTime() < Date.now()) {
      this.tokens.delete(token);
      return null;
    }
    return this.accounts.get(entry.did) ?? null;
  }

  async createUnclaimed(did: Did): Promise<Account> {
    const existing = this.accounts.get(did);
    if (existing) return existing;
    const fresh: Account = {
      did,
      state: "UNCLAIMED",
      createdAt: new Date().toISOString(),
    };
    this.accounts.set(did, fresh);
    return fresh;
  }

  async setPendingInvitation(
    did: Did,
    recipient: Recipient,
    token: string,
    expiresAt: string,
  ): Promise<Account> {
    const account = this.accounts.get(did);
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
        `account ${did} is already claimed`,
      );
    }

    // §7.3 atomic replacement: invalidate any prior pending invitation
    // for this DID before installing the new one. O(1) via reverse
    // index instead of scanning the full token map.
    const existing = this.didToToken.get(did);
    if (existing !== undefined) this.tokens.delete(existing);

    this.tokens.set(token, { did, expiresAt });
    this.didToToken.set(did, token);
    account.state = "INVITED";
    account.pendingRecipient = recipient;
    this.accounts.set(did, account);
    return { ...account };
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
    const account = this.accounts.get(entry.did);
    if (!account) return null;

    const claimed: Account = {
      did: account.did,
      state: "CLAIMED",
      createdAt: account.createdAt,
      owner,
      ...(account.revoked ? { revoked: account.revoked } : {}),
    };
    this.accounts.set(entry.did, claimed);
    this.tokens.delete(token);
    this.didToToken.delete(entry.did);
    return claimed;
  }

  async rotateKey(oldDid: Did, newDid: Did, _rotatedAt: string): Promise<Account> {
    const account = this.accounts.get(oldDid);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${oldDid} does not exist`);
    }
    const rotated: Account = { ...account, did: newDid };
    this.accounts.delete(oldDid);
    this.accounts.set(newDid, rotated);
    // Migrate the pending-token reference (if any) atomically with
    // the account-id swap. O(1) via reverse index.
    const tok = this.didToToken.get(oldDid);
    if (tok !== undefined) {
      this.didToToken.delete(oldDid);
      this.didToToken.set(newDid, tok);
      const tokenEntry = this.tokens.get(tok);
      if (tokenEntry) tokenEntry.did = newDid;
    }
    return rotated;
  }

  async revoke(did: Did, _revokedAt: string): Promise<Account> {
    const account = this.accounts.get(did);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${did} does not exist`);
    }
    account.revoked = true;
    this.accounts.set(did, account);
    return { ...account };
  }

  async listOpenAccounts(): Promise<Account[]> {
    const out: Account[] = [];
    for (const account of this.accounts.values()) {
      if (account.state === "UNCLAIMED" || account.state === "INVITED") {
        out.push({ ...account });
      }
    }
    return out;
  }

  async expire(did: Did, _expiredAt: string): Promise<Account> {
    const account = this.accounts.get(did);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${did} does not exist`);
    }
    if (account.state === "CLAIMED") {
      // Spec forbids CLAIMED → EXPIRED (Appendix A).
      throw new AFAuthError(
        "already_claimed",
        409,
        `account ${did} is CLAIMED; the CLAIMED → EXPIRED transition is forbidden`,
      );
    }
    if (account.state === "EXPIRED") {
      // Idempotent.
      return { ...account };
    }
    account.state = "EXPIRED";
    // Drop the pending invitation (if any) — EXPIRED accounts have no
    // operable surface, and the pending recipient is no longer
    // bindable.
    if (account.pendingRecipient) delete account.pendingRecipient;
    const tok = this.didToToken.get(did);
    if (tok !== undefined) {
      this.tokens.delete(tok);
      this.didToToken.delete(did);
    }
    this.accounts.set(did, account);
    return { ...account };
  }
}

// ---------- TTL sweep (§6.1 / Appendix A) ----------

export interface SweepOptions {
  /**
   * Service's `unclaimed_ttl_seconds` from §4.4 — the maximum age
   * before an UNCLAIMED or INVITED account transitions to EXPIRED.
   * Required (no sensible default — pick a value appropriate to the
   * account's value).
   */
  unclaimedTtlSeconds: number;
  /**
   * Function returning the current `Date`. Overridable for tests.
   * Defaults to `() => new Date()`.
   */
  now?: () => Date;
}

export interface SweepResult {
  /** DIDs transitioned to EXPIRED in this run. */
  expired: Did[];
  /** Total accounts considered (UNCLAIMED + INVITED). */
  scanned: number;
}

/**
 * Periodic sweep that transitions UNCLAIMED / INVITED accounts to
 * `EXPIRED` once they exceed `unclaimedTtlSeconds` from their
 * `createdAt`. Spec §6.1 / Appendix A make this transition mandatory;
 * the SDK does not run it automatically because *when* to sweep is
 * service policy.
 *
 * USAGE
 *
 *   // Run every 15 minutes from your scheduler (cron / Workers
 *   // scheduled trigger / Lambda EventBridge rule).
 *   const result = await sweepExpiredAccounts(accountStore, {
 *     unclaimedTtlSeconds: discovery.limits!.unclaimed_ttl_seconds!,
 *   });
 *   console.log(`expired ${result.expired.length} of ${result.scanned}`);
 *
 * SCOPE
 *
 *   - Sweeps UNCLAIMED → EXPIRED and INVITED → EXPIRED. Both transitions
 *     are spec-mandated (Appendix A).
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
  opts: SweepOptions,
): Promise<SweepResult> {
  if (!Number.isFinite(opts.unclaimedTtlSeconds) || opts.unclaimedTtlSeconds <= 0) {
    throw new Error(
      `sweepExpiredAccounts: unclaimedTtlSeconds must be a positive number; got ${opts.unclaimedTtlSeconds}`,
    );
  }
  const now = opts.now ? opts.now() : new Date();
  const cutoffMs = now.getTime() - opts.unclaimedTtlSeconds * 1000;
  const expiredAt = now.toISOString();

  const candidates = await store.listOpenAccounts();
  const expired: Did[] = [];

  for (const account of candidates) {
    const createdMs = Date.parse(account.createdAt);
    if (!Number.isFinite(createdMs)) continue;
    if (createdMs <= cutoffMs) {
      await store.expire(account.did, expiredAt);
      expired.push(account.did);
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

// ---------- DID resolution (§3.1.2) ----------
//
// DidWebResolver is the §3.1.2 reference implementation: GET
// https://<host>/.well-known/did.json, validate, extract the Ed25519
// verification method, cache, return. It lives in @afauthhq/server (not
// @afauthhq/core) because it needs HTTP fetch; @afauthhq/core stays
// dependency-free for the agent.

/**
 * Configuration knobs for `DidWebResolver`.
 *
 * Production deployments SHOULD configure `positiveCacheTtlSeconds`
 * per §3.1.2 (RECOMMENDED ≤ 1 hour) and a real `fetch` with a sensible
 * connect-and-read timeout. The defaults below are safe but
 * conservative.
 */
export interface DidWebResolverOptions {
  /**
   * Pluggable fetch. Defaults to `globalThis.fetch` (available in
   * Workers, Node ≥18, Deno, browsers). Override for tests or to
   * inject a connection pool.
   */
  fetch?: typeof globalThis.fetch;
  /** Default: 300. RECOMMENDED ≤ 3600 per §3.1.2. */
  positiveCacheTtlSeconds?: number;
  /** Default: 60. Cache TTL for resolution FAILURES (limits hammering bad hosts). */
  negativeCacheTtlSeconds?: number;
  /** Default: 5000. Per-fetch timeout in milliseconds. */
  timeoutMs?: number;
  /** Default: 65536. Cap on the DID document body size (denial-of-service guard). */
  maxBytes?: number;
  /**
   * Default: false. When false, the resolver rejects `did:web` values
   * that would resolve to a non-https URL. Set to true ONLY for tests
   * (e.g. talking to an httptest server on localhost).
   */
  allowInsecureTransport?: boolean;
  /** Function returning current unix-second time. Overridable for tests. */
  now?: () => number;
}

interface CacheEntry {
  expiresAt: number;
  ok?: Ed25519PublicKey;
  err?: AFAuthError;
}

/**
 * Resolver for `did:web:host[:path]` identifiers per §3.1.2 and
 * [W3C-DID-WEB].
 *
 * Mapping rules (W3C-DID-WEB §3.2):
 *   did:web:example.com           → https://example.com/.well-known/did.json
 *   did:web:example.com:user:a    → https://example.com/user/a/did.json
 *   did:web:example.com%3A8443    → https://example.com:8443/.well-known/did.json
 *
 * The fetched document MUST be a JSON object whose `verificationMethod`
 * array contains at least one entry with an Ed25519 public key (in
 * either `Ed25519VerificationKey2020` + `publicKeyMultibase` form, or
 * `JsonWebKey2020` + `publicKeyJwk` with `kty=OKP, crv=Ed25519`).
 *
 * Caching: positive results live for `positiveCacheTtlSeconds`;
 * negative results for `negativeCacheTtlSeconds`. The resolver does
 * NOT honour the response's `Cache-Control`; configure the TTLs
 * directly.
 */
export class DidWebResolver implements DidResolver {
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly positiveTtl: number;
  private readonly negativeTtl: number;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly allowInsecure: boolean;
  private readonly now: () => number;
  private readonly cache = new Map<Did, CacheEntry>();

  constructor(opts: DidWebResolverOptions = {}) {
    this.fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.positiveTtl = opts.positiveCacheTtlSeconds ?? 300;
    this.negativeTtl = opts.negativeCacheTtlSeconds ?? 60;
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.maxBytes = opts.maxBytes ?? 65536;
    this.allowInsecure = opts.allowInsecureTransport ?? false;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Drop the cached result for the given DID. Used after a verify
   * failure to satisfy §3.1.2's "re-fetch on signature verification
   * failure" obligation — call this from your Verifier's catch path
   * when a did:web-signed request fails Ed25519 verification.
   */
  invalidate(did: Did): void {
    this.cache.delete(did);
  }

  async resolve(did: Did): Promise<Ed25519PublicKey> {
    const cached = this.cache.get(did);
    if (cached && cached.expiresAt > this.now()) {
      if (cached.ok) return cached.ok;
      if (cached.err) throw cached.err;
    }

    let pub: Ed25519PublicKey;
    try {
      pub = await this.fetchAndExtract(did);
    } catch (err) {
      const afErr = err instanceof AFAuthError
        ? err
        : new AFAuthError("invalid_signature", 401, `DidWebResolver: ${(err as Error).message}`);
      this.cache.set(did, { expiresAt: this.now() + this.negativeTtl, err: afErr });
      throw afErr;
    }
    this.cache.set(did, { expiresAt: this.now() + this.positiveTtl, ok: pub });
    return pub;
  }

  private async fetchAndExtract(did: Did): Promise<Ed25519PublicKey> {
    const url = this.urlForDid(did);
    if (!this.allowInsecure && !url.startsWith("https://")) {
      throw new AFAuthError(
        "invalid_signature",
        401,
        `DidWebResolver: did:web MUST resolve to HTTPS; got ${url}`,
      );
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let resp: Response;
    try {
      resp = await this.fetchFn(url, {
        method: "GET",
        headers: { accept: "application/json" },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (!resp.ok) {
      throw new AFAuthError(
        "invalid_signature",
        401,
        `DidWebResolver: fetch ${url} returned HTTP ${resp.status}`,
      );
    }
    const ct = (resp.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
    if (ct !== "application/json" && ct !== "application/did+json") {
      throw new AFAuthError(
        "invalid_signature",
        401,
        `DidWebResolver: fetch ${url} content-type ${ct} is not application/json`,
      );
    }

    const buf = await resp.arrayBuffer();
    if (buf.byteLength > this.maxBytes) {
      throw new AFAuthError(
        "invalid_signature",
        401,
        `DidWebResolver: did.json body exceeds maxBytes=${this.maxBytes}`,
      );
    }
    let doc: unknown;
    try {
      doc = JSON.parse(new TextDecoder().decode(buf));
    } catch (e) {
      throw new AFAuthError("invalid_signature", 401, `DidWebResolver: malformed JSON: ${(e as Error).message}`);
    }
    return extractEd25519FromDidDocument(doc, did);
  }

  /**
   * W3C-DID-WEB §3.2: colons in the method-specific identifier are
   * replaced with slashes; the `:host[:path]` portion becomes the
   * URL host + path; absent path → `/.well-known/did.json`.
   *
   * `did:web:example.com%3A8443` keeps the URL-encoded port intact.
   */
  private urlForDid(did: Did): string {
    if (!did.startsWith("did:web:")) {
      throw new AFAuthError("invalid_signature", 401, `not a did:web value: ${did}`);
    }
    const idspec = did.slice("did:web:".length);
    if (idspec === "") {
      throw new AFAuthError("invalid_signature", 401, "did:web: missing host");
    }
    const parts = idspec.split(":");
    const host = decodeURIComponent(parts[0]!);
    if (host !== host.toLowerCase()) {
      // Matches the recipient-normalisation rule in §7.7.4.
      throw new AFAuthError("invalid_signature", 401, "did:web host MUST be lowercase");
    }
    if (parts.length === 1) {
      return `https://${host}/.well-known/did.json`;
    }
    const tail = parts.slice(1).map((p) => decodeURIComponent(p)).join("/");
    return `https://${host}/${tail}/did.json`;
  }
}

/**
 * Walks a DID document and returns the first Ed25519 verification key.
 * Supports the two common encodings:
 *   - `Ed25519VerificationKey2020` + `publicKeyMultibase: "z6Mk..."`
 *   - `JsonWebKey2020` + `publicKeyJwk: {kty:"OKP", crv:"Ed25519", x:"<b64url>"}`
 *
 * Throws `invalid_signature` on schema violation or missing key.
 */
function extractEd25519FromDidDocument(doc: unknown, did: Did): Ed25519PublicKey {
  if (!doc || typeof doc !== "object") {
    throw new AFAuthError("invalid_signature", 401, "DID document is not an object");
  }
  const d = doc as Record<string, unknown>;
  if (typeof d.id === "string" && d.id !== did) {
    // §3.1.2 says the document's id must match the DID being resolved.
    throw new AFAuthError(
      "invalid_signature",
      401,
      `DID document id ${d.id} does not match resolved DID ${did}`,
    );
  }
  const vms = d.verificationMethod;
  if (!Array.isArray(vms) || vms.length === 0) {
    throw new AFAuthError(
      "invalid_signature",
      401,
      "DID document has no verificationMethod entries",
    );
  }
  for (const raw of vms) {
    if (!raw || typeof raw !== "object") continue;
    const vm = raw as Record<string, unknown>;
    const t = vm.type;
    if (t === "Ed25519VerificationKey2020" && typeof vm.publicKeyMultibase === "string") {
      const mb = vm.publicKeyMultibase;
      if (!mb.startsWith("z")) {
        throw new AFAuthError(
          "invalid_signature",
          401,
          `publicKeyMultibase must use base58btc (z…); got ${mb.slice(0, 1)}`,
        );
      }
      // Reuse decodeDidKey's parser by constructing a synthetic did:key.
      try {
        return decodeDidKey(`did:key:${mb}`);
      } catch (e) {
        throw new AFAuthError(
          "invalid_signature",
          401,
          `publicKeyMultibase did not decode as Ed25519: ${(e as Error).message}`,
        );
      }
    }
    if (t === "JsonWebKey2020" && raw && typeof (vm.publicKeyJwk) === "object") {
      const jwk = vm.publicKeyJwk as Record<string, unknown>;
      if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
        continue;
      }
      const x = jwk.x as string;
      // base64url decode.
      const pad = x.length % 4 === 0 ? "" : "=".repeat(4 - (x.length % 4));
      const b64 = x.replace(/-/g, "+").replace(/_/g, "/") + pad;
      let bin: string;
      try {
        bin = atob(b64);
      } catch (e) {
        throw new AFAuthError("invalid_signature", 401, "publicKeyJwk.x is not valid base64url");
      }
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      if (bytes.length !== 32) {
        throw new AFAuthError(
          "invalid_signature",
          401,
          `Ed25519 publicKeyJwk.x must decode to 32 bytes, got ${bytes.length}`,
        );
      }
      return bytes;
    }
  }
  throw new AFAuthError(
    "invalid_signature",
    401,
    "DID document has no Ed25519 verification method",
  );
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
  /** Attestor-specific extra claims (raw). */
  [key: string]: unknown;
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
  verify(jwt: string, agentDid: Did): Promise<AttestationClaims>;
}

interface BaseAttestorOpts {
  /** Attestor identifier — must match the JWT's `iss`. */
  iss: string;
  /** Function returning current unix-second time. Overridable for tests. */
  now?: () => number;
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

  constructor(opts: BaseAttestorOpts & { secret: Uint8Array | string }) {
    this.iss = opts.iss;
    this.key = typeof opts.secret === "string" ? new TextEncoder().encode(opts.secret) : opts.secret;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async verify(jwt: string, agentDid: Did): Promise<AttestationClaims> {
    let result: JWTVerifyResult;
    try {
      result = await jwtVerify(jwt, this.key, {
        algorithms: ["HS256"],
        issuer: this.iss,
        currentDate: new Date(this.now() * 1000),
      });
    } catch (err) {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        `HmacAttestor: ${(err as Error).message}`,
      );
    }
    return validateClaims(result.payload, this.iss, agentDid);
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
  }

  async verify(jwt: string, agentDid: Did): Promise<AttestationClaims> {
    let result: JWTVerifyResult;
    try {
      result = await jwtVerify(jwt, this.jwks, {
        algorithms: this.algorithms as string[],
        issuer: this.iss,
        currentDate: new Date(this.now() * 1000),
      });
    } catch (err) {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        `JwksAttestor: ${(err as Error).message}`,
      );
    }
    return validateClaims(result.payload, this.iss, agentDid);
  }
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

  async verify(jwt: string, agentDid: Did): Promise<AttestationClaims> {
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
    return attestor.verify(jwt, agentDid);
  }
}

function validateClaims(payload: unknown, iss: string, agentDid: Did): AttestationClaims {
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
  return p as AttestationClaims;
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
   * Optional DID resolver. Defaults to a `did:key`-only resolver
   * (preserves v0.1 reference-impl behaviour). Supply a
   * `CompositeDidResolver({ key: …, web: new DidWebResolver(…) })` to
   * also accept `did:web` keyids.
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
    // v0.1 reference behaviour: did:key only. Callers that want
    // did:web pass a CompositeDidResolver({ key: …, web: … }).
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

    // Content digest (when body is present).
    let contentDigest: string | undefined;
    if (covered.includes("content-digest")) {
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
   */
  private async enforceAttestationOnSignup(
    req: Request,
    agentDid: Did,
  ): Promise<void> {
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
      await this.attestor.verify(header, agentDid);
    }
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

    let account = await this.accounts.get(verified.agentDid);
    if (!account) {
      if (!this.implicitSignup) {
        throw new AFAuthError("unknown_account", 404, "account does not exist (implicit signup disabled)");
      }
      account = await this.accounts.createUnclaimed(verified.agentDid);
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
    await this.accounts.setPendingInvitation(verified.agentDid, recipient, token, expiresAt);

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
        account_did: updated.did,
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

    const account = await this.accounts.get(verified.agentDid);
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
    // M3 scope: pre-claim rotation only. §8.2 (post-claim with owner
    // confirmation) is a separate ceremony tracked for later.
    if (account.state === "CLAIMED") {
      throw new AFAuthError(
        "owner_authentication_required",
        403,
        "post-claim key rotation (§8.2) requires owner confirmation and is not implemented in v0.1",
      );
    }

    const rotatedAt = new Date().toISOString();
    await this.accounts.rotateKey(verified.agentDid, newDid, rotatedAt);
    // §8.3: register the old DID on the local revocation list so
    // subsequent requests signed by the old key are rejected.
    await this.revocationList.add(verified.agentDid, rotatedAt);

    return jsonResponse(
      {
        account_did: newDid,
        old_revoked_at: rotatedAt,
      },
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
  async revoke(did: Did): Promise<void> {
    const account = await this.accounts.get(did);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${did} not found`);
    }
    const revokedAt = new Date().toISOString();
    await this.accounts.revoke(did, revokedAt);
    await this.revocationList.add(did, revokedAt);
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

    let account = await this.accounts.get(verified.agentDid);
    if (!account) {
      if (!this.implicitSignup) {
        throw new AFAuthError("unknown_account", 404, "account does not exist (implicit signup disabled)");
      }
      // §9.2: enforce attested_only mode (and validate any present
      // header in lax mode) BEFORE creating the account row. A
      // rejected attestation MUST NOT leave a side-effect.
      await this.enforceAttestationOnSignup(req, verified.agentDid);
      // Implicit signup also goes through the `accounts` rate-limit
      // bucket since it creates an account row.
      await this.enforceRateLimit("accounts", verified.agentDid);
      account = await this.accounts.createUnclaimed(verified.agentDid);
    }

    // §7.2 / §13.2: agent-signed responses MUST NOT expose pending fields.
    const disc = await this.resolveDiscovery();
    const body: Record<string, unknown> = {
      account_did: account.did,
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
