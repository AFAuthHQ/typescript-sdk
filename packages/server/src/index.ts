/**
 * @afauth/server — Server SDK for the AFAuth Protocol.
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
} from "@afauth/core";

// Re-export DiscoveryDocument so server consumers don't need to also
// import from @afauth/core for this type.
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
 * `@afauth/worker`'s `KvNonceStore`).
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
 * Single-process in-memory implementation of `AccountStore`. Suitable
 * for tests and small examples; production deployments should use a
 * durable backend (e.g. a KV-backed implementation).
 */
export class MemoryAccountStore implements AccountStore {
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
    const fresh: Account = { did, state: "UNCLAIMED" };
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
// verification method, cache, return. It lives in @afauth/server (not
// @afauth/core) because it needs HTTP fetch; @afauth/core stays
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
  body: string | null;
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
    body: string | null;
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
   * session evidences. Required by §7.5's freshness floor for
   * owner-binding operations; optional on the type for backward
   * compatibility with claim-completion sessions, which are
   * exempt (§7.5 applies post-claim only).
   *
   * Use `assertFreshOwnerSession` to enforce the freshness window
   * before authorising an owner-binding operation.
   */
  authenticatedAt?: string;
}

/**
 * §7.5 freshness check. Throws `AFAuthError("owner_session_too_stale",
 * 403, …)` if `session.authenticatedAt` is missing or older than
 * `maxAgeSeconds` relative to `now`.
 *
 * Use in service-defined owner-binding routes (revoke owner credential,
 * link federated identity, add recovery contact, etc.) before invoking
 * the underlying storage mutation. §7.5 mandates 60–300s as the
 * recommended window; the SDK does not pin a default — callers must
 * pick the freshness their threat model warrants.
 *
 * Example:
 *
 *   // POST /admin/revoke (service route — not signed by an agent)
 *   const session = await myAuthLayer.extractOwnerSession(req);
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

// DiscoveryDocument is defined in @afauth/core (single source of truth)
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
    const body = await req.text();
    const verified = await this.verifier.verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: body === "" ? null : body,
    });

    let parsed: { recipient?: Recipient; email?: string; redirect_url?: string };
    try {
      parsed = JSON.parse(body) as typeof parsed;
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
    const body = await req.text();
    // Verify the request was signed by the agent's *current* key. If
    // that key was already revoked, the verifier rejects here.
    const verified = await this.verifier.verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: body === "" ? null : body,
    });

    let parsed: { new_account_did?: string };
    try {
      parsed = JSON.parse(body) as typeof parsed;
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

    let account = await this.accounts.get(verified.agentDid);
    if (!account) {
      if (!this.implicitSignup) {
        throw new AFAuthError("unknown_account", 404, "account does not exist (implicit signup disabled)");
      }
      account = await this.accounts.createUnclaimed(verified.agentDid);
    }

    // §7.2 / §13.2: agent-signed responses MUST NOT expose pending fields.
    const body: Record<string, unknown> = {
      account_did: account.did,
      state: account.state,
    };
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
