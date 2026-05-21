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
  decodeDidKey,
  sha256ContentDigest,
  type CoveredComponent,
  type Did,
  type Recipient,
  type SignatureParams,
} from "@afauth/core";

// ---------- Nonce store (§5.6) ----------

export interface NonceStore {
  /**
   * Inserts (keyid, nonce). Returns `true` if it was new, `false` if a
   * replay. Implementations MUST enforce a TTL ≥ `(expires - created) +
   * clockSkew`.
   */
  seen(keyid: Did, nonce: string, ttlSeconds: number): Promise<boolean>;
}

/** Single-process Map-backed nonce store. Suitable for tests. */
export class MemoryNonceStore implements NonceStore {
  private readonly seenSet = new Map<string, number>();

  async seen(keyid: Did, nonce: string, ttlSeconds: number): Promise<boolean> {
    const key = `${keyid}\x00${nonce}`;
    const now = Math.floor(Date.now() / 1000);
    const existingExpiry = this.seenSet.get(key);
    if (existingExpiry !== undefined && existingExpiry > now) return false;
    this.seenSet.set(key, now + ttlSeconds);
    return true;
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
    // for this DID before installing the new one.
    for (const [existingToken, entry] of this.tokens) {
      if (entry.did === did) this.tokens.delete(existingToken);
    }

    this.tokens.set(token, { did, expiresAt });
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
    // Migrate any pending token references.
    for (const entry of this.tokens.values()) {
      if (entry.did === oldDid) entry.did = newDid;
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
    // §7.7.1: case-insensitive equality per RFC 5321 §2.4.
    return pending.value.toLowerCase() === authenticated.value.toLowerCase();
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

export class Verifier {
  private readonly nonceStore: NonceStore;
  private readonly revocationList: RevocationList | undefined;
  private readonly clockSkew: number;
  private readonly maxLifetime: number;
  private readonly now: () => number;

  constructor(opts: VerifierOptions) {
    this.nonceStore = opts.nonceStore;
    this.revocationList = opts.revocationList;
    this.clockSkew = opts.clockSkewSeconds ?? 5;
    this.maxLifetime = opts.maxSignatureLifetimeSeconds ?? 300;
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
    if (this.revocationList && (await this.revocationList.isRevoked(params.keyid))) {
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
    const publicKey = decodeDidKey(params.keyid);
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
}

export interface DiscoveryDocument {
  afauth_version: "0.1";
  service_did: Did;
  endpoints: {
    accounts: string;
    owner_invitation: string;
    claim_page: string;
    claim_completion: string;
    key_rotation?: string;
  };
  signature_algorithms: readonly "ed25519"[];
  features?: readonly ("attestation" | "key_rotation")[];
  recipient_types?: readonly ("email" | "phone" | "oidc" | "did")[];
  limits?: {
    unclaimed_ttl_seconds?: number;
    unclaimed_rate_limit_per_hour?: number;
  };
  billing?: {
    unclaimed_mode?: string;
    accepted_attestors?: readonly string[];
  };
}

export interface ServerOptions extends VerifierOptions {
  accounts: AccountStore;
  recipients: Partial<Record<"email" | "phone" | "oidc" | "did", RecipientHandler>>;
  discovery: DiscoveryDocument | (() => Promise<DiscoveryDocument>);
  baseUrl: string;
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
  private readonly revocationList: RevocationList | undefined;
  private readonly invitationTtlSeconds: number;

  constructor(opts: ServerOptions) {
    this.verifier = new Verifier(opts);
    this.accounts = opts.accounts;
    this.recipients = opts.recipients;
    this.discovery = opts.discovery;
    this.baseUrl = opts.baseUrl;
    this.revocationList = opts.revocationList;
    this.invitationTtlSeconds = DEFAULT_INVITATION_TTL_SECONDS;
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

    // Implicit signup if the account doesn't yet exist (§6.3).
    let account = await this.accounts.get(verified.agentDid);
    if (!account) {
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
        invitation_id: `inv_${token}`,
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
    await this.revocationList?.add(verified.agentDid, rotatedAt);

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
   * §8.4 scopes owner-initiated revocation to CLAIMED accounts; this
   * method also accepts pre-claim revocations for service-driven
   * abuse handling (the spec does not forbid this).
   */
  async revoke(did: Did): Promise<void> {
    const account = await this.accounts.get(did);
    if (!account) {
      throw new AFAuthError("unknown_account", 404, `account ${did} not found`);
    }
    const revokedAt = new Date().toISOString();
    await this.accounts.revoke(did, revokedAt);
    await this.revocationList?.add(did, revokedAt);
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

    // Implicit signup on first touch (§6.3).
    let account = await this.accounts.get(verified.agentDid);
    if (!account) {
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
