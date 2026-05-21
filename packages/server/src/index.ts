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
  get(did: Did): Promise<Account | null>;
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

// ---------- Verifier (§5.5) ----------

export interface VerifierOptions {
  nonceStore: NonceStore;
  serviceDid: Did;
  /** Default: 5. */
  clockSkewSeconds?: number;
  /** Default: 300. Max allowed `expires - created`. */
  maxSignatureLifetimeSeconds?: number;
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
  private readonly clockSkew: number;
  private readonly maxLifetime: number;
  private readonly now: () => number;

  constructor(opts: VerifierOptions) {
    this.nonceStore = opts.nonceStore;
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

export class Server {
  constructor(_opts: ServerOptions) {
    // M1: skeleton — endpoint handlers land in M2/M3.
  }

  async handleDiscovery(_req: Request): Promise<Response> {
    throw new AFAuthError("malformed_request", 500, "Server.handleDiscovery not implemented");
  }

  async handleOwnerInvitation(_req: Request): Promise<Response> {
    throw new AFAuthError("malformed_request", 500, "Server.handleOwnerInvitation not implemented");
  }

  async handleClaimCompletion(_req: Request, _session: OwnerSession): Promise<Response> {
    throw new AFAuthError("malformed_request", 500, "Server.handleClaimCompletion not implemented");
  }

  async handleKeyRotation(_req: Request): Promise<Response> {
    throw new AFAuthError("malformed_request", 500, "Server.handleKeyRotation not implemented");
  }

  async handleAccountIntrospection(_req: Request): Promise<Response> {
    throw new AFAuthError("malformed_request", 500, "Server.handleAccountIntrospection not implemented");
  }
}
