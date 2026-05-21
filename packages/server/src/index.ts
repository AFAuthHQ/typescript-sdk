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
 *     (one per spec-defined mutation) per ADR-0004.
 *   - `RecipientHandler`: per-type ceremony hook for §7.7.
 *
 * `Server.handleClaimCompletion` takes an explicit `session` parameter
 * — the human-auth asymmetry is part of the API surface, not a
 * configuration concern. See ADR-0004.
 *
 * Function bodies throw `not_implemented` in this skeleton.
 */

import {
  AFAuthError,
  type Did,
  type Recipient,
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
 * Storage contract for AFAuth accounts. Mutations are exposed as named
 * methods rather than a generic upsert — each carries the atomicity
 * contract required by the spec section it implements. See ADR-0004.
 */
export interface AccountStore {
  get(did: Did): Promise<Account | null>;

  /** Implicit signup (§6.3). Idempotent. */
  createUnclaimed(did: Did): Promise<Account>;

  /**
   * §7.3 atomic invitation: invalidates any prior pending invitation,
   * installs new pending_recipient + token + TTL. Implementation MUST
   * enforce single-invitation-at-a-time at the storage layer.
   */
  setPendingInvitation(
    did: Did,
    recipient: Recipient,
    token: string,
    expiresAt: string,
  ): Promise<Account>;

  /**
   * §7.4 atomic claim: finds by token, verifies the token is unconsumed
   * and unexpired, transitions to CLAIMED, persists owner, clears
   * pending. Returns null if the token was missing, expired, or
   * already consumed.
   */
  completeClaimByToken(
    token: string,
    owner: NonNullable<Account["owner"]>,
  ): Promise<Account | null>;

  /** §8.1 / §8.2 atomic key rotation. */
  rotateKey(oldDid: Did, newDid: Did, rotatedAt: string): Promise<Account>;

  /** §8.4 atomic owner-initiated revocation. */
  revoke(did: Did, revokedAt: string): Promise<Account>;
}

// ---------- Recipient handlers (§7.7) ----------

export interface RecipientHandler<R extends Recipient = Recipient> {
  /** Begin the verification ceremony — email, SMS, OIDC redirect, etc. */
  initiate(opts: {
    recipient: R;
    claimToken: string;
    claimPageUrl: string;
    redirectUrl?: string;
  }): Promise<void>;

  /** Apply the §7.7 match relation between pending and authenticated recipient. */
  matches(opts: { pending: R; authenticated: R }): boolean;
}

// ---------- Verifier (§5.5) ----------

export interface VerifierOptions {
  nonceStore: NonceStore;
  serviceDid: Did;
  /** Default: 5. */
  clockSkewSeconds?: number;
  /** Default: 300. Max allowed `expires - created`. */
  maxSignatureLifetimeSeconds?: number;
}

export interface VerifiedRequest {
  agentDid: Did;
  method: string;
  url: string;
  body: string | null;
}

/**
 * Standalone request verifier. Throws `AFAuthError` on any §5.5/§5.6
 * failure; does not enforce §7.5 (that is a service-policy concern).
 */
export class Verifier {
  constructor(_opts: VerifierOptions) {
    // intentionally empty in skeleton
  }

  async verify(_req: {
    method: string;
    url: string;
    headers: Headers;
    body: string | null;
  }): Promise<VerifiedRequest> {
    throw new AFAuthError("invalid_signature", 401, "Verifier.verify not implemented");
  }
}

// ---------- Server (full endpoint handlers) ----------

// We import this here for use in handleClaimCompletion's signature.
export interface OwnerSession {
  authenticated: Recipient;
  userId: string;
}

// DiscoveryDocument is duplicated from @afauth/agent's exports to avoid
// a cycle. They MUST stay structurally compatible.
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
  recipients: Partial<
    Record<"email" | "phone" | "oidc" | "did", RecipientHandler>
  >;
  /** Either a static discovery doc or a builder that resolves at request time. */
  discovery: DiscoveryDocument | (() => Promise<DiscoveryDocument>);
  /** Used to compose `endpoints.claim_completion` URLs. */
  baseUrl: string;
}

export class Server {
  constructor(_opts: ServerOptions) {
    // intentionally empty in skeleton
  }

  async handleDiscovery(_req: Request): Promise<Response> {
    throw new AFAuthError("malformed_request", 500, "Server.handleDiscovery not implemented");
  }

  async handleOwnerInvitation(_req: Request): Promise<Response> {
    throw new AFAuthError("malformed_request", 500, "Server.handleOwnerInvitation not implemented");
  }

  /**
   * Claim completion (§7.4). Takes an explicit `session` argument
   * because this is the one endpoint that requires human authentication
   * rather than an agent signature — see ADR-0004.
   */
  async handleClaimCompletion(
    _req: Request,
    _session: OwnerSession,
  ): Promise<Response> {
    throw new AFAuthError("malformed_request", 500, "Server.handleClaimCompletion not implemented");
  }

  async handleKeyRotation(_req: Request): Promise<Response> {
    throw new AFAuthError("malformed_request", 500, "Server.handleKeyRotation not implemented");
  }

  async handleAccountIntrospection(_req: Request): Promise<Response> {
    throw new AFAuthError("malformed_request", 500, "Server.handleAccountIntrospection not implemented");
  }
}
