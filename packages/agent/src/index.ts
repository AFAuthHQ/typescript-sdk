/**
 * @afauth/agent — Agent SDK for the AFAuth Protocol.
 *
 * Provides the `Agent` class for signing requests per RFC 9421 with
 * AFAuth-specific canonical components, plus protocol-aware builders
 * for the owner-invitation (§7.2), key-rotation (§8.1), and
 * account-introspection (§6.5) endpoints.
 *
 * `signRequest` is the lower-level escape hatch with spec-conformant
 * defaults — see ADR-0004.
 *
 * Function bodies throw `not_implemented` in this skeleton.
 */

import {
  AFAuthError,
  type CoveredComponent,
  type Did,
  type Ed25519PrivateKey,
  type Ed25519PublicKey,
  type Recipient,
} from "@afauth/core";

/** A complete request ready to `fetch()` — headers carry the AFAuth signature. */
export interface SignedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
}

export interface SignOptions {
  /** Default: 60. Total signature lifetime (`expires - created`). */
  expiresInSeconds?: number;
  /** Default: 16 random bytes as hex. */
  nonce?: string;
  /**
   * Default: `['@method','@target-uri']` when body is absent, plus
   * `'content-digest'` when body is present.
   */
  coveredComponents?: readonly CoveredComponent[];
}

/**
 * An agent's cryptographic identity. The `did` is the agent's account
 * ID on every AFAuth-enabled service the agent talks to.
 */
export class Agent {
  readonly did: Did;
  readonly publicKey: Ed25519PublicKey;

  private constructor(did: Did, publicKey: Ed25519PublicKey) {
    this.did = did;
    this.publicKey = publicKey;
  }

  /** Fresh random keypair. */
  static async generate(): Promise<Agent> {
    throw new AFAuthError("malformed_request", 500, "Agent.generate not implemented");
  }

  /** Restore from a 32-byte private key (raw seed). */
  static async fromPrivateKey(_privateKey: Ed25519PrivateKey): Promise<Agent> {
    throw new AFAuthError("malformed_request", 500, "Agent.fromPrivateKey not implemented");
  }

  /**
   * Lower-level escape hatch: sign any AFAuth request. Defaults match
   * the spec so callers normally pass no `opts` — see ADR-0004.
   */
  async signRequest(
    _req: { method: string; url: string; body?: string | null },
    _opts?: SignOptions,
  ): Promise<SignedRequest> {
    throw new AFAuthError("malformed_request", 500, "Agent.signRequest not implemented");
  }

  // ---------- High-level builders for protocol endpoints ----------

  async buildOwnerInvitation(_opts: {
    baseUrl: string;
    recipient: Recipient;
    redirectUrl?: string;
  }): Promise<SignedRequest> {
    throw new AFAuthError("malformed_request", 500, "Agent.buildOwnerInvitation not implemented");
  }

  async buildKeyRotation(_opts: {
    baseUrl: string;
    newDid: Did;
  }): Promise<SignedRequest> {
    throw new AFAuthError("malformed_request", 500, "Agent.buildKeyRotation not implemented");
  }

  async buildAccountIntrospection(_opts: { baseUrl: string }): Promise<SignedRequest> {
    throw new AFAuthError("malformed_request", 500, "Agent.buildAccountIntrospection not implemented");
  }
}

// ---------- Discovery (§4) ----------

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

/** Unsigned GET of `/.well-known/afauth`. Validates `afauth_version === '0.1'`. */
export async function fetchDiscovery(_baseUrl: string): Promise<DiscoveryDocument> {
  throw new AFAuthError("malformed_request", 500, "fetchDiscovery not implemented");
}
