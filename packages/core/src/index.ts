/**
 * @afauth/core — shared primitives for the AFAuth Protocol.
 *
 * Types, codec, canonicalisation, content-digest, and error envelope are
 * defined here. The other three SDK packages (`@afauth/agent`,
 * `@afauth/server`, `@afauth/worker`) all depend on this module so the
 * canonicalisation rule and error shape stay aligned across the SDK.
 *
 * Function bodies throw `not_implemented` in this skeleton — types
 * are stable and match `implementation/sdk-v0.1.d.ts` in the spec repo.
 */

// ---------- Identifiers (§3) ----------

/** A W3C DID. v0.1 supports `did:key:...` only; `did:web:...` recognised in types. */
export type Did = string;

/** Raw 32-byte Ed25519 public key. */
export type Ed25519PublicKey = Uint8Array;

/** Raw 32-byte Ed25519 seed (private key material). */
export type Ed25519PrivateKey = Uint8Array;

// ---------- did:key codec (§3.1.1) ----------

export function encodeDidKey(_publicKey: Ed25519PublicKey): Did {
  throw new AFAuthError("malformed_request", 500, "encodeDidKey not implemented");
}

export function decodeDidKey(_did: Did): Ed25519PublicKey {
  throw new AFAuthError("malformed_request", 500, "decodeDidKey not implemented");
}

// ---------- Recipient registry (§7.7) ----------

export type Recipient =
  | { type: "email"; value: string }
  | { type: "phone"; value: string }
  | { type: "oidc"; issuer: string; subject: string }
  | { type: "did"; value: Did };

// ---------- Signature parameters (§5.2) ----------

export interface SignatureParams {
  created: number;
  expires: number;
  nonce: string;
  keyid: Did;
  alg: "ed25519";
}

export type CoveredComponent = "@method" | "@target-uri" | "content-digest";

// ---------- Canonicalisation (§5.2) ----------

export interface CanonicalRequest {
  method: string;
  targetUri: string;
  contentDigest?: string;
}

export function buildCanonicalInput(
  _req: CanonicalRequest,
  _params: SignatureParams,
  _covered: readonly CoveredComponent[],
): string {
  throw new AFAuthError("malformed_request", 500, "buildCanonicalInput not implemented");
}

export function sha256ContentDigest(_body: string | Uint8Array): string {
  throw new AFAuthError("malformed_request", 500, "sha256ContentDigest not implemented");
}

// ---------- Error envelope (§11) ----------

export type AFAuthErrorCode =
  | "invalid_signature"
  | "expired_signature"
  | "replayed_nonce"
  | "unknown_account"
  | "revoked_key"
  | "invalid_attestation"
  | "attestation_required"
  | "invitation_expired"
  | "invitation_not_found"
  | "already_claimed"
  | "not_claimed"
  | "owner_authentication_required"
  | "owner_binding_blocked"
  | "account_expired"
  | "rate_limit_exceeded"
  | "malformed_request"
  | "unsupported_recipient_type";

export class AFAuthError extends Error {
  readonly code: AFAuthErrorCode;
  readonly status: number;
  readonly details?: unknown;

  constructor(code: AFAuthErrorCode, status: number, message: string, details?: unknown) {
    super(message);
    this.name = "AFAuthError";
    this.code = code;
    this.status = status;
    this.details = details;
  }

  /** Serialises to a §11.1 error envelope Response. */
  toResponse(): Response {
    const body: { error: { code: AFAuthErrorCode; message: string; details?: unknown } } = {
      error: { code: this.code, message: this.message },
    };
    if (this.details !== undefined) body.error.details = this.details;
    return new Response(JSON.stringify(body), {
      status: this.status,
      headers: { "content-type": "application/json" },
    });
  }
}
