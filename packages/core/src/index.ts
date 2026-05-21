/**
 * @afauth/core — shared primitives for the AFAuth Protocol.
 *
 * Types, codec, canonicalisation, content-digest, and error envelope.
 * The other three SDK packages (`@afauth/agent`, `@afauth/server`,
 * `@afauth/worker`) depend on this module so the canonicalisation rule
 * and error shape stay aligned across the SDK.
 */

import { sha256 } from "@noble/hashes/sha2.js";

// ---------- Identifiers (§3) ----------

/** A W3C DID. v0.1 supports `did:key:...` only; `did:web:...` recognised in types. */
export type Did = string;

/** Raw 32-byte Ed25519 public key. */
export type Ed25519PublicKey = Uint8Array;

/** Raw 32-byte Ed25519 seed (private key material). */
export type Ed25519PrivateKey = Uint8Array;

// ---------- did:key codec (§3.1.1) ----------

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_INDEX = new Map<string, number>();
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_INDEX.set(BASE58_ALPHABET[i]!, i);
}

function base58btcEncode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);

  let leadingZeros = 0;
  for (const b of bytes) {
    if (b === 0) leadingZeros++;
    else break;
  }

  let body = "";
  while (n > 0n) {
    const rem = Number(n % 58n);
    n /= 58n;
    body = BASE58_ALPHABET[rem]! + body;
  }
  return "1".repeat(leadingZeros) + body;
}

function base58btcDecode(str: string): Uint8Array {
  let n = 0n;
  for (const ch of str) {
    const v = BASE58_INDEX.get(ch);
    if (v === undefined) {
      throw new AFAuthError("malformed_request", 400, `invalid base58 character: ${ch}`);
    }
    n = n * 58n + BigInt(v);
  }

  let leadingZeros = 0;
  for (const ch of str) {
    if (ch === "1") leadingZeros++;
    else break;
  }

  // Convert bigint to bytes (big-endian).
  const bodyBytes: number[] = [];
  while (n > 0n) {
    bodyBytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  const out = new Uint8Array(leadingZeros + bodyBytes.length);
  for (let i = 0; i < bodyBytes.length; i++) out[leadingZeros + i] = bodyBytes[i]!;
  return out;
}

// Multicodec varint for ed25519-pub = 0xed 0x01 (two bytes).
const ED25519_PUB_VARINT = new Uint8Array([0xed, 0x01]);

/** Encode a 32-byte Ed25519 public key as `did:key:z6Mk...`. */
export function encodeDidKey(publicKey: Ed25519PublicKey): Did {
  if (publicKey.length !== 32) {
    throw new AFAuthError(
      "malformed_request",
      400,
      `Ed25519 public key must be 32 bytes, got ${publicKey.length}`,
    );
  }
  const buf = new Uint8Array(2 + 32);
  buf.set(ED25519_PUB_VARINT, 0);
  buf.set(publicKey, 2);
  return `did:key:z${base58btcEncode(buf)}`;
}

/** Decode a `did:key:z...` to its 32-byte Ed25519 public key. */
export function decodeDidKey(did: Did): Ed25519PublicKey {
  if (!did.startsWith("did:key:z")) {
    throw new AFAuthError("malformed_request", 400, `not a did:key:z... value: ${did}`);
  }
  const decoded = base58btcDecode(did.slice("did:key:z".length));
  if (decoded.length < 2) {
    throw new AFAuthError("malformed_request", 400, "did:key payload too short");
  }
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new AFAuthError(
      "malformed_request",
      400,
      `unsupported multicodec prefix: 0x${decoded[0]!.toString(16)}${decoded[1]!.toString(16)} (only ed25519-pub 0xed01 in v0.1)`,
    );
  }
  const pubKey = decoded.slice(2);
  if (pubKey.length !== 32) {
    throw new AFAuthError(
      "malformed_request",
      400,
      `Ed25519 public key must be 32 bytes, got ${pubKey.length}`,
    );
  }
  return pubKey;
}

// ---------- Recipient registry (§7.7) ----------

/**
 * Wire format for each recipient type. The shape matches spec §7.7
 * exactly — the SDK does not translate between an internal type and
 * the wire format. See vendored vectors under
 * `vendor/spec-vectors/signatures/post-owner-invitation-*.json`.
 */
export type Recipient =
  | { type: "email"; value: string }
  | { type: "phone"; value: string }
  | { type: "oidc"; value: { issuer: string; sub: string } }
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

/**
 * Builds the RFC 9421 canonical signature input — byte-exact, no
 * trailing newline. Matches `harness/run.js#buildCanonicalInput` in
 * the spec repo; any drift fails the conformance suite.
 */
export function buildCanonicalInput(
  req: CanonicalRequest,
  params: SignatureParams,
  covered: readonly CoveredComponent[],
): string {
  const lines: string[] = [];
  for (const component of covered) {
    if (component === "@method") {
      lines.push(`"@method": ${req.method}`);
    } else if (component === "@target-uri") {
      lines.push(`"@target-uri": ${req.targetUri}`);
    } else if (component === "content-digest") {
      if (req.contentDigest === undefined) {
        throw new AFAuthError(
          "malformed_request",
          400,
          `covered components include content-digest but no contentDigest on request`,
        );
      }
      lines.push(`"content-digest": ${req.contentDigest}`);
    }
  }
  const componentList = covered.map((c) => `"${c}"`).join(" ");
  const paramStr =
    `created=${params.created};` +
    `expires=${params.expires};` +
    `nonce="${params.nonce}";` +
    `keyid="${params.keyid}";` +
    `alg="${params.alg}"`;
  lines.push(`"@signature-params": (${componentList});${paramStr}`);
  return lines.join("\n");
}

// ---------- Content digest (RFC 9530 §2) ----------

function bytesToBase64(bytes: Uint8Array): string {
  // Universal — works in Node ≥16, Cloudflare Workers, Deno, browsers.
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Computes the `Content-Digest` header value `'sha-256=:<base64>:'`. */
export function sha256ContentDigest(body: string | Uint8Array): string {
  const bytes = typeof body === "string" ? new TextEncoder().encode(body) : body;
  const hash = sha256(bytes);
  return `sha-256=:${bytesToBase64(hash)}:`;
}

// ---------- Discovery document (§4) ----------

/**
 * v0.1 `/.well-known/afauth` document shape. Lives in `core` so the
 * agent (which fetches it) and the server (which serves and consults
 * it) share the same definition — duplicate types previously lived in
 * both packages and risked drift.
 */
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

// ---------- Invitation IDs (§7.2) ----------

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Derives the public `invitation_id` from the secret claim token.
 * The id is `"inv_" + base64url(sha256(token)[0:12])`. The forward
 * direction is deterministic; the reverse direction requires
 * inverting SHA-256, so leaking the id does not leak the token.
 *
 * Use this whenever the service returns an `invitation_id` to the
 * agent — never return the raw token, which is the secret carried
 * by the magic link.
 */
export function deriveInvitationId(token: string): string {
  const hash = sha256(new TextEncoder().encode(token));
  return `inv_${bytesToBase64Url(hash.slice(0, 12))}`;
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
