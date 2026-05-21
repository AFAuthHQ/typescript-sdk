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
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import {
  AFAuthError,
  buildCanonicalInput,
  encodeDidKey,
  sha256ContentDigest,
  type CoveredComponent,
  type Did,
  type Ed25519PrivateKey,
  type Ed25519PublicKey,
  type Recipient,
} from "@afauth/core";

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
  /** Override the clock — useful only for tests. Defaults to `Date.now()/1000`. */
  now?: () => number;
}

function randomHexBytes(byteLen: number): string {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export class Agent {
  readonly did: Did;
  readonly publicKey: Ed25519PublicKey;
  private readonly secretKey: Ed25519PrivateKey;

  private constructor(did: Did, publicKey: Ed25519PublicKey, secretKey: Ed25519PrivateKey) {
    this.did = did;
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }

  /** Fresh random keypair. */
  static async generate(): Promise<Agent> {
    const { secretKey, publicKey } = ed25519.keygen();
    return new Agent(encodeDidKey(publicKey), publicKey, secretKey);
  }

  /** Restore from a 32-byte private key (raw seed). */
  static async fromPrivateKey(privateKey: Ed25519PrivateKey): Promise<Agent> {
    if (privateKey.length !== 32) {
      throw new AFAuthError(
        "malformed_request",
        400,
        `Ed25519 seed must be 32 bytes, got ${privateKey.length}`,
      );
    }
    const publicKey = ed25519.getPublicKey(privateKey);
    return new Agent(encodeDidKey(publicKey), publicKey, privateKey);
  }

  /**
   * Lower-level escape hatch: sign any AFAuth request. Defaults match
   * the spec — see ADR-0004.
   */
  async signRequest(
    req: { method: string; url: string; body?: string | null },
    opts: SignOptions = {},
  ): Promise<SignedRequest> {
    const body = req.body ?? null;
    const hasBody = body !== null && body !== "";

    const covered: readonly CoveredComponent[] =
      opts.coveredComponents ??
      (hasBody
        ? (["@method", "@target-uri", "content-digest"] as const)
        : (["@method", "@target-uri"] as const));

    const expiresIn = opts.expiresInSeconds ?? 60;
    const now = opts.now ? opts.now() : Math.floor(Date.now() / 1000);
    const created = now;
    const expires = now + expiresIn;
    const nonce = opts.nonce ?? randomHexBytes(16);

    const contentDigest = hasBody ? sha256ContentDigest(body) : undefined;

    if (covered.includes("content-digest") && contentDigest === undefined) {
      throw new AFAuthError(
        "malformed_request",
        400,
        "coveredComponents includes content-digest but request has no body",
      );
    }

    const params = {
      created,
      expires,
      nonce,
      keyid: this.did,
      alg: "ed25519" as const,
    };

    const canonicalInput = buildCanonicalInput(
      {
        method: req.method,
        targetUri: req.url,
        ...(contentDigest ? { contentDigest } : {}),
      },
      params,
      covered,
    );

    const sigBytes = ed25519.sign(new TextEncoder().encode(canonicalInput), this.secretKey);

    const componentList = covered.map((c) => `"${c}"`).join(" ");
    const signatureInput =
      `sig1=(${componentList});` +
      `created=${created};expires=${expires};` +
      `nonce="${nonce}";keyid="${this.did}";alg="ed25519"`;

    const headers: Record<string, string> = {
      "signature-input": signatureInput,
      signature: `sig1=:${bytesToBase64(sigBytes)}:`,
    };
    if (contentDigest) {
      headers["content-digest"] = contentDigest;
      headers["content-type"] = "application/json";
    }

    return { method: req.method, url: req.url, headers, body };
  }

  // ---------- High-level builders for protocol endpoints ----------

  async buildOwnerInvitation(opts: {
    baseUrl: string;
    recipient: Recipient;
    redirectUrl?: string;
  }): Promise<SignedRequest> {
    const url = `${trimTrailing(opts.baseUrl)}/afauth/v1/accounts/me/owner-invitation`;
    const bodyObj: { recipient: Recipient; redirect_url?: string } = {
      recipient: opts.recipient,
    };
    if (opts.redirectUrl) bodyObj.redirect_url = opts.redirectUrl;
    return this.signRequest({ method: "POST", url, body: JSON.stringify(bodyObj) });
  }

  async buildKeyRotation(opts: { baseUrl: string; newDid: Did }): Promise<SignedRequest> {
    const url = `${trimTrailing(opts.baseUrl)}/afauth/v1/accounts/me/keys/rotate`;
    return this.signRequest({
      method: "POST",
      url,
      body: JSON.stringify({ new_account_did: opts.newDid }),
    });
  }

  async buildAccountIntrospection(opts: { baseUrl: string }): Promise<SignedRequest> {
    const url = `${trimTrailing(opts.baseUrl)}/afauth/v1/accounts/me`;
    return this.signRequest({ method: "GET", url });
  }

  /** Export the raw seed — for keypair persistence. Treat as secret material. */
  exportPrivateKey(): Ed25519PrivateKey {
    return this.secretKey.slice();
  }

  /** Hex form of the raw public key — useful for diagnostics. */
  publicKeyHex(): string {
    return bytesToHex(this.publicKey);
  }
}

function trimTrailing(s: string): string {
  return s.endsWith("/") ? s.slice(0, -1) : s;
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
export async function fetchDiscovery(baseUrl: string): Promise<DiscoveryDocument> {
  const url = `${trimTrailing(baseUrl)}/.well-known/afauth`;
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) {
    throw new AFAuthError(
      "malformed_request",
      res.status,
      `discovery fetch failed: ${res.status} ${res.statusText}`,
    );
  }
  const doc = (await res.json()) as DiscoveryDocument;
  if (doc.afauth_version !== "0.1") {
    throw new AFAuthError(
      "malformed_request",
      400,
      `unsupported afauth_version: ${doc.afauth_version}`,
    );
  }
  return doc;
}
