/**
 * AFAP-0006 — `afauth-trust` client used from the agent side.
 *
 * Two responsibilities:
 *
 *   1. Bind the agent's account DID to a human-controlled account at
 *      a trust attestor (default trust.afauth.org). The agent calls
 *      `linkStart()` to obtain a deep-link URL it surfaces to the
 *      human (in a chat, in a terminal, as a QR code). After the
 *      human confirms in their browser, `linkPoll()` returns the
 *      long-lived binding token.
 *
 *   2. Mint short-lived, audience-bound §10 attestation JWTs by
 *      calling `token(serviceDid)`. The mint request is signed per §5
 *      with the agent's account key (§3.1 keyless mint) — the keypair is
 *      the sole credential and no bearer token is sent. Minted JWTs are
 *      cached in memory by audience and refreshed near TTL.
 *
 * The agent's Ed25519 keypair is therefore the only secret to persist
 * (the AFAuth CLI stores it under `~/.afauth/` with chmod 600). The
 * `binding` record returned by `linkPoll()` carries only the binding id
 * and its expiry — there is no bearer token. It records that the agent
 * has linked; `token()` authenticates each mint by signing with the key.
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
} from "@afauthhq/core";

export const AFAUTH_TRUST_DEFAULT_BASE = "https://trust.afauth.org" as const;

export interface TrustLinkStart {
  /** Echoed from the server; used by the poll loop. */
  req_id: string;
  /** Show this URL to the human. They visit it in a browser. */
  link_url: string;
  /** Endpoint the agent polls until state becomes "confirmed". */
  poll_url: string;
  /** Seconds until the link request expires. Currently 1800 (30 minutes). */
  expires_in: number;
}

export interface TrustBinding {
  binding_id: string;
  /**
   * Unix seconds when the binding lapses if left unused. The attestor
   * re-arms this on every successful mint (the inactivity window), and
   * token() refreshes this field from the mint response — so an
   * actively-minting agent's binding does not expire. There is no bearer
   * token: the agent authenticates mints by signing `/v1/token` with its
   * account key (§3.1 keyless mint).
   */
  binding_token_expires_at: number;
}

export interface TrustToken {
  /** §10 attestation JWT to send as `AFAuth-Attestation: <jwt>`. */
  jwt: string;
  expires_at: number;
  verification: "email" | "oauth" | "payment";
  /**
   * The attestor's issuer identifier (`iss`), decoded from `jwt`. This is
   * exactly what a service lists in `billing.accepted_attestors` (§4.4), so
   * compare against it before sending — see `assertAttestorAccepted` or
   * `AttestedFetcher`'s `acceptedAttestors`. Undefined only when the JWT
   * payload can't be parsed.
   */
  iss?: string;
  /**
   * Unix seconds when the binding lapses if left unused, as re-armed by
   * this mint (the inactivity window). Present from attestors that slide
   * binding expiry on use; absent from older servers. When present,
   * token() refreshes the client's binding expiry from it.
   */
  binding_expires_at?: number;
}

export interface TrustClientOptions {
  /** Defaults to https://trust.afauth.org. Override for staging/local. */
  baseUrl?: string;
  /** A persisted binding from a previous run. Required for token(). */
  binding?: TrustBinding;
  /** Override the agent keypair. Defaults to a fresh random pair. */
  agentDid?: Did;
  agentPublicKey?: Uint8Array;
  agentPrivateKey?: Ed25519PrivateKey;
  /** Optional fetch override — useful for tests. Defaults to global fetch. */
  fetch?: typeof globalThis.fetch;
  /** Test seam for the clock. */
  now?: () => number;
}

interface CachedToken {
  jwt: string;
  expires_at: number;
  verification: TrustToken["verification"];
  iss?: string;
}

export class TrustClient {
  readonly baseUrl: string;
  readonly agentDid: Did;
  readonly agentPublicKey: Uint8Array;
  private readonly agentPrivateKey: Ed25519PrivateKey;
  private binding: TrustBinding | undefined;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly now: () => number;
  private cache = new Map<string, CachedToken>();

  constructor(opts: TrustClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? AFAUTH_TRUST_DEFAULT_BASE).replace(/\/$/, "");
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));

    if (opts.agentDid && opts.agentPublicKey && opts.agentPrivateKey) {
      this.agentDid = opts.agentDid;
      this.agentPublicKey = opts.agentPublicKey;
      this.agentPrivateKey = opts.agentPrivateKey;
    } else if (opts.agentDid || opts.agentPublicKey || opts.agentPrivateKey) {
      throw new Error(
        "TrustClient: agentDid, agentPublicKey, agentPrivateKey must be set together",
      );
    } else {
      const { secretKey, publicKey } = ed25519.keygen();
      this.agentPrivateKey = secretKey;
      this.agentPublicKey = publicKey;
      this.agentDid = encodeDidKey(publicKey);
    }

    this.binding = opts.binding;
  }

  /** True if a binding token has been received from /v1/link/poll. */
  isLinked(): boolean {
    return this.binding !== undefined && this.binding.binding_token_expires_at > this.now();
  }

  getBinding(): TrustBinding | undefined {
    return this.binding;
  }

  /**
   * Step 1 of the deep-link flow. Returns the URL to show to the
   * human and the polling endpoint the agent will hit afterward.
   */
  async linkStart(opts: { label?: string; callbackUrl?: string } = {}): Promise<TrustLinkStart> {
    const body = await this.postJson("/v1/link/start", {
      agent_did: this.agentDid,
      agent_pubkey_b64: bytesToBase64Url(this.agentPublicKey),
      ...(opts.label ? { agent_label: opts.label } : {}),
      ...(opts.callbackUrl ? { callback_url: opts.callbackUrl } : {}),
    });
    return body as TrustLinkStart;
  }

  /**
   * Step 2. Poll until the human confirms or the request expires.
   * Returns the binding (persist it!) on confirm, undefined while pending.
   *
   * For headless usage, call in a loop with backoff; for desktop
   * agents, consider wiring a loopback callback instead and polling
   * once after the callback fires.
   */
  async linkPoll(reqId: string): Promise<TrustBinding | undefined> {
    const message = new TextEncoder().encode(reqId);
    const sig = ed25519.sign(message, this.agentPrivateKey);
    const body = (await this.postJson("/v1/link/poll", {
      req_id: reqId,
      sig_b64: bytesToBase64Url(sig),
    })) as { state: "pending" } | ({ state: "confirmed" } & TrustBinding);
    if (body.state === "pending") return undefined;
    this.binding = {
      binding_id: body.binding_id,
      binding_token_expires_at: body.binding_token_expires_at,
    };
    return this.binding;
  }

  /**
   * Mint a §10 attestation JWT for `serviceDid`. The mint request is
   * signed per §5 with the agent key (§3.1 keyless mint); no bearer token
   * is sent. Cached in-memory by audience and refreshed near TTL.
   *
   * The agent signs `${baseUrl}/v1/token`, which MUST equal the
   * attestor's configured public base URL (the default
   * `https://trust.afauth.org` matches out of the box).
   */
  async token(serviceDid: string): Promise<TrustToken> {
    if (!this.binding) {
      throw new AFAuthError(
        "invalid_attestation",
        401,
        "TrustClient: not linked — run linkStart()/linkPoll() first or pass `binding` to the constructor",
      );
    }

    // Return cached if it still has comfortably more than 60 seconds.
    // Trust attestor JWTs cap at 900s, so a 60s floor leaves plenty
    // of room for the request to traverse the network and be verified
    // by the receiving service.
    const cached = this.cache.get(serviceDid);
    if (cached && cached.expires_at - this.now() > 60) {
      return {
        jwt: cached.jwt,
        expires_at: cached.expires_at,
        verification: cached.verification,
        iss: cached.iss,
      };
    }

    const path = "/v1/token";
    const url = `${this.baseUrl}${path}`;
    const bodyStr = JSON.stringify({ aud: serviceDid });
    const r = await this.fetchImpl(url, {
      method: "POST",
      headers: this.signMintHeaders(url, bodyStr),
      body: bodyStr,
    });
    await this.ensureOk(r, path);
    const body = (await r.json()) as TrustToken;
    // The attestor's /v1/token response carries no `iss`; decode it from the
    // minted JWT so callers can reconcile against a service's
    // accepted_attestors (§4.4) before sending. Never a trust decision.
    body.iss = attestationIssuer(body.jwt);
    this.cache.set(serviceDid, { ...body });
    // The attestor re-arms the binding's expiry on each mint (inactivity
    // window). Refresh our cached binding so isLinked() — and anything the
    // caller persists from getBinding() — tracks the live expiry instead
    // of the link-time deadline. Guarded so an older server (no field) is
    // a no-op.
    if (this.binding && typeof body.binding_expires_at === "number") {
      this.binding.binding_token_expires_at = body.binding_expires_at;
    }
    return body;
  }

  /**
   * Builds the §5 (RFC 9421) signed headers for a `/v1/token` mint POST,
   * signed with the agent's account key. Covers `@method`, `@target-uri`,
   * and `content-digest`; `keyid` is the agent DID.
   */
  private signMintHeaders(url: string, bodyStr: string): Record<string, string> {
    const created = this.now();
    const expires = created + 60;
    const nonce = randomHex(16);
    const contentDigest = sha256ContentDigest(bodyStr);
    const covered: readonly CoveredComponent[] = ["@method", "@target-uri", "content-digest"];
    const canonicalInput = buildCanonicalInput(
      { method: "POST", targetUri: url, contentDigest },
      { created, expires, nonce, keyid: this.agentDid, alg: "ed25519" },
      covered,
    );
    const sig = ed25519.sign(new TextEncoder().encode(canonicalInput), this.agentPrivateKey);
    const componentList = covered.map((c) => `"${c}"`).join(" ");
    return {
      "content-type": "application/json",
      "content-digest": contentDigest,
      "signature-input":
        `sig1=(${componentList});created=${created};expires=${expires};` +
        `nonce="${nonce}";keyid="${this.agentDid}";alg="ed25519"`,
      signature: `sig1=:${bytesToBase64(sig)}:`,
    };
  }

  /** Forget the cached token for a specific audience (or all). */
  clearTokenCache(serviceDid?: string): void {
    if (serviceDid) this.cache.delete(serviceDid);
    else this.cache.clear();
  }

  // -------------------------------------------------------------------

  private async postJson(path: string, payload: unknown): Promise<unknown> {
    const r = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    await this.ensureOk(r, path);
    return r.json();
  }

  /**
   * Throw a `TrustHttpError` (preserving the upstream error code) when
   * `r` is not 2xx. Shared by `postJson` and the signed `token()` flow.
   */
  private async ensureOk(r: Response, path: string): Promise<void> {
    if (r.ok) return;
    let upstreamCode: string | undefined;
    let detail = `${r.status} ${r.statusText}`;
    try {
      const j = await r.json();
      if (j && typeof j === "object" && "error" in j) {
        const err = (j as { error?: { code?: string; message?: string } }).error;
        if (err) {
          upstreamCode = err.code;
          detail = `${err.code ?? "error"}: ${err.message ?? detail}`;
        }
      }
    } catch {
      // Ignore body-parse errors and keep the status line.
    }
    throw new TrustHttpError(`trust ${path} failed: ${detail}`, r.status, upstreamCode);
  }
}

/**
 * Surface trust-attestor HTTP failures with the upstream error code
 * intact so callers can distinguish, for example, `binding_expired`
 * ("re-link the agent") from `binding_revoked` ("ask the human") from
 * `verification_required` ("send the human to upgrade their account"), or
 * `service_suspended` ("the owner revoked this service for this agent").
 *
 * Falls back to `invalid_attestation` for compatibility with the core
 * AFAuthError taxonomy when no upstream code is available.
 */
export class TrustHttpError extends AFAuthError {
  /** The trust attestor's error code, e.g. "binding_expired". */
  readonly upstreamCode: string | undefined;

  constructor(message: string, status: number, upstreamCode?: string) {
    super("invalid_attestation", status, message);
    this.name = "TrustHttpError";
    this.upstreamCode = upstreamCode;
  }

  isBindingExpired(): boolean {
    return this.upstreamCode === "binding_expired";
  }
  isBindingRevoked(): boolean {
    return this.upstreamCode === "binding_revoked";
  }
  isVerificationRequired(): boolean {
    return this.upstreamCode === "verification_required";
  }
  /**
   * §10.3.1 — the human owner has revoked minting for this (agent DID,
   * service) pair from trust.afauth.org/account. Terminal for this `aud`:
   * the agent MUST NOT retry until the owner restores it. Other services are
   * unaffected, so the caller can keep using the agent elsewhere.
   */
  isServiceSuspended(): boolean {
    return this.upstreamCode === "service_suspended";
  }
}

/**
 * Decode the `iss` (attestor identifier) from a JWT payload WITHOUT
 * verifying its signature. Used only to learn which attestor minted a
 * token — for §4.4 reconciliation against a service's accepted_attestors —
 * never as a trust decision. Returns undefined when the token can't be
 * parsed.
 */
export function attestationIssuer(jwt: string): string | undefined {
  const payload = jwt.split(".")[1];
  if (!payload) return undefined;
  try {
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
    const claims = JSON.parse(atob(padded)) as { iss?: unknown };
    return typeof claims.iss === "string" ? claims.iss : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Thrown when a minted attestation's issuer isn't in a service's §4.4
 * `billing.accepted_attestors`. Surfaced BEFORE the attestation is sent so
 * the agent gets an actionable error instead of an opaque server rejection.
 * Carries `issuer` and `accepted` for programmatic handling.
 */
export class AttestorNotAcceptedError extends Error {
  constructor(
    readonly issuer: string,
    readonly accepted: readonly string[],
  ) {
    super(
      `attestor "${issuer}" is not accepted by this service ` +
        `(it accepts: ${accepted.join(", ") || "none"}). ` +
        `Link this agent to an accepted attestor — e.g. ` +
        `new TrustClient({ baseUrl }) pointed at one — or ask the service ` +
        `to add "${issuer}" to billing.accepted_attestors.`,
    );
    this.name = "AttestorNotAcceptedError";
  }
}

/**
 * Reconcile a minted token against a service's `accepted_attestors` (§4.4).
 * No-op when the service didn't constrain attestors (empty/undefined list)
 * or the issuer can't be determined; throws {@link AttestorNotAcceptedError}
 * on a known mismatch. Pass the discovery doc's `billing.accepted_attestors`.
 */
export function assertAttestorAccepted(
  token: { jwt: string; iss?: string },
  acceptedAttestors: readonly string[] | undefined,
): void {
  if (!acceptedAttestors || acceptedAttestors.length === 0) return;
  const iss = token.iss ?? attestationIssuer(token.jwt);
  if (iss && !acceptedAttestors.includes(iss)) {
    throw new AttestorNotAcceptedError(iss, acceptedAttestors);
  }
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/** Standard base64 (with padding) — the encoding RFC 9421 uses in the `Signature` header. */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function randomHex(byteLen: number): string {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
