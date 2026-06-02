/**
 * §10.7 attested-session client — the agent side of the
 * refresh-on-challenge loop (the OAuth `401 → refresh → retry` pattern).
 *
 * Wraps an `Agent` (signs every request) and a `TrustClient` (mints
 * audience-bound §10 attestations, cached near TTL). On a service's
 * `401 attestation_required` (§10.7) it mints a fresh attestation and
 * retries the request ONCE with a fresh signature (new nonce). A
 * revoked/expired binding surfaces as a terminal `TrustHttpError`
 * (`isBindingRevoked()` / `isBindingExpired()` → re-link required)
 * rather than an unbounded retry loop.
 *
 * The per-request signature (§5) is always present; the attestation is
 * the additional §10.7 liveness gate, attached only when challenged
 * (reactive, the default) or pre-emptively (`proactive`).
 */

import type { Did } from "@afauthhq/core";
import type { Agent, SignOptions } from "./index.js";
import type { TrustClient } from "./trust.js";

export interface AttestedFetcherOptions {
  /** Signs each request. Its DID MUST equal the TrustClient's agent DID. */
  agent: Agent;
  /** Mints audience-bound attestations for `serviceDid` (cached near TTL). */
  trust: TrustClient;
  /** The service's DID — both the attestation `aud` and the mint target. */
  serviceDid: Did;
  /** `fetch` override (tests / custom transports). Defaults to global fetch. */
  fetch?: typeof globalThis.fetch;
  /**
   * Attach a fresh attestation on the FIRST attempt instead of waiting
   * for a challenge — avoids the extra round-trip at each window
   * boundary, at the cost of sending the header on more requests.
   * Default `false` (reactive, the §10.7 baseline).
   */
  proactive?: boolean;
}

export class AttestedFetcher {
  private readonly agent: Agent;
  private readonly trust: TrustClient;
  private readonly serviceDid: Did;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly proactive: boolean;

  constructor(opts: AttestedFetcherOptions) {
    if (opts.trust.agentDid !== opts.agent.did) {
      throw new Error(
        "AttestedFetcher: agent.did and trust.agentDid must be the same key — " +
          "the attestation `sub` must match the request signer (§10.2).",
      );
    }
    this.agent = opts.agent;
    this.trust = opts.trust;
    this.serviceDid = opts.serviceDid;
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.proactive = opts.proactive ?? false;
  }

  /**
   * Send a signed request to the service, handling a §10.7 challenge.
   * Returns the service's `Response`. On `401 attestation_required` it
   * mints a fresh attestation and retries ONCE with a freshly-signed
   * request (new nonce). Any other status — including a `401` with a
   * different code — is returned to the caller unchanged.
   *
   * Throws `TrustHttpError` when minting fails; inspect
   * `isBindingRevoked()` / `isBindingExpired()` to tell a terminal
   * "re-link required" condition from a transient one. Never retries
   * more than once.
   */
  async fetch(
    req: { method: string; url: string; body?: string | Uint8Array | null },
    signOpts?: SignOptions,
  ): Promise<Response> {
    const first = await this.send(
      req,
      signOpts,
      this.proactive ? (await this.trust.token(this.serviceDid)).jwt : undefined,
    );
    if (first.status !== 401 || !(await isAttestationRequired(first))) {
      return first;
    }
    // §10.7 challenge: the attested session lapsed. Drop the cached
    // token the service just rejected, mint a genuinely fresh one, and
    // retry exactly once with a fresh signature (new nonce, so the
    // §5.6 replay set accepts it).
    this.trust.clearTokenCache(this.serviceDid);
    const fresh = await this.trust.token(this.serviceDid); // throws TrustHttpError if the binding is gone
    return this.send(req, signOpts, fresh.jwt);
  }

  private async send(
    req: { method: string; url: string; body?: string | Uint8Array | null },
    signOpts: SignOptions | undefined,
    attestationJwt: string | undefined,
  ): Promise<Response> {
    const signed = await this.agent.signRequest(req, signOpts);
    const headers = new Headers(signed.headers);
    if (attestationJwt) headers.set("afauth-attestation", attestationJwt);
    return this.fetchImpl(signed.url, {
      method: signed.method,
      headers,
      // Cast: a Uint8Array is a valid fetch body at runtime; the cast
      // sidesteps the TS lib's `Uint8Array<ArrayBufferLike>` vs BodyInit
      // generic mismatch (string bodies need no help).
      ...(signed.body != null ? { body: signed.body as BodyInit } : {}),
    });
  }
}

/**
 * True iff `res` is a §10.7 `401 attestation_required` challenge.
 * Reads a clone so the original `res` stays consumable by the caller.
 */
async function isAttestationRequired(res: Response): Promise<boolean> {
  if (res.status !== 401) return false;
  try {
    const j = (await res.clone().json()) as { error?: { code?: string } };
    return j?.error?.code === "attestation_required";
  } catch {
    return false;
  }
}
