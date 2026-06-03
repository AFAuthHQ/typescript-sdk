/**
 * §3.1 keyless mint, end to end across real components:
 *
 *   agent's TrustClient SIGNS POST /v1/token with its account key (§5)
 *   → an in-process attestor verifies that signature with the REAL
 *     @afauthhq/server `Verifier` (the keypair is the sole credential —
 *     no binding_token is sent) and maps the verified keyid to a mint
 *   → the minted §10 attestation flows through AttestedFetcher
 *   → the REAL `Server.verifyAttested` serves the request.
 *
 * This proves the property the §3.1 change is about: the agent's keypair,
 * and nothing else, authenticates minting. The companion negative test
 * shows an unsigned mint request is refused, so the key is necessary.
 *
 * The attestor's keyid→binding mapping and its revoke/expire/replay
 * behaviour are unit-tested against the real trust app in
 * trust/test/token-signed-mint.test.ts; here we prove the cross-component
 * contract using a reference verifier.
 */

import { Agent, AttestedFetcher, TrustClient } from "@afauthhq/agent";
import { AFAuthError } from "@afauthhq/core";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  HmacAttestor,
  MemoryAccountStore,
  MemoryAttestedFreshnessStore,
  MemoryNonceStore,
  Server,
  Verifier,
  type DiscoveryDocument,
  type RecipientHandler,
} from "../index.js";

const SERVICE_DID = "did:web:svc.example";
const BASE_URL = "https://svc.example";
const TRUST_BASE = "https://trust.afauth.example";
const ISS = "test-attestor";
const SECRET = new TextEncoder().encode("this-secret-is-at-least-32-bytes-long-enough-for-hs256");
const ATTESTATION_TTL_SECONDS = 2;

const emailHandler: RecipientHandler = { async initiate() {}, matches() { return true; } };

function discovery(): DiscoveryDocument {
  return {
    afauth_version: "0.1",
    service_did: SERVICE_DID,
    endpoints: {
      accounts: "/afauth/v1/accounts",
      owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
      claim_page: "https://claim.svc.example",
      claim_completion: "/afauth/v1/claim",
    },
    signature_algorithms: ["ed25519"],
    features: ["attestation", "attested_session"],
    billing: { unclaimed_mode: "attested_only", accepted_attestors: [ISS] },
  };
}

/**
 * In-process trust attestor whose `/v1/token` requires a §5 signature
 * from the agent key, verified by the real `Verifier`. Mirrors the real
 * keyless mint path: verify the request signature, then mint for the
 * verified keyid. Records what it saw for assertions.
 */
function keylessAttestor(clock: () => number) {
  const verifier = new Verifier({
    nonceStore: new MemoryNonceStore(),
    serviceDid: ISS,
    now: clock,
  });
  const seen: { verifiedDid: string | null; hadAuthHeader: boolean }[] = [];
  const fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    if (!String(url).endsWith("/v1/token")) throw new Error(`unexpected trust path: ${String(url)}`);
    const headers = new Headers(init?.headers);
    let verifiedDid: string | null = null;
    try {
      const v = await verifier.verify({
        method: init?.method ?? "POST",
        url: String(url),
        headers,
        body: init?.body != null ? String(init.body) : null,
      });
      verifiedDid = v.agentDid;
    } catch {
      verifiedDid = null;
    }
    seen.push({ verifiedDid, hadAuthHeader: headers.has("authorization") });
    if (!verifiedDid) {
      return new Response(JSON.stringify({ error: { code: "invalid_signature", message: "mint not signed by agent key" } }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    }
    const aud = (JSON.parse(String(init?.body)) as { aud: string }).aud;
    const exp = clock() + ATTESTATION_TTL_SECONDS;
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer(ISS)
      .setSubject(verifiedDid) // §10.2: attestation sub == the verified request signer
      .setAudience(aud)
      .setIssuedAt(clock())
      .setExpirationTime(exp)
      .sign(SECRET);
    return new Response(JSON.stringify({ jwt, expires_at: exp, verification: "oauth" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;
  return { fetch, seen };
}

describe("§3.1 E2E: keyless signed mint → reference Verifier → Server.verifyAttested", () => {
  it("the agent's keypair alone authenticates minting, and the full attested path serves 200", async () => {
    let nowS = 1_700_000_000;
    const clock = () => nowS;

    const agent = await Agent.generate();
    const attestor = keylessAttestor(clock);

    const trust = new TrustClient({
      agentDid: agent.did,
      agentPublicKey: agent.publicKey,
      agentPrivateKey: agent.exportPrivateKey(),
      // Phase-1 linked marker; its binding_token is NOT used by token().
      binding: { binding_id: "bind-1", binding_token: "legacy-unused", binding_token_expires_at: nowS + 86_400 },
      baseUrl: TRUST_BASE, // the agent signs `${TRUST_BASE}/v1/token`
      fetch: attestor.fetch,
      now: clock,
    });

    const server = new Server({
      accounts: new MemoryAccountStore(),
      recipients: { email: emailHandler },
      discovery: discovery(),
      baseUrl: BASE_URL,
      serviceDid: SERVICE_DID,
      nonceStore: new MemoryNonceStore(),
      attestor: new HmacAttestor({ iss: ISS, secret: SECRET, now: clock }),
      attestedSession: { store: new MemoryAttestedFreshnessStore(), mode: "strict" },
      now: clock,
    });

    const serviceFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const req = new Request(String(url), init);
      try {
        await server.verifyAttested(req);
        return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
      } catch (e) {
        if (e instanceof AFAuthError) return e.toResponse();
        throw e;
      }
    }) as unknown as typeof globalThis.fetch;

    const fetcher = new AttestedFetcher({ agent, trust, serviceDid: SERVICE_DID, fetch: serviceFetch });
    const call = () => fetcher.fetch({ method: "GET", url: `${BASE_URL}/api/resource` }, { now: clock });

    // First access: challenged → agent SIGNS a mint → attestor verifies → retry serves.
    expect((await call()).status).toBe(200);
    // Window lapses → a fresh signed mint.
    nowS += ATTESTATION_TTL_SECONDS + 1;
    expect((await call()).status).toBe(200);

    // Every mint the attestor saw was §5-verified as THIS agent's DID,
    // and NONE carried an Authorization/bearer header — the keypair is the
    // sole credential.
    expect(attestor.seen.length).toBeGreaterThanOrEqual(2);
    expect(attestor.seen.every((s) => s.verifiedDid === agent.did)).toBe(true);
    expect(attestor.seen.every((s) => s.hadAuthHeader === false)).toBe(true);
  });

  it("refuses to mint when the request is not signed by the agent key (keypair is necessary)", async () => {
    const clock = () => 1_700_000_000;
    const attestor = keylessAttestor(clock);
    // A mint attempt with a body but NO signature headers — what an
    // attacker holding only a (now-removed) bearer token could send.
    const res = await attestor.fetch(`${TRUST_BASE}/v1/token`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer stolen-or-guessed" },
      body: JSON.stringify({ aud: SERVICE_DID }),
    });
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("invalid_signature");
    expect(attestor.seen.at(-1)).toEqual({ verifiedDid: null, hadAuthHeader: true });
  });
});
