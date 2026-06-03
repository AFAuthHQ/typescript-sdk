/**
 * §10.7 critical path, end to end across real components, including the
 * attestor revoking the agent_did:
 *
 *   attest → access → within-window access → window expires → re-mint →
 *   access → ATTESTOR REVOKES agent_did → (still served until the window
 *   lapses — the bounded residual) → window lapses → re-mint refused →
 *   access stops.
 *
 * Wires a real Server (attestedSession gate + HmacAttestor) to a real
 * agent-side AttestedFetcher (+ TrustClient minting against an in-process
 * attestor), connected by an in-process transport. One injected clock
 * drives the agent signatures, the Verifier, the gate, and the attestor,
 * so advancing it past the short attestation TTL expires the session
 * deterministically — while request signatures (300s) stay valid.
 *
 * The attestor's binding-revoke → mint-refusal primitive itself is unit-
 * tested against the real trust app in `trust/test/token.test.ts`
 * ("refuses after the binding is revoked"); here we prove that revoking
 * the agent_did at the attestor actually stops service access, and does
 * so within one freshness window — the §10.7 kill-switch end to end.
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
  type DiscoveryDocument,
  type RecipientHandler,
} from "../index.js";

const SERVICE_DID = "did:web:svc.example";
const BASE_URL = "https://svc.example";
const ISS = "test-attestor";
const SECRET = new TextEncoder().encode(
  "this-secret-is-at-least-32-bytes-long-enough-for-hs256",
);
const ATTESTATION_TTL_SECONDS = 2; // short window so we can lapse it by advancing the clock

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

describe("§10.7 E2E: attest → access → expire → re-mint → attestor revokes agent_did → access stops", () => {
  it("propagates an attestor revoke of the agent_did to the service within one window", async () => {
    let nowS = 1_700_000_000;
    const clock = () => nowS;

    const agent = await Agent.generate();

    // In-process attestor for this agent's binding. Mints short-lived
    // HS256 attestations the Server's HmacAttestor accepts — until the
    // binding is revoked, after which it refuses (binding_revoked), the
    // real trust mint-path behaviour (token.ts §10.7).
    let mintAttempts = 0;
    let bindingRevoked = false; // flipped when the attestor revokes the agent_did
    const trustFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      if (!String(url).endsWith("/v1/token")) throw new Error(`unexpected trust path: ${String(url)}`);
      mintAttempts += 1;
      if (bindingRevoked) {
        return new Response(JSON.stringify({ error: { code: "binding_revoked", message: "revoked by the human" } }), {
          status: 403,
          headers: { "content-type": "application/json" },
        });
      }
      const aud = (JSON.parse(String(init?.body)) as { aud: string }).aud;
      const exp = clock() + ATTESTATION_TTL_SECONDS;
      const jwt = await new SignJWT({})
        .setProtectedHeader({ alg: "HS256" })
        .setIssuer(ISS)
        .setSubject(agent.did)
        .setAudience(aud)
        .setIssuedAt(clock())
        .setExpirationTime(exp)
        .sign(SECRET);
      return new Response(JSON.stringify({ jwt, expires_at: exp, verification: "oauth" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const trust = new TrustClient({
      agentDid: agent.did,
      agentPublicKey: agent.publicKey,
      agentPrivateKey: agent.exportPrivateKey(),
      binding: { binding_id: "bind-1", binding_token_expires_at: nowS + 86_400 },
      fetch: trustFetch,
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

    // In-process transport: the agent's signed Request is gated by the
    // real Server.verifyAttested. Record whether each request carried an
    // attestation header (a within-window served request carries none).
    const serviceLog: { attested: boolean }[] = [];
    const serviceFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const req = new Request(String(url), init);
      serviceLog.push({ attested: req.headers.has("afauth-attestation") });
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

    // 1) First access: no session → challenged → agent mints → retry passes.
    expect((await call()).status).toBe(200);
    expect(serviceLog.map((c) => c.attested)).toEqual([false, true]);

    // 2) Within the window: served from the session — no attestation re-presented, no mint.
    const mintsAfterFirst = mintAttempts;
    expect((await call()).status).toBe(200);
    expect(serviceLog.at(-1)).toEqual({ attested: false });
    expect(mintAttempts).toBe(mintsAfterFirst);

    // 3) Window lapses (signatures, 300s, stay valid): challenged → re-mint → served.
    nowS += ATTESTATION_TTL_SECONDS + 1;
    expect((await call()).status).toBe(200);
    expect(mintAttempts).toBe(mintsAfterFirst + 1);

    // 4) The attestor revokes the agent_did's binding (owner kill-switch).
    bindingRevoked = true;

    // 5) Bounded residual: the attestation already on file at the service
    //    stays valid until its exp, so the agent is still served within the
    //    current window WITHOUT contacting the attestor — revoke is not
    //    instant, it takes effect within ≤ one window (§10.7 honest latency).
    const mintsAtRevoke = mintAttempts;
    expect((await call()).status).toBe(200);
    expect(mintAttempts).toBe(mintsAtRevoke); // served from session; attestor not consulted

    // 6) Window lapses again → challenged → the agent tries to re-mint →
    //    the attestor refuses (binding_revoked) → terminal error, NO access.
    //    The kill-switch has taken full effect within one window.
    nowS += ATTESTATION_TTL_SECONDS + 1;
    await expect(call()).rejects.toMatchObject({ upstreamCode: "binding_revoked" });
    expect(mintAttempts).toBe(mintsAtRevoke + 1); // one refused mint, no further retries
  });
});
