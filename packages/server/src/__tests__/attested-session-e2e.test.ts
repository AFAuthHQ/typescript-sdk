/**
 * §10.7 critical path, end to end across real components:
 *
 *   attest → access (within window) → window expires → re-mint → access again
 *
 * Wires a real Server (attestedSession gate, HmacAttestor) to a real
 * agent-side AttestedFetcher (+ TrustClient minting against an in-process
 * attestor), connected by an in-process transport. A single injected
 * clock drives the agent signatures, the Verifier, the gate, and the
 * attestor, so advancing it past the short attestation TTL expires the
 * session deterministically — while request signatures (300s lifetime)
 * stay valid.
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
const ATTESTATION_TTL_SECONDS = 2; // short window so we can expire it by advancing the clock

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

describe("§10.7 E2E: attest → access → expire → re-mint → access", () => {
  it("serves within the window, challenges once it lapses, and the agent re-mints to recover", async () => {
    let nowS = 1_700_000_000;
    const clock = () => nowS;

    const agent = await Agent.generate();

    // In-process attestor: mints short-lived HS256 attestations the
    // Server's HmacAttestor accepts. Counts mints so we can prove the
    // agent re-minted only when the window actually lapsed.
    let mints = 0;
    const trustFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      if (!String(url).endsWith("/v1/token")) throw new Error(`unexpected trust path: ${String(url)}`);
      mints += 1;
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
      binding: {
        binding_id: "bind-1",
        binding_token: "tok",
        binding_token_expires_at: nowS + 86_400,
      },
      fetch: trustFetch,
      now: clock,
    });

    // Real Server with the §10.7 gate, driven by the same clock.
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
    // attestation header so we can prove "served within window" sends none.
    const serviceLog: { attested: boolean }[] = [];
    const serviceFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const req = new Request(String(url), init);
      serviceLog.push({ attested: req.headers.has("afauth-attestation") });
      try {
        await server.verifyAttested(req);
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      } catch (e) {
        if (e instanceof AFAuthError) return e.toResponse();
        throw e;
      }
    }) as unknown as typeof globalThis.fetch;

    const fetcher = new AttestedFetcher({ agent, trust, serviceDid: SERVICE_DID, fetch: serviceFetch });
    const call = () => fetcher.fetch({ method: "GET", url: `${BASE_URL}/api/resource` }, { now: clock });

    // 1) First access: no session yet → challenged → agent mints → retry passes.
    const first = await call();
    expect(first.status).toBe(200);
    expect(mints).toBe(1);
    expect(serviceLog.map((c) => c.attested)).toEqual([false, true]); // challenge, then re-minted retry

    // 2) Within the window: served straight from the session, no attestation re-presented, no new mint.
    const within = await call();
    expect(within.status).toBe(200);
    expect(mints).toBe(1);
    expect(serviceLog.at(-1)).toEqual({ attested: false });

    // 3) Window lapses: advance past the attestation TTL. Signatures (300s) stay valid.
    nowS += ATTESTATION_TTL_SECONDS + 1;
    const afterExpiry = await call();
    expect(afterExpiry.status).toBe(200);   // recovered
    expect(mints).toBe(2);                   // re-minted exactly once, only because the window lapsed
    // The lapsed request was challenged (no attestation) then served on the re-minted retry.
    expect(serviceLog.slice(-2).map((c) => c.attested)).toEqual([false, true]);
  });

  it("stops serving when the binding is revoked at the attestor (kill-switch within the window)", async () => {
    let nowS = 1_700_000_000;
    const clock = () => nowS;
    const agent = await Agent.generate();

    // Attestor that mints once, then refuses (binding revoked) — modelling
    // an owner revoke between the first access and the window lapsing.
    let revoked = false;
    const trustFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      if (!String(url).endsWith("/v1/token")) throw new Error("unexpected");
      if (revoked) {
        return new Response(JSON.stringify({ error: { code: "binding_revoked", message: "revoked" } }), {
          status: 403,
          headers: { "content-type": "application/json" },
        });
      }
      const aud = (JSON.parse(String(init?.body)) as { aud: string }).aud;
      const exp = clock() + ATTESTATION_TTL_SECONDS;
      const jwt = await new SignJWT({})
        .setProtectedHeader({ alg: "HS256" })
        .setIssuer(ISS).setSubject(agent.did).setAudience(aud)
        .setIssuedAt(clock()).setExpirationTime(exp).sign(SECRET);
      return new Response(JSON.stringify({ jwt, expires_at: exp, verification: "oauth" }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof globalThis.fetch;

    const trust = new TrustClient({
      agentDid: agent.did, agentPublicKey: agent.publicKey, agentPrivateKey: agent.exportPrivateKey(),
      binding: { binding_id: "b", binding_token: "tok", binding_token_expires_at: nowS + 86_400 },
      fetch: trustFetch, now: clock,
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
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      } catch (e) {
        if (e instanceof AFAuthError) return e.toResponse();
        throw e;
      }
    }) as unknown as typeof globalThis.fetch;
    const fetcher = new AttestedFetcher({ agent, trust, serviceDid: SERVICE_DID, fetch: serviceFetch });
    const call = () => fetcher.fetch({ method: "GET", url: `${BASE_URL}/api/resource` }, { now: clock });

    // Establish the session.
    expect((await call()).status).toBe(200);

    // Owner revokes the binding; window then lapses.
    revoked = true;
    nowS += ATTESTATION_TTL_SECONDS + 1;

    // The agent is challenged, tries to re-mint, the attestor refuses →
    // a terminal TrustHttpError, not access. The kill-switch held within
    // one window.
    await expect(call()).rejects.toMatchObject({ upstreamCode: "binding_revoked" });
  });
});
