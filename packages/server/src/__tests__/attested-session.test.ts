/**
 * §10.7 attested sessions — agent-refreshed periodic re-presentation.
 *
 * Covers:
 *   - attestedUntilAfter / isAttestationFresh (pure window logic).
 *   - AttestedSessionGate strict mode: empty/lapsed → attestation_required;
 *     valid header refreshes; served-from-session within the window;
 *     expired or wrong-aud token rejected as invalid_attestation.
 *   - AttestedSessionGate extended mode: serves past the token's own exp,
 *     up to the session TTL, then lapses.
 *   - Server.verifyAttested: throws when unconfigured; with a real signed
 *     request, challenges a stale session and serves a freshly-attested one.
 */

import { Agent } from "@afauthhq/agent";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  AttestedSessionGate,
  HmacAttestor,
  MemoryAccountStore,
  MemoryAttestedFreshnessStore,
  MemoryNonceStore,
  Server,
  attestedUntilAfter,
  isAttestationFresh,
  type DiscoveryDocument,
  type RecipientHandler,
} from "../index.js";

const SERVICE_DID = "did:web:api.example.com";
const BASE_URL = "https://api.example.com";
const ATTESTOR_ISS = "test-attestor";
const SECRET = new TextEncoder().encode(
  "this-secret-is-at-least-32-bytes-long-enough-for-hs256",
);
const AGENT_DID = "did:key:z6MkAttestedAgent";

function makeToken(opts: {
  sub: string;
  exp: number;
  iat?: number;
  aud?: string | null;
  iss?: string;
}): Promise<string> {
  const b = new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(opts.iss ?? ATTESTOR_ISS)
    .setSubject(opts.sub)
    .setIssuedAt(opts.iat ?? opts.exp - 60)
    .setExpirationTime(opts.exp);
  if (opts.aud !== null) b.setAudience(opts.aud ?? SERVICE_DID);
  return b.sign(SECRET);
}

function headersWith(jwt?: string): Headers {
  const h = new Headers();
  if (jwt) h.set("afauth-attestation", jwt);
  return h;
}

describe("attestedUntilAfter / isAttestationFresh (§10.7 window)", () => {
  it("strict: window is the attestation's own exp", () => {
    expect(attestedUntilAfter({ exp: 1_000_100 }, "strict", 1_000_000)).toBe(1_000_100);
  });

  it("extended: window is now + sessionTtlSeconds (may exceed exp)", () => {
    expect(attestedUntilAfter({ exp: 1_000_060 }, "extended", 1_000_000, 1800)).toBe(1_001_800);
  });

  it("extended without a positive ttl throws", () => {
    expect(() => attestedUntilAfter({ exp: 1 }, "extended", 0)).toThrow(/sessionTtlSeconds/);
    expect(() => attestedUntilAfter({ exp: 1 }, "extended", 0, 0)).toThrow(/sessionTtlSeconds/);
  });

  it("isAttestationFresh: fresh strictly before attestedUntil", () => {
    expect(isAttestationFresh(1_000_100, 1_000_000)).toBe(true);
    expect(isAttestationFresh(1_000_100, 1_000_100)).toBe(false); // boundary: now == until
    expect(isAttestationFresh(1_000_100, 1_000_200)).toBe(false);
    expect(isAttestationFresh(null, 1_000_000)).toBe(false);
  });
});

describe("AttestedSessionGate — strict mode", () => {
  function setup() {
    let now = 1_700_000_000;
    const clock = () => now;
    const attestor = new HmacAttestor({ iss: ATTESTOR_ISS, secret: SECRET, now: clock });
    const store = new MemoryAttestedFreshnessStore();
    const gate = new AttestedSessionGate({ attestor, store, serviceDid: SERVICE_DID, now: clock });
    return { gate, store, setNow: (t: number) => { now = t; }, now: () => now };
  }

  it("challenges when no attestation has ever been presented", async () => {
    const { gate } = setup();
    await expect(gate.check({ headers: headersWith() }, AGENT_DID)).rejects.toMatchObject({
      code: "attestation_required",
      status: 401,
    });
  });

  it("a valid presented attestation establishes the session (window = exp)", async () => {
    const { gate, store, now } = setup();
    const exp = now() + 60;
    await gate.check({ headers: headersWith(await makeToken({ sub: AGENT_DID, exp })) }, AGENT_DID);
    expect(await store.get(AGENT_DID)).toBe(exp);
  });

  it("serves subsequent header-less requests while within the window", async () => {
    const { gate, setNow, now } = setup();
    const exp = now() + 60;
    await gate.check({ headers: headersWith(await makeToken({ sub: AGENT_DID, exp })) }, AGENT_DID);
    setNow(exp - 1); // still fresh
    await expect(gate.check({ headers: headersWith() }, AGENT_DID)).resolves.toBeUndefined();
  });

  it("challenges once the window lapses (no fresh attestation)", async () => {
    const { gate, setNow, now } = setup();
    const exp = now() + 60;
    await gate.check({ headers: headersWith(await makeToken({ sub: AGENT_DID, exp })) }, AGENT_DID);
    setNow(exp + 1); // lapsed
    await expect(gate.check({ headers: headersWith() }, AGENT_DID)).rejects.toMatchObject({
      code: "attestation_required",
    });
  });

  it("rejects an already-expired presented attestation as invalid_attestation (§10.2)", async () => {
    const { gate, now } = setup();
    const jwt = await makeToken({ sub: AGENT_DID, exp: now() - 10, iat: now() - 70 });
    await expect(gate.check({ headers: headersWith(jwt) }, AGENT_DID)).rejects.toMatchObject({
      code: "invalid_attestation",
    });
  });

  it("rejects a wrong-audience attestation (cross-service replay defense)", async () => {
    const { gate, now } = setup();
    const jwt = await makeToken({ sub: AGENT_DID, exp: now() + 60, aud: "did:web:other.example" });
    await expect(gate.check({ headers: headersWith(jwt) }, AGENT_DID)).rejects.toMatchObject({
      code: "invalid_attestation",
    });
  });
});

describe("AttestedSessionGate — extended mode", () => {
  it("serves past the token's own exp, up to the session TTL, then lapses", async () => {
    let now = 1_700_000_000;
    const clock = () => now;
    const attestor = new HmacAttestor({ iss: ATTESTOR_ISS, secret: SECRET, now: clock });
    const store = new MemoryAttestedFreshnessStore();
    const gate = new AttestedSessionGate({
      attestor, store, serviceDid: SERVICE_DID, mode: "extended", sessionTtlSeconds: 1800, now: clock,
    });

    const tokenExp = now + 60;
    await gate.check({ headers: headersWith(await makeToken({ sub: AGENT_DID, exp: tokenExp })) }, AGENT_DID);
    expect(await store.get(AGENT_DID)).toBe(now + 1800); // window = now + T, beyond tokenExp

    now = tokenExp + 120; // past the token's own exp, still within T
    await expect(gate.check({ headers: headersWith() }, AGENT_DID)).resolves.toBeUndefined();

    now = 1_700_000_000 + 1801; // past T
    await expect(gate.check({ headers: headersWith() }, AGENT_DID)).rejects.toMatchObject({
      code: "attestation_required",
    });
  });

  it("constructor rejects extended mode without a positive sessionTtlSeconds", () => {
    const attestor = new HmacAttestor({ iss: ATTESTOR_ISS, secret: SECRET });
    expect(() => new AttestedSessionGate({
      attestor, store: new MemoryAttestedFreshnessStore(), serviceDid: SERVICE_DID, mode: "extended",
    })).toThrow(/sessionTtlSeconds/);
  });
});

describe("Server.verifyAttested (§10.7 integration)", () => {
  const emailHandler: RecipientHandler = { async initiate() {}, matches() { return true; } };

  function discovery(): DiscoveryDocument {
    return {
      afauth_version: "0.1",
      service_did: SERVICE_DID,
      endpoints: {
        accounts: "/afauth/v1/accounts",
        owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
        claim_page: "https://claim.example.com",
        claim_completion: "/afauth/v1/claim",
      },
      signature_algorithms: ["ed25519"],
      features: ["attestation", "attested_session"],
      billing: { unclaimed_mode: "attested_only", accepted_attestors: [ATTESTOR_ISS] },
    };
  }

  function newServer(withAttestedSession: boolean): Server {
    return new Server({
      accounts: new MemoryAccountStore(),
      recipients: { email: emailHandler },
      discovery: discovery(),
      baseUrl: BASE_URL,
      serviceDid: SERVICE_DID,
      nonceStore: new MemoryNonceStore(),
      attestor: new HmacAttestor({ iss: ATTESTOR_ISS, secret: SECRET }),
      ...(withAttestedSession
        ? { attestedSession: { store: new MemoryAttestedFreshnessStore() } }
        : {}),
    });
  }

  it("throws a configuration error when attestedSession is not configured", async () => {
    const server = newServer(false);
    await expect(
      server.verifyAttested(new Request(`${BASE_URL}/api/thing`)),
    ).rejects.toThrow(/attestedSession/);
  });

  it("challenges a signed business request with a lapsed (empty) session → 401 attestation_required", async () => {
    const server = newServer(true);
    const agent = await Agent.generate();
    const signed = await agent.signRequest({ method: "GET", url: `${BASE_URL}/api/thing` });
    const req = new Request(signed.url, { method: signed.method, headers: new Headers(signed.headers) });
    await expect(server.verifyAttested(req)).rejects.toMatchObject({
      code: "attestation_required",
      status: 401,
    });
  });

  it("serves a signed business request that carries a fresh attestation, and records the session", async () => {
    const store = new MemoryAttestedFreshnessStore();
    const server = new Server({
      accounts: new MemoryAccountStore(),
      recipients: { email: emailHandler },
      discovery: discovery(),
      baseUrl: BASE_URL,
      serviceDid: SERVICE_DID,
      nonceStore: new MemoryNonceStore(),
      attestor: new HmacAttestor({ iss: ATTESTOR_ISS, secret: SECRET }),
      attestedSession: { store },
    });
    const agent = await Agent.generate();
    const exp = Math.floor(Date.now() / 1000) + 60;
    const jwt = await makeToken({ sub: agent.did, exp });
    const signed = await agent.signRequest({ method: "GET", url: `${BASE_URL}/api/thing` });
    const headers = new Headers(signed.headers);
    headers.set("afauth-attestation", jwt);
    const verified = await server.verifyAttested(
      new Request(signed.url, { method: signed.method, headers }),
    );
    expect(verified.agentDid).toBe(agent.did);
    expect(await store.get(agent.did)).toBe(exp);
  });
});
