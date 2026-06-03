/**
 * defineService — opinionated factory that flips §9.2 attested_only ON
 * by default and wires `trustAttestor()` so the simple integration is
 * the spam-resistant integration.
 *
 * Covers:
 *   - attestation: 'required' (default) → discovery doc carries
 *     unclaimed_mode: 'attested_only' + accepted_attestors: ['afauth-trust'];
 *     un-attested signups rejected with 401 attestation_required.
 *   - attestation: 'optional' → no unclaimed_mode, attestor still present
 *     so attestations verify when supplied.
 *   - attestation: 'off' → no attestor, no enforcement; equivalent to
 *     calling new Server({...}) with no attestor.
 *   - opts.attestor override (custom HmacAttestor) replaces the default
 *     trustAttestor() while keeping the rest of the defaults intact.
 *   - opts.discovery.endpoints / opts.discovery.billing overrides merge
 *     on top of the synthesized values.
 */

import { Agent } from "@afauthhq/agent";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  AFAUTH_TRUST_ISS,
  HmacAttestor,
  MemoryAccountStore,
  MemoryNonceStore,
  defineService,
  type DiscoveryDocument,
  type RecipientHandler,
} from "../index.js";

const SERVICE_DID = "did:web:api.example.com";
const BASE_URL = "https://api.example.com";

const emailHandler: RecipientHandler = {
  async initiate() { /* noop */ },
  matches() { return true; },
};

const SECRET = new TextEncoder().encode(
  "this-secret-is-at-least-32-bytes-long-enough-for-hs256",
);

async function makeHmacToken(opts: {
  iss?: string;
  sub: string;
  aud?: string;
  exp?: number;
}): Promise<string> {
  const exp = opts.exp ?? Math.floor(Date.now() / 1000) + 60;
  const builder = new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(opts.iss ?? "test-attestor")
    .setSubject(opts.sub)
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .setExpirationTime(exp);
  if (opts.aud) builder.setAudience(opts.aud);
  return builder.sign(SECRET);
}

function baseOpts() {
  return {
    baseUrl: BASE_URL,
    serviceDid: SERVICE_DID,
    accounts: new MemoryAccountStore(),
    recipients: { email: emailHandler },
    nonceStore: new MemoryNonceStore(),
  };
}

describe("defineService — synthesized discovery doc", () => {
  it("required mode emits unclaimed_mode: attested_only + accepted_attestors: ['afauth-trust']", async () => {
    const server = defineService({ ...baseOpts() }); // default required
    const resp = await server.handleDiscovery(new Request("https://x/.well-known/afauth"));
    const doc = (await resp.json()) as DiscoveryDocument;
    expect(doc.afauth_version).toBe("0.1");
    expect(doc.service_did).toBe(SERVICE_DID);
    expect(doc.signature_algorithms).toContain("ed25519");
    expect(doc.endpoints.accounts).toBe(`${BASE_URL}/accounts`);
    expect(doc.endpoints.owner_invitation).toBe(`${BASE_URL}/owner-invitations`);
    expect(doc.endpoints.claim_page).toBe(`${BASE_URL}/claim`);
    expect(doc.endpoints.claim_completion).toBe(`${BASE_URL}/claim/complete`);
    expect(doc.billing?.unclaimed_mode).toBe("attested_only");
    expect(doc.billing?.accepted_attestors).toEqual([AFAUTH_TRUST_ISS]);
  });

  it("optional mode omits unclaimed_mode but advertises accepted_attestors", async () => {
    const server = defineService({ ...baseOpts(), attestation: "optional" });
    const resp = await server.handleDiscovery(new Request("https://x/.well-known/afauth"));
    const doc = (await resp.json()) as DiscoveryDocument;
    expect(doc.billing?.unclaimed_mode).toBeUndefined();
    expect(doc.billing?.accepted_attestors).toEqual([AFAUTH_TRUST_ISS]);
  });

  it("off mode emits no billing block at all", async () => {
    const server = defineService({ ...baseOpts(), attestation: "off" });
    const resp = await server.handleDiscovery(new Request("https://x/.well-known/afauth"));
    const doc = (await resp.json()) as DiscoveryDocument;
    expect(doc.billing).toBeUndefined();
  });

  it("discovery override merges endpoints and billing", async () => {
    const server = defineService({
      ...baseOpts(),
      discovery: {
        endpoints: {
          accounts: "/api/v1/accounts",
          owner_invitation: `${BASE_URL}/owner-invitations`,
          claim_page: `${BASE_URL}/claim`,
          claim_completion: `${BASE_URL}/claim/complete`,
        },
        billing: { accepted_attestors: ["afauth-trust", "stripe-projects"] },
        limits: { unclaimed_ttl_seconds: 3600 },
      },
    });
    const resp = await server.handleDiscovery(new Request("https://x/.well-known/afauth"));
    const doc = (await resp.json()) as DiscoveryDocument;
    expect(doc.endpoints.accounts).toBe("/api/v1/accounts");
    expect(doc.billing?.unclaimed_mode).toBe("attested_only"); // still synthesized
    expect(doc.billing?.accepted_attestors).toEqual(["afauth-trust", "stripe-projects"]);
    expect(doc.limits?.unclaimed_ttl_seconds).toBe(3600);
  });
});

describe("defineService — signup enforcement", () => {
  it("required + no header → 401 attestation_required", async () => {
    // Use a custom attestor so we don't hit the network for trust JWKS.
    const server = defineService({
      ...baseOpts(),
      attestor: new HmacAttestor({ iss: "test-attestor", secret: SECRET }),
    });
    const agent = await Agent.generate();
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const resp = await server.handleAccountIntrospection(new Request(signed.url, {
      method: signed.method,
      headers: new Headers(signed.headers),
    })).catch((e) => (e as { toResponse: () => Response }).toResponse());
    expect(resp.status).toBe(401);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe("attestation_required");
  });

  it("required + valid attestation → 200 + account row", async () => {
    const accounts = new MemoryAccountStore();
    const server = defineService({
      ...baseOpts(),
      accounts,
      attestor: new HmacAttestor({ iss: "test-attestor", secret: SECRET }),
    });
    const agent = await Agent.generate();
    const jwt = await makeHmacToken({ sub: agent.did, aud: SERVICE_DID });
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const headers = new Headers(signed.headers);
    headers.set("afauth-attestation", jwt);
    const resp = await server.handleAccountIntrospection(new Request(signed.url, {
      method: signed.method, headers,
    }));
    expect(resp.status).toBe(200);
    expect(await accounts.getByAgentDid(agent.did)).not.toBeNull();
  });

  it("optional + no header → 200 (no enforcement)", async () => {
    const server = defineService({
      ...baseOpts(),
      attestation: "optional",
      attestor: new HmacAttestor({ iss: "test-attestor", secret: SECRET }),
    });
    const agent = await Agent.generate();
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const resp = await server.handleAccountIntrospection(new Request(signed.url, {
      method: signed.method, headers: new Headers(signed.headers),
    }));
    expect(resp.status).toBe(200);
  });

  it("optional + invalid header → 401 invalid_attestation (lax verifies when present)", async () => {
    const server = defineService({
      ...baseOpts(),
      attestation: "optional",
      attestor: new HmacAttestor({ iss: "test-attestor", secret: SECRET }),
    });
    const agent = await Agent.generate();
    // sub doesn't match the agent's DID
    const jwt = await makeHmacToken({ sub: "did:key:zSomeoneElse" });
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const headers = new Headers(signed.headers);
    headers.set("afauth-attestation", jwt);
    const resp = await server.handleAccountIntrospection(new Request(signed.url, {
      method: signed.method, headers,
    })).catch((e) => (e as { toResponse: () => Response }).toResponse());
    expect(resp.status).toBe(401);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe("invalid_attestation");
  });

  it("off + no header → 200, no attestation processed", async () => {
    const accounts = new MemoryAccountStore();
    const server = defineService({
      ...baseOpts(),
      accounts,
      attestation: "off",
    });
    const agent = await Agent.generate();
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const resp = await server.handleAccountIntrospection(new Request(signed.url, {
      method: signed.method, headers: new Headers(signed.headers),
    }));
    expect(resp.status).toBe(200);
    expect(await accounts.getByAgentDid(agent.did)).not.toBeNull();
  });
});
