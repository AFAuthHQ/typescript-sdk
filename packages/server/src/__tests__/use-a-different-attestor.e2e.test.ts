/**
 * End-to-end: "use a different attestor" across the agent and server
 * packages, exercising the REAL verification crypto (not stubbed). A
 * service accepts a non-default attestor (`acme-trust`); an agent mints an
 * attestation from it and the service verifies it offline; the agent-side
 * reconciliation accepts a matching attestor and rejects a non-matching one
 * BEFORE sending.
 *
 * Covers the whole feature surface that the recent fixes added:
 *   - defineService derives billing.accepted_attestors from the attestor's
 *     issuers (a custom MultiAttestor is auto-advertised).
 *   - AttestedFetcher reconciles the minted token's iss against the
 *     service's accepted_attestors (read from discovery) and throws
 *     AttestorNotAcceptedError locally on a mismatch.
 *   - The real MultiAttestor → HmacAttestor/JwksAttestor → validateClaims
 *     path accepts a custom-iss token and the server materializes the account.
 */

import {
  AttestedFetcher,
  AttestorNotAcceptedError,
  Agent,
  TrustClient,
  type TrustToken,
} from "@afauthhq/agent";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AFAUTH_TRUST_ISS,
  HmacAttestor,
  JwksAttestor,
  MemoryAccountStore,
  MemoryNonceStore,
  MultiAttestor,
  Server,
  defineService,
  trustAttestor,
  type DiscoveryDocument,
  type RecipientHandler,
} from "../index.js";

const SERVICE_DID = "did:web:api.example.com";
const BASE_URL = "https://api.example.com";
const ACME_ISS = "acme-trust";
const ACME_SECRET = new TextEncoder().encode("acme-trust-shared-secret-at-least-32-bytes!!");
const SUB_H = "a".repeat(43); // valid §10.4 base64url pseudonym (length ∈ [22,86])

const emailHandler: RecipientHandler = {
  async initiate() {},
  matches() {
    return true;
  },
};

function baseOpts() {
  return {
    baseUrl: BASE_URL,
    serviceDid: SERVICE_DID,
    accounts: new MemoryAccountStore(),
    recipients: { email: emailHandler },
    nonceStore: new MemoryNonceStore(),
  };
}

/** Mint a custom-iss HMAC attestation as the acme-trust attestor would. */
async function acmeHmacToken(agentDid: string): Promise<string> {
  return new SignJWT({ verification: "email", sub_h: SUB_H })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(ACME_ISS)
    .setSubject(agentDid)
    .setAudience(SERVICE_DID)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + 300)
    .sign(ACME_SECRET);
}

/** A TrustClient fetch stub that mints `jwt` at /v1/token (the attestor). */
function attestorFetch(jwt: string, calls?: { n: number }) {
  return (async (url: string | URL | Request) => {
    if (String(url).endsWith("/v1/token")) {
      if (calls) calls.n += 1;
      return new Response(
        JSON.stringify({ jwt, expires_at: Math.floor(Date.now() / 1000) + 300, verification: "email" } satisfies TrustToken),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`unexpected attestor path: ${String(url)}`);
  }) as unknown as typeof globalThis.fetch;
}

/** Route an AttestedFetcher request into the in-process Server. */
function serverFetch(server: Server, calls?: { n: number }) {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    if (calls) calls.n += 1;
    const req = new Request(typeof url === "string" ? url : url.toString(), init);
    try {
      return await server.handleAccountIntrospection(req);
    } catch (e) {
      return (e as { toResponse: () => Response }).toResponse();
    }
  }) as unknown as typeof globalThis.fetch;
}

async function readAcceptedAttestors(server: Server): Promise<readonly string[] | undefined> {
  const resp = await server.handleDiscovery(new Request("https://x/.well-known/afauth"));
  const doc = (await resp.json()) as DiscoveryDocument;
  return doc.billing?.accepted_attestors;
}

describe("E2E — use a different attestor (agent ↔ server, real verification)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("HMAC custom attestor: discovery advertises it, agent mints+reconciles, server verifies, account created", async () => {
    const accounts = new MemoryAccountStore();
    const server = defineService({
      ...baseOpts(),
      accounts,
      attestor: new MultiAttestor([
        trustAttestor(),
        new HmacAttestor({ iss: ACME_ISS, secret: ACME_SECRET }),
      ]),
    });

    // defineService fix: the custom iss is advertised, not just afauth-trust.
    const accepted = await readAcceptedAttestors(server);
    expect(accepted).toEqual([AFAUTH_TRUST_ISS, ACME_ISS]);

    const agent = await Agent.generate();
    const trust = new TrustClient({
      baseUrl: "https://trust.acme.example",
      agentDid: agent.did,
      agentPublicKey: agent.publicKey,
      agentPrivateKey: agent.exportPrivateKey(),
      binding: { binding_id: "b", binding_token_expires_at: Math.floor(Date.now() / 1000) + 100_000 },
      fetch: attestorFetch(await acmeHmacToken(agent.did)),
    });

    const svcCalls = { n: 0 };
    const fetcher = new AttestedFetcher({
      agent,
      trust,
      serviceDid: SERVICE_DID,
      fetch: serverFetch(server, svcCalls),
      proactive: true,
      acceptedAttestors: accepted, // reconcile against what discovery advertises
    });

    const built = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const res = await fetcher.fetch({ method: built.method, url: built.url });

    expect(res.status).toBe(200);
    expect(svcCalls.n).toBe(1);
    expect(await accounts.getByAgentDid(agent.did)).not.toBeNull();
  });

  it("agent reconcile: an attestor the service does NOT accept fails locally, before any request", async () => {
    // Service accepts only afauth-trust (defineService default).
    const accounts = new MemoryAccountStore();
    const server = defineService({ ...baseOpts(), accounts }); // attestor defaults to trustAttestor()
    const accepted = await readAcceptedAttestors(server);
    expect(accepted).toEqual([AFAUTH_TRUST_ISS]);

    const agent = await Agent.generate();
    const trust = new TrustClient({
      baseUrl: "https://trust.acme.example",
      agentDid: agent.did,
      agentPublicKey: agent.publicKey,
      agentPrivateKey: agent.exportPrivateKey(),
      binding: { binding_id: "b", binding_token_expires_at: Math.floor(Date.now() / 1000) + 100_000 },
      fetch: attestorFetch(await acmeHmacToken(agent.did)), // acme-trust token
    });

    const svcCalls = { n: 0 };
    const fetcher = new AttestedFetcher({
      agent,
      trust,
      serviceDid: SERVICE_DID,
      fetch: serverFetch(server, svcCalls),
      proactive: true,
      acceptedAttestors: accepted, // ["afauth-trust"] — acme-trust not on it
    });

    const built = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    await expect(fetcher.fetch({ method: built.method, url: built.url })).rejects.toBeInstanceOf(
      AttestorNotAcceptedError,
    );
    expect(svcCalls.n).toBe(0); // never sent
    expect(await accounts.getByAgentDid(agent.did)).toBeNull(); // no account created
  });

  it("JWKS/EdDSA custom attestor: the real asymmetric verifier accepts a custom-iss token", async () => {
    // An operator-run attestor: EdDSA-signed, JWKS-published, custom iss.
    const { publicKey, privateKey } = await generateKeyPair("Ed25519");
    const kid = "acme-k1";
    const jwk = { ...(await exportJWK(publicKey)), kid, alg: "EdDSA", use: "sig" };
    const jwksUrl = "https://trust.acme.example/.well-known/jwks.json";

    // Serve the JWKS to jose's createRemoteJWKSet via a stubbed global fetch.
    vi.stubGlobal(
      "fetch",
      (async (url: string | URL | Request) => {
        if (String(url) === jwksUrl) {
          return new Response(JSON.stringify({ keys: [jwk] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        throw new Error(`unexpected fetch: ${String(url)}`);
      }) as unknown as typeof globalThis.fetch,
    );

    const accounts = new MemoryAccountStore();
    const server = new Server({
      baseUrl: BASE_URL,
      serviceDid: SERVICE_DID,
      accounts,
      recipients: { email: emailHandler },
      nonceStore: new MemoryNonceStore(),
      attestor: new MultiAttestor([
        new JwksAttestor({ iss: ACME_ISS, jwksUrl, algorithms: ["EdDSA"] }),
      ]),
      discovery: {
        afauth_version: "0.1",
        service_did: SERVICE_DID,
        signature_algorithms: ["ed25519"],
        endpoints: {
          accounts: `${BASE_URL}/afauth/v1/accounts`,
          owner_invitation: `${BASE_URL}/afauth/v1/accounts/me/owner-invitation`,
          claim_page: `${BASE_URL}/claim`,
          claim_completion: `${BASE_URL}/afauth/v1/claim`,
        },
        billing: { unclaimed_mode: "attested_only", accepted_attestors: [ACME_ISS] },
      },
    });

    const agent = await Agent.generate();
    const jwt = await new SignJWT({ verification: "email", sub_h: SUB_H })
      .setProtectedHeader({ alg: "EdDSA", kid })
      .setIssuer(ACME_ISS)
      .setSubject(agent.did)
      .setAudience(SERVICE_DID)
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 300)
      .sign(privateKey);

    const built = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const headers = new Headers(built.headers);
    headers.set("afauth-attestation", jwt);
    const res = await server.handleAccountIntrospection(
      new Request(built.url, { method: built.method, headers }),
    );

    expect(res.status).toBe(200);
    expect(await accounts.getByAgentDid(agent.did)).not.toBeNull();
  });
});
