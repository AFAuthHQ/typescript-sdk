/**
 * §10 attestation JWT verifier + §9.2 attested_only enforcement.
 *
 * Covers:
 *   - HmacAttestor accepts a valid HS256 token, rejects expired /
 *     wrong-issuer / wrong-sub / mangled-signature variants.
 *   - JwksAttestor verifies against an in-process JWKS endpoint.
 *   - MultiAttestor dispatches by iss; rejects unknown issuers.
 *   - Server.handleAccountIntrospection enforces §9.2 attested_only:
 *     missing header → 401 attestation_required; invalid token →
 *     401 invalid_attestation; valid token → 200 + account created.
 *   - In non-attested_only mode a present-but-bad header still
 *     rejects (lax validation); absent header passes through.
 */

import { Agent } from "@afauthhq/agent";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  HmacAttestor,
  JwksAttestor,
  MemoryAccountStore,
  MemoryNonceStore,
  MultiAttestor,
  Server,
  type DiscoveryDocument,
  type RecipientHandler,
} from "../index.js";

const SERVICE_DID = "did:web:api.example.com";
const BASE_URL = "https://api.example.com";

function discoveryFor(unclaimedMode?: "free" | "attested_only" | "denied"): DiscoveryDocument {
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
    recipient_types: ["email"],
    ...(unclaimedMode
      ? { billing: { unclaimed_mode: unclaimedMode, accepted_attestors: ["test-attestor"] } }
      : {}),
  };
}

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
  exp?: number;
  secret?: Uint8Array;
  aud?: string;
}): Promise<string> {
  const exp = opts.exp ?? Math.floor(Date.now() / 1000) + 60;
  const builder = new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(opts.iss ?? "test-attestor")
    .setSubject(opts.sub)
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .setExpirationTime(exp);
  if (opts.aud) builder.setAudience(opts.aud);
  return await builder.sign(opts.secret ?? SECRET);
}

describe("HmacAttestor", () => {
  it("accepts a valid HS256 token", async () => {
    const att = new HmacAttestor({ iss: "test-attestor", secret: SECRET });
    const agentDid = "did:key:z6MkAgent";
    const jwt = await makeHmacToken({ sub: agentDid });
    const claims = await att.verify(jwt, agentDid);
    expect(claims.iss).toBe("test-attestor");
    expect(claims.sub).toBe(agentDid);
  });

  it("rejects when iss doesn't match", async () => {
    const att = new HmacAttestor({ iss: "test-attestor", secret: SECRET });
    const jwt = await makeHmacToken({ sub: "did:key:zAgent", iss: "other-attestor" });
    await expect(att.verify(jwt, "did:key:zAgent")).rejects.toThrow();
  });

  it("rejects when sub doesn't match the agent DID", async () => {
    const att = new HmacAttestor({ iss: "test-attestor", secret: SECRET });
    const jwt = await makeHmacToken({ sub: "did:key:zVictim" });
    await expect(att.verify(jwt, "did:key:zAttacker")).rejects.toThrow(/sub mismatch/);
  });

  it("rejects expired tokens", async () => {
    const att = new HmacAttestor({ iss: "test-attestor", secret: SECRET });
    const jwt = await makeHmacToken({
      sub: "did:key:zAgent",
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    await expect(att.verify(jwt, "did:key:zAgent")).rejects.toThrow();
  });

  it("rejects tokens signed with a different secret", async () => {
    const att = new HmacAttestor({ iss: "test-attestor", secret: SECRET });
    const jwt = await makeHmacToken({
      sub: "did:key:zAgent",
      secret: new TextEncoder().encode("a-completely-different-secret-of-32+bytes!"),
    });
    await expect(att.verify(jwt, "did:key:zAgent")).rejects.toThrow();
  });
});

describe("JwksAttestor", () => {
  it("verifies an ES256 token against a stub JWKS endpoint", async () => {
    const kid = "test-key-1";
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.use = "sig";
    jwk.alg = "ES256";

    // Patch globalThis.fetch to return the JWKS doc.
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url) => {
      const s = url.toString();
      if (s === "https://attestor.test/jwks.json") {
        return new Response(JSON.stringify({ keys: [jwk] }), {
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("not found", { status: 404 });
    }) as typeof globalThis.fetch;

    try {
      const att = new JwksAttestor({
        iss: "stripe-projects",
        jwksUrl: "https://attestor.test/jwks.json",
      });
      const agentDid = "did:key:z6MkAgent";
      const jwt = await new SignJWT({})
        .setProtectedHeader({ alg: "ES256", kid })
        .setIssuer("stripe-projects")
        .setSubject(agentDid)
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + 60)
        .sign(privateKey);
      const claims = await att.verify(jwt, agentDid);
      expect(claims.iss).toBe("stripe-projects");
      expect(claims.sub).toBe(agentDid);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("refuses non-https JWKS URLs at construction", () => {
    expect(() => new JwksAttestor({
      iss: "x",
      jwksUrl: "http://attestor.test/jwks.json",
    })).toThrow(/MUST be https/);
  });
});

describe("VerifyOptions.audience", () => {
  it("HmacAttestor accepts when aud matches", async () => {
    const att = new HmacAttestor({ iss: "x-svc", secret: SECRET });
    const agentDid = "did:key:zAud";
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("x-svc")
      .setSubject(agentDid)
      .setAudience("did:web:svc.example")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 60)
      .sign(SECRET);
    const claims = await att.verify(jwt, agentDid, { audience: "did:web:svc.example" });
    expect(claims.sub).toBe(agentDid);
  });

  it("HmacAttestor rejects when aud mismatches", async () => {
    const att = new HmacAttestor({ iss: "x-svc", secret: SECRET });
    const agentDid = "did:key:zAud";
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("x-svc")
      .setSubject(agentDid)
      .setAudience("did:web:other.example")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 60)
      .sign(SECRET);
    await expect(
      att.verify(jwt, agentDid, { audience: "did:web:svc.example" }),
    ).rejects.toThrow(/aud/i);
  });

  it("HmacAttestor without audience option does not check aud", async () => {
    const att = new HmacAttestor({ iss: "x-svc", secret: SECRET });
    const agentDid = "did:key:zAud";
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("x-svc")
      .setSubject(agentDid)
      .setAudience("did:web:anywhere.example")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 60)
      .sign(SECRET);
    const claims = await att.verify(jwt, agentDid);
    expect(claims.aud).toBe("did:web:anywhere.example");
  });
});

describe("sub_h validation — AFAP-0006 §10.4", () => {
  const GOOD_SUB_H = "8f3cZ_K9qWmA-LpQ7tVnRsxBcD2yE0HfJgIuYpXoNkM"; // 43-char base64url
  const SHORT_SUB_H = "tooShort"; // <22 chars

  async function tokenWith(extra: Record<string, unknown>): Promise<{ jwt: string; sub: string }> {
    const sub = "did:key:zSubH";
    const jwt = await new SignJWT(extra)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("trust-test")
      .setSubject(sub)
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 60)
      .sign(SECRET);
    return { jwt, sub };
  }

  function attestor() {
    return new HmacAttestor({ iss: "trust-test", secret: SECRET });
  }

  it("accepts a token carrying verification + well-formed sub_h", async () => {
    const { jwt, sub } = await tokenWith({ verification: "oauth", sub_h: GOOD_SUB_H });
    const claims = await attestor().verify(jwt, sub);
    expect(claims.verification).toBe("oauth");
    expect(claims.sub_h).toBe(GOOD_SUB_H);
  });

  it("rejects a verification claim without sub_h (§10.4.1)", async () => {
    const { jwt, sub } = await tokenWith({ verification: "oauth" });
    await expect(attestor().verify(jwt, sub)).rejects.toThrow(/sub_h.*missing or malformed/);
  });

  it("rejects a sub_h shorter than 22 chars (§10.4.2)", async () => {
    const { jwt, sub } = await tokenWith({ verification: "oauth", sub_h: SHORT_SUB_H });
    await expect(attestor().verify(jwt, sub)).rejects.toThrow(/sub_h.*missing or malformed/);
  });

  it("rejects a sub_h containing non-base64url characters", async () => {
    const { jwt, sub } = await tokenWith({
      verification: "oauth",
      sub_h: "has+plus/and=padding-which-violates-base64url-shape",
    });
    await expect(attestor().verify(jwt, sub)).rejects.toThrow(/sub_h/);
  });

  it("accepts a token without verification AND without sub_h (runtime attestor)", async () => {
    const { jwt, sub } = await tokenWith({});
    const claims = await attestor().verify(jwt, sub);
    expect(claims.sub).toBe(sub);
    expect(claims.sub_h).toBeUndefined();
  });

  it("rejects a malformed sub_h even when no verification claim is present", async () => {
    const { jwt, sub } = await tokenWith({ sub_h: SHORT_SUB_H });
    await expect(attestor().verify(jwt, sub)).rejects.toThrow(/sub_h.*not a base64url/);
  });

  it("exposes sub_h on the returned claims for service-side dedup", async () => {
    const { jwt, sub } = await tokenWith({ verification: "payment", sub_h: GOOD_SUB_H });
    const claims = await attestor().verify(jwt, sub);
    // §10.4.4 — services use sub_h as a per-(iss, sub_h) dedup key.
    expect(typeof claims.sub_h).toBe("string");
    expect(claims.sub_h).toMatch(/^[A-Za-z0-9_-]{22,86}$/);
  });
});

describe("trustAttestor() — AFAP-0006 pre-config", () => {
  it("pins iss=afauth-trust and the AFAP JWKS URL", async () => {
    const { trustAttestor, AFAUTH_TRUST_ISS, AFAUTH_TRUST_JWKS_URL } = await import(
      "../index.js"
    );
    const att = trustAttestor();
    expect(att.iss).toBe(AFAUTH_TRUST_ISS);
    expect(att.iss).toBe("afauth-trust");
    expect(AFAUTH_TRUST_JWKS_URL).toBe("https://trust.afauth.org/.well-known/jwks.json");
  });

  it("verifies a real EdDSA token minted by the trust attestor", async () => {
    const { trustAttestor } = await import("../index.js");
    const kid = "tk-test-1";
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.use = "sig";
    jwk.alg = "EdDSA";

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url) => {
      const s = url.toString();
      if (s === "https://staging.afauth.org/.well-known/jwks.json") {
        return new Response(JSON.stringify({ keys: [jwk] }), {
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("not found", { status: 404 });
    }) as typeof globalThis.fetch;

    try {
      const att = trustAttestor({
        jwksUrl: "https://staging.afauth.org/.well-known/jwks.json",
      });
      const agentDid = "did:key:z6MkTrustTest";
      const jwt = await new SignJWT({
        verification: "email",
        // §10.4 — trust attestor MUST include sub_h whenever
        // `verification` is present. Test value is a 43-char base64url.
        sub_h: "8f3cZ_K9qWmA-LpQ7tVnRsxBcD2yE0HfJgIuYpXoNkM",
      })
        .setProtectedHeader({ alg: "EdDSA", kid })
        .setIssuer("afauth-trust")
        .setSubject(agentDid)
        .setAudience("did:web:svc.example")
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + 900)
        .sign(privateKey);
      const claims = await att.verify(jwt, agentDid);
      expect(claims.iss).toBe("afauth-trust");
      expect(claims.sub).toBe(agentDid);
      expect((claims as { verification?: string }).verification).toBe("email");
      expect(claims.sub_h).toMatch(/^[A-Za-z0-9_-]{22,86}$/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("MultiAttestor", () => {
  it("dispatches to the matching iss", async () => {
    const a = new HmacAttestor({ iss: "first", secret: SECRET });
    const b = new HmacAttestor({
      iss: "second",
      secret: new TextEncoder().encode("a-different-secret-of-the-right-length"),
    });
    const multi = new MultiAttestor([a, b]);

    const jwt = await makeHmacToken({ iss: "first", sub: "did:key:zAgent" });
    const claims = await multi.verify(jwt, "did:key:zAgent");
    expect(claims.iss).toBe("first");
  });

  it("rejects unknown issuers", async () => {
    const multi = new MultiAttestor([
      new HmacAttestor({ iss: "first", secret: SECRET }),
    ]);
    const jwt = await makeHmacToken({ iss: "rogue", sub: "did:key:zAgent" });
    await expect(multi.verify(jwt, "did:key:zAgent")).rejects.toThrow(/not accepted/);
  });
});

// ---- §9.2 server-side enforcement ----

function newServer(opts: {
  unclaimedMode?: "free" | "attested_only";
  attestor?: ReturnType<typeof getDefaultAttestor>;
}) {
  const accounts = new MemoryAccountStore();
  return {
    accounts,
    server: new Server({
      nonceStore: new MemoryNonceStore(),
      serviceDid: SERVICE_DID,
      accounts,
      recipients: { email: emailHandler },
      discovery: discoveryFor(opts.unclaimedMode),
      baseUrl: BASE_URL,
      ...(opts.attestor ? { attestor: opts.attestor } : {}),
    }),
  };
}

function getDefaultAttestor() {
  return new HmacAttestor({ iss: "test-attestor", secret: SECRET });
}

describe("Server attested_only enforcement (§9.2)", () => {
  it("attested_only + no header → 401 attestation_required (no account row created)", async () => {
    const { server, accounts } = newServer({
      unclaimedMode: "attested_only",
      attestor: getDefaultAttestor(),
    });
    const agent = await Agent.generate();
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const resp = await server.handleAccountIntrospection(new Request(signed.url, {
      method: signed.method,
      headers: new Headers(signed.headers),
    })).catch((e) => (e as { toResponse: () => Response }).toResponse());
    expect(resp.status).toBe(401);
    const body = await resp.json() as { error: { code: string } };
    expect(body.error.code).toBe("attestation_required");
    // No account row should have been created.
    expect(await accounts.getByAgentDid(agent.did)).toBeNull();
  });

  it("attested_only + valid token → 200 + account created", async () => {
    const { server, accounts } = newServer({
      unclaimedMode: "attested_only",
      attestor: getDefaultAttestor(),
    });
    const agent = await Agent.generate();
    // Server now pins audience to its own serviceDid — tokens must include it.
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

  it("attested_only + token with wrong aud → 401 (cross-service replay defense)", async () => {
    const { server } = newServer({
      unclaimedMode: "attested_only",
      attestor: getDefaultAttestor(),
    });
    const agent = await Agent.generate();
    const jwt = await makeHmacToken({ sub: agent.did, aud: "did:web:wrong.example" });
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

  it("attested_only + invalid token → 401 invalid_attestation (no account row)", async () => {
    const { server, accounts } = newServer({
      unclaimedMode: "attested_only",
      attestor: getDefaultAttestor(),
    });
    const agent = await Agent.generate();
    // Token for a DIFFERENT agent.
    const jwt = await makeHmacToken({ sub: "did:key:zNotThisAgent" });
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const headers = new Headers(signed.headers);
    headers.set("afauth-attestation", jwt);
    const resp = await server.handleAccountIntrospection(new Request(signed.url, {
      method: signed.method, headers,
    })).catch((e) => (e as { toResponse: () => Response }).toResponse());
    expect(resp.status).toBe(401);
    const body = await resp.json() as { error: { code: string } };
    expect(body.error.code).toBe("invalid_attestation");
    expect(await accounts.getByAgentDid(agent.did)).toBeNull();
  });

  it("attested_only declared, header present, but no attestor configured → 503 (server misconfig)", async () => {
    const { server } = newServer({ unclaimedMode: "attested_only" }); // no attestor
    const agent = await Agent.generate();
    const jwt = await makeHmacToken({ sub: agent.did });
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const headers = new Headers(signed.headers);
    headers.set("afauth-attestation", jwt);
    const resp = await server.handleAccountIntrospection(new Request(signed.url, {
      method: signed.method, headers,
    })).catch((e) => (e as { toResponse: () => Response }).toResponse());
    expect(resp.status).toBe(503);
  });

  it("non-attested_only + no header → 200 (signup proceeds normally)", async () => {
    const { server } = newServer({ attestor: getDefaultAttestor() }); // mode undefined
    const agent = await Agent.generate();
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const resp = await server.handleAccountIntrospection(new Request(signed.url, {
      method: signed.method,
      headers: new Headers(signed.headers),
    }));
    expect(resp.status).toBe(200);
  });

  it("non-attested_only + invalid token → still 401 invalid_attestation (lax mode)", async () => {
    const { server } = newServer({ attestor: getDefaultAttestor() });
    const agent = await Agent.generate();
    const jwt = await makeHmacToken({
      sub: agent.did,
      exp: Math.floor(Date.now() / 1000) - 1000, // expired
    });
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const headers = new Headers(signed.headers);
    headers.set("afauth-attestation", jwt);
    const resp = await server.handleAccountIntrospection(new Request(signed.url, {
      method: signed.method, headers,
    })).catch((e) => (e as { toResponse: () => Response }).toResponse());
    expect(resp.status).toBe(401);
    const body = await resp.json() as { error: { code: string } };
    expect(body.error.code).toBe("invalid_attestation");
  });
});
