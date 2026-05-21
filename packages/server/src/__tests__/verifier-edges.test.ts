/**
 * Verifier edge cases identified in the M0–M4 review:
 *   - clockSkewSeconds boundary (exact = OK; +1 = reject)
 *   - maxSignatureLifetimeSeconds enforcement
 *   - content-digest mismatch (body altered after signing) → 401
 *   - non-ed25519 `alg` → 401
 *   - revocation check runs BEFORE Ed25519 verification (timing/effect)
 *   - Signature-Input tolerant of whitespace
 */

import { describe, expect, it, vi } from "vitest";
import { Agent } from "@afauthhq/agent";
import {
  MemoryNonceStore,
  MemoryRevocationList,
  Verifier,
} from "../index.js";

const BASE_URL = "https://api.example.com";

async function signedGet() {
  const agent = await Agent.generate();
  const signed = await agent.signRequest({
    method: "GET",
    url: `${BASE_URL}/afauth/v1/accounts/me`,
  });
  return { agent, signed };
}

function toHeaders(rec: Record<string, string>): Headers {
  const h = new Headers();
  for (const [k, v] of Object.entries(rec)) h.set(k, v);
  return h;
}

function reqOf(signed: { method: string; url: string; headers: Record<string, string>; body: string | null }) {
  return { method: signed.method, url: signed.url, headers: toHeaders(signed.headers), body: signed.body };
}

describe("Verifier clockSkew boundary", () => {
  it("accepts a request with now == expires + clockSkew (exact boundary)", async () => {
    const { agent, signed } = await signedGet();
    // Parse created/expires out of the signature-input header.
    const params = /created=(\d+);expires=(\d+)/.exec(signed.headers["signature-input"]!)!;
    const expires = Number(params[2]);
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      clockSkewSeconds: 5,
      now: () => expires + 5,
    });
    const r = await v.verify(reqOf(signed));
    expect(r.agentDid).toBe(agent.did);
  });

  it("rejects a request with now == expires + clockSkew + 1 (just past boundary)", async () => {
    const { signed } = await signedGet();
    const params = /created=(\d+);expires=(\d+)/.exec(signed.headers["signature-input"]!)!;
    const expires = Number(params[2]);
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      clockSkewSeconds: 5,
      now: () => expires + 6,
    });
    await expect(v.verify(reqOf(signed))).rejects.toMatchObject({ code: "expired_signature" });
  });

  it("rejects a request with now < created - clockSkew (future-dated past skew)", async () => {
    const { signed } = await signedGet();
    const params = /created=(\d+);expires=(\d+)/.exec(signed.headers["signature-input"]!)!;
    const created = Number(params[1]);
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      clockSkewSeconds: 5,
      now: () => created - 6,
    });
    await expect(v.verify(reqOf(signed))).rejects.toMatchObject({ code: "invalid_signature" });
  });
});

describe("Verifier maxSignatureLifetimeSeconds enforcement", () => {
  it("rejects signatures whose lifetime exceeds the configured maximum (§5.2 300s)", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest(
      { method: "GET", url: `${BASE_URL}/afauth/v1/accounts/me` },
      { expiresInSeconds: 301 },
    );
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      maxSignatureLifetimeSeconds: 300,
      // pin now within the window so we only fail on the lifetime check
      now: () => {
        const created = Number(/created=(\d+)/.exec(signed.headers["signature-input"]!)![1]);
        return created + 1;
      },
    });
    await expect(v.verify(reqOf(signed))).rejects.toMatchObject({ code: "invalid_signature" });
  });
});

describe("Verifier content-digest mismatch", () => {
  it("rejects a POST whose body has been altered after signing", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: `${BASE_URL}/afauth/v1/accounts/me/owner-invitation`,
      body: JSON.stringify({ recipient: { type: "email", value: "alice@example.com" } }),
    });
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      now: () => Number(/created=(\d+)/.exec(signed.headers["signature-input"]!)![1]) + 1,
    });
    // Replace the body with a different JSON of the same approximate shape.
    const tamperedReq = {
      method: signed.method,
      url: signed.url,
      headers: toHeaders(signed.headers),
      body: JSON.stringify({ recipient: { type: "email", value: "eve@example.com" } }),
    };
    await expect(v.verify(tamperedReq)).rejects.toMatchObject({ code: "invalid_signature" });
  });
});

describe("Verifier non-ed25519 alg", () => {
  it("rejects a Signature-Input whose alg is not ed25519", async () => {
    const { signed } = await signedGet();
    // Swap alg="ed25519" → alg="rsa-sha256" in the Signature-Input header.
    const tampered = {
      ...signed,
      headers: { ...signed.headers, "signature-input": signed.headers["signature-input"]!.replace(/alg="ed25519"/, 'alg="rsa-sha256"') },
    };
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
    });
    await expect(v.verify(reqOf(tampered))).rejects.toMatchObject({ code: "invalid_signature" });
  });
});

describe("Verifier revocation check runs before signature verification", () => {
  it("a revoked key with a tampered signature still rejects as revoked_key", async () => {
    const { agent, signed } = await signedGet();
    const revocationList = new MemoryRevocationList();
    await revocationList.add(agent.did, new Date().toISOString());

    // Tamper a single base64 character inside the signature so the
    // bytes decode to something Ed25519 will reject. If revocation
    // is checked first, the response is revoked_key (not invalid).
    const sig = signed.headers.signature!;
    const match = /sig1=:([^:]+):/.exec(sig)!;
    const b64 = match[1]!;
    const flipped = (b64[0] === "A" ? "B" : "A") + b64.slice(1);
    const tampered = {
      ...signed,
      headers: { ...signed.headers, signature: `sig1=:${flipped}:` },
    };
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      revocationList,
      serviceDid: "did:web:example.com",
    });
    await expect(v.verify(reqOf(tampered))).rejects.toMatchObject({ code: "revoked_key" });
  });
});

describe("Signature-Input header tolerance to whitespace", () => {
  it("accepts extra whitespace inside the parameter list", async () => {
    const { agent, signed } = await signedGet();
    // Inject whitespace after the components list and around each `;`.
    const original = signed.headers["signature-input"]!;
    const tolerant = original.replace(/\);/, ") ;").replace(/;/g, " ; ");
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
    });
    const r = await v.verify(reqOf({ ...signed, headers: { ...signed.headers, "signature-input": tolerant } }));
    expect(r.agentDid).toBe(agent.did);
  });
});

describe("ServerOptions.implicitSignup", () => {
  it("with implicitSignup=false, handleAccountIntrospection on unknown account → 404", async () => {
    const { MemoryAccountStore, MemoryNonceStore: NS, MemoryRevocationList: RL, Server } = await import("../index.js");
    const accounts = new MemoryAccountStore();
    const server = new Server({
      nonceStore: new NS(),
      revocationList: new RL(),
      serviceDid: "did:web:example.com",
      accounts,
      recipients: {},
      discovery: {
        afauth_version: "0.1",
        service_did: "did:web:example.com",
        endpoints: {
          accounts: "/afauth/v1/accounts",
          owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
          claim_page: "/claim",
          claim_completion: "/afauth/v1/claim",
        },
        signature_algorithms: ["ed25519"],
      },
      baseUrl: "https://api.example.com",
      implicitSignup: false,
    });

    const agent = await Agent.generate();
    const signed = await agent.buildAccountIntrospection({ baseUrl: "https://api.example.com" });
    const init: RequestInit = { method: signed.method, headers: signed.headers };
    if (signed.body !== null) init.body = signed.body;
    await expect(server.handleAccountIntrospection(new Request(signed.url, init))).rejects.toMatchObject({
      code: "unknown_account",
      status: 404,
    });
  });
});

describe("discovery resolver as function", () => {
  it("Server reads discovery from a function on each request", async () => {
    const { MemoryAccountStore, MemoryNonceStore: NS, MemoryRevocationList: RL, Server } = await import("../index.js");
    let callCount = 0;
    const server = new Server({
      nonceStore: new NS(),
      revocationList: new RL(),
      serviceDid: "did:web:example.com",
      accounts: new MemoryAccountStore(),
      recipients: {},
      discovery: async () => {
        callCount++;
        return {
          afauth_version: "0.1",
          service_did: "did:web:example.com",
          endpoints: {
            accounts: "/afauth/v1/accounts",
            owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
            claim_page: "/claim",
            claim_completion: "/afauth/v1/claim",
          },
          signature_algorithms: ["ed25519"],
        } as const;
      },
      baseUrl: "https://api.example.com",
    });
    await server.handleDiscovery(new Request("https://api.example.com/.well-known/afauth", { method: "GET" }));
    await server.handleDiscovery(new Request("https://api.example.com/.well-known/afauth", { method: "GET" }));
    expect(callCount).toBe(2);
  });
});

describe("MemoryNonceStore lazy GC", () => {
  it("sweeps expired entries on every Nth insert", async () => {
    const store = new MemoryNonceStore({ gcEvery: 4 });
    // Insert 3 short-lived entries; sweep won't run yet.
    for (let i = 0; i < 3; i++) await store.seen("did:key:zX", `n${i}`, 0);
    expect(store.size()).toBe(3);
    // 4th insert triggers a sweep; the prior 3 entries (ttl 0,
    // expiry = now) are stale and removed.
    await store.seen("did:key:zX", "n3", 60);
    // After sweep, only the freshly-inserted entry survives.
    expect(store.size()).toBe(1);
  });
});

describe("MemoryAccountStore reverse index", () => {
  it("§7.3 atomic supersession is O(1) and correct across many invites", async () => {
    const { MemoryAccountStore } = await import("../index.js");
    const accounts = new MemoryAccountStore();
    const did = "did:key:zAlice";
    await accounts.createUnclaimed(did);

    // Issue 10 supersessions; the most recent token wins.
    for (let i = 0; i < 10; i++) {
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      await accounts.setPendingInvitation(
        did,
        { type: "email", value: "alice@example.com" },
        `tok${i}`,
        expiresAt,
      );
    }

    // tok0..tok8 must all be invalid; only tok9 resolves.
    for (let i = 0; i < 9; i++) {
      expect(await accounts.findByPendingToken(`tok${i}`)).toBeNull();
    }
    expect(await accounts.findByPendingToken("tok9")).toMatchObject({ did, state: "INVITED" });
  });
});
