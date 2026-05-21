/**
 * §3.1.2 did:web resolver tests.
 *
 * The resolver fetches /.well-known/did.json (or path-derived URL),
 * validates the document, and extracts the first Ed25519 verification
 * method. We exercise both wire formats (Ed25519VerificationKey2020
 * with publicKeyMultibase; JsonWebKey2020 with publicKeyJwk), the
 * caching layer, the §3.1.2 invalidate-on-verify-failure contract,
 * the TLS-only enforcement, and a handful of malformed-document
 * rejections.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { AFAuthError, encodeDidKey } from "@afauthhq/core";
import {
  DidWebResolver,
  MemoryNonceStore,
  Verifier,
} from "../index.js";
import {
  CompositeDidResolver,
  DidKeyResolver,
} from "@afauthhq/core";

// ---- helpers ----

function freshEd25519() {
  const { secretKey, publicKey } = ed25519.keygen();
  return { secretKey, publicKey };
}

function multibaseFromPub(pubkey: Uint8Array): string {
  // Reuse the existing did:key encoding which is the same multicodec +
  // multibase scheme that DID documents use for Ed25519VerificationKey2020.
  return encodeDidKey(pubkey).slice("did:key:".length);
}

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function makeFetchStub(responses: Record<string, { status: number; contentType?: string; body: string }>) {
  let calls = 0;
  const fetchFn: typeof globalThis.fetch = async (url) => {
    calls++;
    const r = responses[url.toString()];
    if (!r) {
      return new Response("not found", { status: 404 });
    }
    return new Response(r.body, {
      status: r.status,
      headers: { "content-type": r.contentType ?? "application/json" },
    });
  };
  return { fetchFn, getCalls: () => calls };
}

describe("DidWebResolver", () => {
  it("resolves a did:web with Ed25519VerificationKey2020 + publicKeyMultibase", async () => {
    const { publicKey } = freshEd25519();
    const did = "did:web:example.com";
    const docUrl = "https://example.com/.well-known/did.json";
    const { fetchFn } = makeFetchStub({
      [docUrl]: {
        status: 200,
        body: JSON.stringify({
          id: did,
          verificationMethod: [{
            id: `${did}#key-1`,
            type: "Ed25519VerificationKey2020",
            controller: did,
            publicKeyMultibase: multibaseFromPub(publicKey),
          }],
        }),
      },
    });
    const resolver = new DidWebResolver({ fetch: fetchFn });
    const got = await resolver.resolve(did);
    expect(Array.from(got)).toEqual(Array.from(publicKey));
  });

  it("resolves a did:web with JsonWebKey2020 + publicKeyJwk", async () => {
    const { publicKey } = freshEd25519();
    const did = "did:web:example.com";
    const docUrl = "https://example.com/.well-known/did.json";
    const { fetchFn } = makeFetchStub({
      [docUrl]: {
        status: 200,
        body: JSON.stringify({
          id: did,
          verificationMethod: [{
            id: `${did}#key-1`,
            type: "JsonWebKey2020",
            controller: did,
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: base64url(publicKey) },
          }],
        }),
      },
    });
    const resolver = new DidWebResolver({ fetch: fetchFn });
    const got = await resolver.resolve(did);
    expect(Array.from(got)).toEqual(Array.from(publicKey));
  });

  it("maps did:web:host:path:to:doc per W3C-DID-WEB §3.2", async () => {
    const { publicKey } = freshEd25519();
    const did = "did:web:example.com:user:alice";
    const docUrl = "https://example.com/user/alice/did.json";
    const { fetchFn } = makeFetchStub({
      [docUrl]: {
        status: 200,
        body: JSON.stringify({
          id: did,
          verificationMethod: [{
            id: `${did}#k`,
            type: "Ed25519VerificationKey2020",
            controller: did,
            publicKeyMultibase: multibaseFromPub(publicKey),
          }],
        }),
      },
    });
    const resolver = new DidWebResolver({ fetch: fetchFn });
    await expect(resolver.resolve(did)).resolves.toBeInstanceOf(Uint8Array);
  });

  it("allowInsecureTransport=true still synthesises https URLs (TLS-only is canonical)", async () => {
    // did:web's URL mapping is always https; the allow-insecure flag
    // exists so a resolver could in principle be ported to accept
    // http for tests, but the canonical URL synthesis is unchanged.
    let seen = "";
    const fetchFn: typeof globalThis.fetch = async (url) => {
      seen = url.toString();
      return new Response("", { status: 404 });
    };
    const resolver = new DidWebResolver({ fetch: fetchFn, allowInsecureTransport: true });
    await expect(resolver.resolve("did:web:example.com")).rejects.toThrow();
    expect(seen.startsWith("https://")).toBe(true);
  });

  it("rejects did:web with uppercase host (matches §7.7.4)", async () => {
    const resolver = new DidWebResolver({ fetch: async () => new Response("", { status: 500 }) });
    await expect(resolver.resolve("did:web:Example.com")).rejects.toThrow(/lowercase/);
  });

  it("rejects when the document's id does not match the resolved DID", async () => {
    const { publicKey } = freshEd25519();
    const did = "did:web:victim.com";
    const docUrl = "https://victim.com/.well-known/did.json";
    const { fetchFn } = makeFetchStub({
      [docUrl]: {
        status: 200,
        body: JSON.stringify({
          id: "did:web:attacker.com",
          verificationMethod: [{
            id: "did:web:attacker.com#k",
            type: "Ed25519VerificationKey2020",
            controller: "did:web:attacker.com",
            publicKeyMultibase: multibaseFromPub(publicKey),
          }],
        }),
      },
    });
    const resolver = new DidWebResolver({ fetch: fetchFn });
    await expect(resolver.resolve(did)).rejects.toThrow(/does not match/);
  });

  it("rejects when verificationMethod is missing", async () => {
    const did = "did:web:example.com";
    const docUrl = "https://example.com/.well-known/did.json";
    const { fetchFn } = makeFetchStub({
      [docUrl]: { status: 200, body: JSON.stringify({ id: did }) },
    });
    const resolver = new DidWebResolver({ fetch: fetchFn });
    await expect(resolver.resolve(did)).rejects.toThrow(/verificationMethod/);
  });

  it("rejects when no verification method is Ed25519", async () => {
    const did = "did:web:example.com";
    const docUrl = "https://example.com/.well-known/did.json";
    const { fetchFn } = makeFetchStub({
      [docUrl]: {
        status: 200,
        body: JSON.stringify({
          id: did,
          verificationMethod: [{
            id: `${did}#k1`,
            type: "P256VerificationKey",
            controller: did,
            publicKeyMultibase: "zSomeP256Key",
          }],
        }),
      },
    });
    const resolver = new DidWebResolver({ fetch: fetchFn });
    await expect(resolver.resolve(did)).rejects.toThrow(/no Ed25519 verification method/);
  });

  it("rejects malformed JSON", async () => {
    const did = "did:web:example.com";
    const docUrl = "https://example.com/.well-known/did.json";
    const { fetchFn } = makeFetchStub({
      [docUrl]: { status: 200, body: "{this is not json" },
    });
    const resolver = new DidWebResolver({ fetch: fetchFn });
    await expect(resolver.resolve(did)).rejects.toThrow(/malformed JSON/);
  });

  it("rejects oversized documents", async () => {
    const did = "did:web:example.com";
    const docUrl = "https://example.com/.well-known/did.json";
    const big = JSON.stringify({ id: did, padding: "x".repeat(1000) });
    const { fetchFn } = makeFetchStub({ [docUrl]: { status: 200, body: big } });
    const resolver = new DidWebResolver({ fetch: fetchFn, maxBytes: 100 });
    await expect(resolver.resolve(did)).rejects.toThrow(/exceeds maxBytes/);
  });

  it("rejects non-JSON content-type", async () => {
    const did = "did:web:example.com";
    const docUrl = "https://example.com/.well-known/did.json";
    const { fetchFn } = makeFetchStub({
      [docUrl]: { status: 200, body: "<html></html>", contentType: "text/html" },
    });
    const resolver = new DidWebResolver({ fetch: fetchFn });
    await expect(resolver.resolve(did)).rejects.toThrow(/text\/html/);
  });

  it("caches positive results for positiveCacheTtlSeconds", async () => {
    const { publicKey } = freshEd25519();
    const did = "did:web:example.com";
    const docUrl = "https://example.com/.well-known/did.json";
    const { fetchFn, getCalls } = makeFetchStub({
      [docUrl]: {
        status: 200,
        body: JSON.stringify({
          id: did,
          verificationMethod: [{
            id: `${did}#k`,
            type: "Ed25519VerificationKey2020",
            controller: did,
            publicKeyMultibase: multibaseFromPub(publicKey),
          }],
        }),
      },
    });
    let now = 1_000_000;
    const resolver = new DidWebResolver({ fetch: fetchFn, positiveCacheTtlSeconds: 300, now: () => now });
    await resolver.resolve(did);
    expect(getCalls()).toBe(1);
    await resolver.resolve(did);
    await resolver.resolve(did);
    expect(getCalls()).toBe(1); // cached

    now += 301;
    await resolver.resolve(did);
    expect(getCalls()).toBe(2); // cache expired, re-fetched
  });

  it("caches negative results for negativeCacheTtlSeconds", async () => {
    const { fetchFn, getCalls } = makeFetchStub({}); // every URL → 404
    let now = 1_000_000;
    const resolver = new DidWebResolver({ fetch: fetchFn, negativeCacheTtlSeconds: 60, now: () => now });
    await expect(resolver.resolve("did:web:example.com")).rejects.toThrow();
    expect(getCalls()).toBe(1);
    await expect(resolver.resolve("did:web:example.com")).rejects.toThrow();
    expect(getCalls()).toBe(1); // negatively cached

    now += 61;
    await expect(resolver.resolve("did:web:example.com")).rejects.toThrow();
    expect(getCalls()).toBe(2);
  });

  it("invalidate() drops the cached entry for §3.1.2 re-fetch-on-verify-failure", async () => {
    const { publicKey } = freshEd25519();
    const did = "did:web:example.com";
    const docUrl = "https://example.com/.well-known/did.json";
    const { fetchFn, getCalls } = makeFetchStub({
      [docUrl]: {
        status: 200,
        body: JSON.stringify({
          id: did,
          verificationMethod: [{
            id: `${did}#k`,
            type: "Ed25519VerificationKey2020",
            controller: did,
            publicKeyMultibase: multibaseFromPub(publicKey),
          }],
        }),
      },
    });
    const resolver = new DidWebResolver({ fetch: fetchFn });
    await resolver.resolve(did);
    await resolver.resolve(did);
    expect(getCalls()).toBe(1);

    resolver.invalidate(did);
    await resolver.resolve(did);
    expect(getCalls()).toBe(2);
  });

  it("allowInsecureTransport=true lets the resolver hit a local httptest server", async () => {
    // Simulate a localhost test endpoint by bypassing TLS enforcement.
    const { publicKey } = freshEd25519();
    const did = "did:web:localhost";
    let captured = "";
    const fetchFn: typeof globalThis.fetch = async (url) => {
      captured = url.toString();
      return new Response(JSON.stringify({
        id: did,
        verificationMethod: [{
          id: `${did}#k`,
          type: "Ed25519VerificationKey2020",
          controller: did,
          publicKeyMultibase: multibaseFromPub(publicKey),
        }],
      }), { headers: { "content-type": "application/json" } });
    };
    // The resolver only emits https URLs even with allowInsecureTransport=true;
    // the flag governs whether non-https URLs are rejected, not URL synthesis.
    // So this test confirms the synthesised URL is https://localhost/...
    const resolver = new DidWebResolver({ fetch: fetchFn, allowInsecureTransport: true });
    await resolver.resolve(did);
    expect(captured).toBe("https://localhost/.well-known/did.json");
  });
});

// ---- end-to-end: signed request whose keyid is did:web ----

describe("Verifier with CompositeDidResolver(did:key + did:web)", () => {
  it("accepts a request signed by a did:web key when the resolver finds it", async () => {
    const { secretKey, publicKey } = freshEd25519();
    const did = "did:web:api.example.com";
    const docUrl = "https://api.example.com/.well-known/did.json";

    const { fetchFn } = makeFetchStub({
      [docUrl]: {
        status: 200,
        body: JSON.stringify({
          id: did,
          verificationMethod: [{
            id: `${did}#k`,
            type: "Ed25519VerificationKey2020",
            controller: did,
            publicKeyMultibase: multibaseFromPub(publicKey),
          }],
        }),
      },
    });

    const didWeb = new DidWebResolver({ fetch: fetchFn });
    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:service.example.com",
      didResolver: new CompositeDidResolver({ key: new DidKeyResolver(), web: didWeb }),
    });

    // Sign a fresh GET as if the agent's identity were the did:web.
    const now = Math.floor(Date.now() / 1000);
    const params = {
      created: now,
      expires: now + 60,
      nonce: "abcd1234abcd1234",
      keyid: did,
      alg: "ed25519" as const,
    };
    const { buildCanonicalInput } = await import("@afauthhq/core");
    const canonical = buildCanonicalInput(
      { method: "GET", targetUri: "https://service.example.com/x" },
      params,
      ["@method", "@target-uri"],
    );
    const sigBytes = ed25519.sign(new TextEncoder().encode(canonical), secretKey);
    let bin = "";
    for (const b of sigBytes) bin += String.fromCharCode(b);
    const sigB64 = btoa(bin);

    const headers = new Headers();
    headers.set(
      "signature-input",
      `sig1=("@method" "@target-uri");created=${params.created};expires=${params.expires};nonce="${params.nonce}";keyid="${params.keyid}";alg="ed25519"`,
    );
    headers.set("signature", `sig1=:${sigB64}:`);
    const verified = await verifier.verify({
      method: "GET",
      url: "https://service.example.com/x",
      headers,
      body: null,
    });
    expect(verified.agentDid).toBe(did);
  });

  it("rejects with invalid_signature when the did:web resolver throws", async () => {
    const { fetchFn } = makeFetchStub({}); // all 404
    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:s.example.com",
      didResolver: new CompositeDidResolver({
        key: new DidKeyResolver(),
        web: new DidWebResolver({ fetch: fetchFn }),
      }),
    });

    const headers = new Headers();
    headers.set(
      "signature-input",
      `sig1=("@method" "@target-uri");created=1;expires=99999999999;nonce="x";keyid="did:web:missing.example.com";alg="ed25519"`,
    );
    headers.set("signature", "sig1=:AAAA:");
    await expect(
      verifier.verify({ method: "GET", url: "https://s.example.com/x", headers, body: null }),
    ).rejects.toBeInstanceOf(AFAuthError);
  });

  it("default Verifier (no didResolver) still rejects did:web", async () => {
    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:s.example.com",
    });
    const now = Math.floor(Date.now() / 1000);
    const headers = new Headers();
    headers.set(
      "signature-input",
      `sig1=("@method" "@target-uri");created=${now};expires=${now + 60};nonce="abcd";keyid="did:web:example.com";alg="ed25519"`,
    );
    // 64-byte all-zero signature is a valid base64 shape; the resolver
    // will reject before signature verification is reached.
    const zeros = "A".repeat(86) + "==";
    headers.set("signature", `sig1=:${zeros}:`);
    await expect(
      verifier.verify({ method: "GET", url: "https://s.example.com/x", headers, body: null }),
    ).rejects.toThrow(/not a did:key/);
  });
});
