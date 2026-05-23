/**
 * Binary-body Content-Digest regression.
 *
 * The Verifier and Server handlers MUST hash the raw request bytes, not
 * a UTF-8-decoded form of them. RFC 9421 §2 defines `Content-Digest`
 * over bytes, so any RFC-conformant agent on Go / Rust / Python that
 * signs a multipart or binary body must verify successfully against an
 * AFAuth service — even when the body contains bytes outside the
 * valid-UTF-8 set (ZIP magic, PNG, protobuf, etc.).
 *
 * Pre-fix bug: `Server.handle*` read bodies via `await req.text()`,
 * which replaces invalid UTF-8 bytes with U+FFFD before
 * `sha256ContentDigest` re-encodes them — the bytes hashed on the
 * server are not the bytes signed by the agent, so verification fails
 * with `invalid_signature`.
 */
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  buildCanonicalInput,
  encodeDidKey,
  sha256ContentDigest,
  type CoveredComponent,
} from "@afauthhq/core";
import {
  MemoryAccountStore,
  MemoryNonceStore,
  Server,
  Verifier,
  consoleEmailHandler,
  type DiscoveryDocument,
} from "../index.js";

const BASE_URL = "https://api.example.com";

const DISCOVERY: DiscoveryDocument = {
  afauth_version: "0.1",
  service_did: "did:web:api.example.com",
  endpoints: {
    accounts: "/afauth/v1/accounts",
    owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
    claim_page: "/claim",
    claim_completion: "/afauth/v1/claim",
  },
  signature_algorithms: ["ed25519"],
  recipient_types: ["email"],
};

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/**
 * Mint a signed request whose body is raw bytes. Mirrors what an
 * RFC-9421-conformant non-JS agent (Go, Rust, Python) would produce:
 * the signature covers `content-digest` over the BYTES, not over a
 * UTF-8 round-trip of them.
 */
function signBinary(opts: {
  method: string;
  url: string;
  body: Uint8Array;
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  created: number;
  expires: number;
  nonce: string;
}): { headers: Headers; did: string } {
  const did = encodeDidKey(opts.publicKey);
  const contentDigest = sha256ContentDigest(opts.body);
  const covered: readonly CoveredComponent[] = ["@method", "@target-uri", "content-digest"];
  const params = {
    created: opts.created,
    expires: opts.expires,
    nonce: opts.nonce,
    keyid: did,
    alg: "ed25519" as const,
  };
  const canonicalInput = buildCanonicalInput(
    { method: opts.method, targetUri: opts.url, contentDigest },
    params,
    covered,
  );
  const sigBytes = ed25519.sign(new TextEncoder().encode(canonicalInput), opts.secretKey);
  const componentList = covered.map((c) => `"${c}"`).join(" ");
  const signatureInput =
    `sig1=(${componentList});` +
    `created=${opts.created};expires=${opts.expires};` +
    `nonce="${opts.nonce}";keyid="${did}";alg="ed25519"`;
  const headers = new Headers({
    "signature-input": signatureInput,
    signature: `sig1=:${bytesToBase64(sigBytes)}:`,
    "content-digest": contentDigest,
    "content-type": "application/zip",
  });
  return { headers, did };
}

describe("Verifier accepts binary (non-UTF-8) bodies as Uint8Array", () => {
  it("verifies a ZIP-magic-prefixed body whose bytes include invalid UTF-8 sequences", async () => {
    const { secretKey, publicKey } = ed25519.keygen();
    // ZIP magic followed by bytes that do not form valid UTF-8.
    const body = new Uint8Array([
      0x50, 0x4b, 0x03, 0x04,
      0xff, 0xfe, 0xc0, 0xc1, 0x80, 0x81, 0x82,
      0x9a, 0xab, 0xcd,
    ]);
    const now = Math.floor(Date.now() / 1000);
    const { headers, did } = signBinary({
      method: "POST",
      url: `${BASE_URL}/v1/artifacts/upload`,
      body,
      secretKey,
      publicKey,
      created: now,
      expires: now + 60,
      nonce: "n".repeat(32),
    });

    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: DISCOVERY.service_did,
      now: () => now + 1,
    });

    const result = await verifier.verify({
      method: "POST",
      url: `${BASE_URL}/v1/artifacts/upload`,
      headers,
      body,
    });
    expect(result.agentDid).toBe(did);
  });

  it("rejects a binary body that has been tampered after signing", async () => {
    const { secretKey, publicKey } = ed25519.keygen();
    const body = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0xff, 0xfe]);
    const now = Math.floor(Date.now() / 1000);
    const { headers } = signBinary({
      method: "POST",
      url: `${BASE_URL}/v1/artifacts/upload`,
      body,
      secretKey,
      publicKey,
      created: now,
      expires: now + 60,
      nonce: "n".repeat(32),
    });
    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: DISCOVERY.service_did,
      now: () => now + 1,
    });
    const tampered = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0xff, 0x00]);
    await expect(
      verifier.verify({
        method: "POST",
        url: `${BASE_URL}/v1/artifacts/upload`,
        headers,
        body: tampered,
      }),
    ).rejects.toMatchObject({ code: "invalid_signature" });
  });

  it("rejects a string body whose UTF-8 encoding does not match the agent-signed bytes", async () => {
    // Reproduces the exact failure mode in the bug report: agent signs
    // bytes; if the server hands the verifier the .text() roundtrip
    // (lossy on invalid UTF-8) the digests no longer match.
    const { secretKey, publicKey } = ed25519.keygen();
    const body = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0xff, 0xfe, 0xc0]);
    const now = Math.floor(Date.now() / 1000);
    const { headers } = signBinary({
      method: "POST",
      url: `${BASE_URL}/v1/artifacts/upload`,
      body,
      secretKey,
      publicKey,
      created: now,
      expires: now + 60,
      nonce: "n".repeat(32),
    });
    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: DISCOVERY.service_did,
      now: () => now + 1,
    });
    // What `await req.text()` would produce — replacement characters
    // for the invalid bytes. This must NOT verify (it is no longer the
    // body the agent signed).
    const lossy = new TextDecoder().decode(body);
    await expect(
      verifier.verify({
        method: "POST",
        url: `${BASE_URL}/v1/artifacts/upload`,
        headers,
        body: lossy,
      }),
    ).rejects.toMatchObject({ code: "invalid_signature" });
  });
});

describe("sha256ContentDigest is byte-identity for Uint8Array input", () => {
  it("Uint8Array and a UTF-8 roundtrip of invalid bytes produce DIFFERENT digests", () => {
    const raw = new Uint8Array([0xff, 0xfe, 0xc0, 0xc1]);
    const lossy = new TextDecoder().decode(raw); // each byte → U+FFFD
    expect(sha256ContentDigest(raw)).not.toBe(sha256ContentDigest(lossy));
  });
});

describe("Server handlers preserve byte-identity on JSON requests", () => {
  // The existing handlers route JSON bodies; this test guards against
  // regressions when the handlers switch from req.text() to
  // req.arrayBuffer() — the verified body must still match what the
  // agent signed.
  it("handleOwnerInvitation still accepts a normal JSON-bodied request", async () => {
    const { Agent } = await import("@afauthhq/agent");
    const agent = await Agent.generate();
    const accounts = new MemoryAccountStore();
    const server = new Server({
      nonceStore: new MemoryNonceStore(),
      serviceDid: DISCOVERY.service_did,
      accounts,
      recipients: { email: consoleEmailHandler },
      discovery: DISCOVERY,
      baseUrl: BASE_URL,
    });
    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "alice@example.com" },
    });
    const init: RequestInit = { method: signed.method, headers: signed.headers };
    if (signed.body !== null) init.body = signed.body as BodyInit;
    const resp = await server.handleOwnerInvitation(new Request(signed.url, init));
    expect(resp.status).toBe(202);
  });
});

describe("Agent → Verifier roundtrip with binary bodies", () => {
  it("agent signs a Uint8Array body and the verifier accepts it through a Request", async () => {
    const { Agent } = await import("@afauthhq/agent");
    const agent = await Agent.generate();
    const body = new Uint8Array([
      0x50, 0x4b, 0x03, 0x04,
      0xff, 0xfe, 0xc0, 0xc1, 0x80, 0x81, 0x82,
    ]);
    const signed = await agent.signRequest({
      method: "POST",
      url: `${BASE_URL}/v1/artifacts/upload`,
      body,
    });
    // Simulate the wire round-trip — the way a service's custom route
    // would do it after the fix: read raw bytes from the Request,
    // pass to verifier.verify().
    const init: RequestInit = {
      method: signed.method,
      headers: signed.headers,
      body: signed.body as BodyInit,
    };
    const wireReq = new Request(signed.url, init);
    const receivedBytes = new Uint8Array(await wireReq.arrayBuffer());

    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: DISCOVERY.service_did,
    });
    const result = await verifier.verify({
      method: wireReq.method,
      url: wireReq.url,
      headers: wireReq.headers,
      body: receivedBytes.length === 0 ? null : receivedBytes,
    });
    expect(result.agentDid).toBe(agent.did);
  });
});

describe("Server.handle* handlers do not corrupt non-UTF-8 bodies", () => {
  // Bug-as-reported: handlers read bodies via `await req.text()`,
  // which replaces invalid UTF-8 bytes with U+FFFD before the
  // verifier hashes them. Result: an agent that signs raw bytes
  // (RFC 9421 §2 — Content-Digest is over BYTES) fails verification
  // with `invalid_signature`.
  //
  // After the fix the handler reads via `arrayBuffer()` and passes
  // the raw bytes to the Verifier; the signature verifies. (The body
  // then fails JSON.parse — which produces `malformed_request`, the
  // correct error for a non-JSON body on a JSON endpoint.)
  it("handleOwnerInvitation with a binary body verifies the signature (then 400-on-JSON)", async () => {
    const { secretKey, publicKey } = ed25519.keygen();
    const did = encodeDidKey(publicKey);
    const accounts = new MemoryAccountStore();
    await accounts.createUnclaimed(did);
    const server = new Server({
      nonceStore: new MemoryNonceStore(),
      serviceDid: DISCOVERY.service_did,
      accounts,
      recipients: { email: consoleEmailHandler },
      discovery: DISCOVERY,
      baseUrl: BASE_URL,
    });

    // A ZIP-magic-prefixed body whose bytes are not valid UTF-8.
    const body = new Uint8Array([
      0x50, 0x4b, 0x03, 0x04,
      0xff, 0xfe, 0xc0, 0xc1, 0x80, 0x81, 0x82,
    ]);
    const url = `${BASE_URL}/afauth/v1/accounts/me/owner-invitation`;
    const now = Math.floor(Date.now() / 1000);
    const { headers } = signBinary({
      method: "POST",
      url,
      body,
      secretKey,
      publicKey,
      created: now,
      expires: now + 60,
      nonce: "n".repeat(32),
    });

    // The Server should NOT throw `invalid_signature` — that would
    // mean the handler corrupted the bytes before hashing. After
    // signature verification passes, JSON.parse will fail and we
    // expect `malformed_request` instead.
    await expect(
      server.handleOwnerInvitation(new Request(url, { method: "POST", headers, body })),
    ).rejects.toMatchObject({ code: "malformed_request" });
  });
});
