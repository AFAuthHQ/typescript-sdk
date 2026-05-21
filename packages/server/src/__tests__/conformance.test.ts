import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CoveredComponent, SignatureParams } from "@afauthhq/core";
import { MemoryNonceStore, Verifier } from "../index.js";

const SIGS_DIR = join(__dirname, "..", "..", "..", "..", "vendor", "spec-vectors", "signatures");

interface Vector {
  name: string;
  request: { method: string; target_uri: string; body: string | null };
  content_digest: string | null;
  covered_components: readonly CoveredComponent[];
  signature_params: SignatureParams;
  canonical_signature_input: string;
  signature_hex: string;
  public_key_did: string;
}

function loadVectors(): Vector[] {
  return readdirSync(SIGS_DIR)
    .filter((f) => f.endsWith(".json") && !f.startsWith("_"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(SIGS_DIR, f), "utf8")) as Vector);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Build the HTTP headers a real request would carry for this vector. */
function buildHeaders(v: Vector): Headers {
  const headers = new Headers();
  const p = v.signature_params;
  const componentList = v.covered_components.map((c) => `"${c}"`).join(" ");
  const sigInput =
    `sig1=(${componentList});` +
    `created=${p.created};expires=${p.expires};` +
    `nonce="${p.nonce}";keyid="${p.keyid}";alg="${p.alg}"`;
  headers.set("signature-input", sigInput);

  const sigBytes = hexToBytes(v.signature_hex);
  headers.set("signature", `sig1=:${bytesToBase64(sigBytes)}:`);

  if (v.content_digest) headers.set("content-digest", v.content_digest);
  return headers;
}

describe("Verifier.verify against vendored conformance vectors", () => {
  for (const v of loadVectors()) {
    it(`${v.name}: verifies through Verifier.verify`, async () => {
      // Pin "now" inside the signature's validity window for deterministic tests.
      const verifier = new Verifier({
        nonceStore: new MemoryNonceStore(),
        serviceDid: "did:web:example.com",
        now: () => v.signature_params.created + 1,
      });

      const result = await verifier.verify({
        method: v.request.method,
        url: v.request.target_uri,
        headers: buildHeaders(v),
        body: v.request.body,
      });

      expect(result.agentDid).toBe(v.public_key_did);
      expect(result.method).toBe(v.request.method);
      expect(result.url).toBe(v.request.target_uri);
      expect(result.body).toBe(v.request.body);
    });
  }
});

describe("Verifier.verify error paths", () => {
  const v = loadVectors()[0]!;

  function makeVerifier() {
    return new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      now: () => v.signature_params.created + 1,
    });
  }

  function makeRequest(headers: Headers) {
    return {
      method: v.request.method,
      url: v.request.target_uri,
      headers,
      body: v.request.body,
    };
  }

  it("rejects when Signature-Input is missing", async () => {
    const verifier = makeVerifier();
    const headers = buildHeaders(v);
    headers.delete("signature-input");
    await expect(verifier.verify(makeRequest(headers))).rejects.toThrow(/Signature-Input/);
  });

  it("rejects expired signatures", async () => {
    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      now: () => v.signature_params.expires + 100,
    });
    await expect(verifier.verify(makeRequest(buildHeaders(v)))).rejects.toThrow(/expired/);
  });

  it("rejects replayed nonces", async () => {
    const verifier = makeVerifier();
    await verifier.verify(makeRequest(buildHeaders(v)));
    await expect(verifier.verify(makeRequest(buildHeaders(v)))).rejects.toThrow(/nonce/);
  });

  it("rejects tampered signature bytes", async () => {
    const verifier = makeVerifier();
    const headers = buildHeaders(v);
    const bad = hexToBytes(v.signature_hex);
    bad[0] = bad[0]! ^ 0xff;
    headers.set("signature", `sig1=:${bytesToBase64(bad)}:`);
    await expect(verifier.verify(makeRequest(headers))).rejects.toThrow(/did not verify/);
  });
});
