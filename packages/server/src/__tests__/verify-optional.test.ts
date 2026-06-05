/**
 * Verifier.verifyOptional — the "optional auth" entry point for endpoints that
 * allow anonymous calls but grant more to an authenticated agent.
 */
import { describe, expect, it } from "vitest";
import { Agent } from "@afauthhq/agent";
import { AFAuthError } from "@afauthhq/core";
import { MemoryNonceStore, Verifier } from "../index.js";

function verifier() {
  return new Verifier({ nonceStore: new MemoryNonceStore(), serviceDid: "did:web:example.com" });
}

function toHeaders(h: Record<string, string>): Headers {
  const headers = new Headers();
  for (const [k, v] of Object.entries(h)) headers.set(k, v);
  return headers;
}

describe("Verifier.verifyOptional (anonymous-allowed endpoints)", () => {
  it("returns { authenticated: false } when no AFAuth credentials are present", async () => {
    const res = await verifier().verifyOptional({
      method: "GET",
      url: "https://api.example.com/api/data",
      headers: new Headers(),
      body: null,
    });
    expect(res.authenticated).toBe(false);
  });

  it("returns the authenticated agent when a valid signature is present", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "GET",
      url: "https://api.example.com/api/data",
    });
    const res = await verifier().verifyOptional({
      method: signed.method,
      url: signed.url,
      headers: toHeaders(signed.headers),
      body: signed.body,
    });
    expect(res.authenticated).toBe(true);
    if (res.authenticated) expect(res.request.agentDid).toBe(agent.did);
  });

  it("throws (does not silently downgrade) when credentials are present but invalid", async () => {
    await expect(
      verifier().verifyOptional({
        method: "GET",
        url: "https://api.example.com/api/data",
        headers: toHeaders({ "signature-input": "garbage" }),
        body: null,
      }),
    ).rejects.toBeInstanceOf(AFAuthError);
  });

  it("treats a lone AFAuth-Attestation as an attempt (verifies rather than serving anonymous)", async () => {
    await expect(
      verifier().verifyOptional({
        method: "GET",
        url: "https://api.example.com/api/data",
        headers: toHeaders({ "afauth-attestation": "eyJ.x.y" }),
        body: null,
      }),
    ).rejects.toBeInstanceOf(AFAuthError);
  });
});
