import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Agent } from "@afauthhq/agent";
import { MemoryNonceStore, Verifier } from "../index.js";

const VENDOR_DIR = join(__dirname, "..", "..", "..", "..", "vendor", "spec-vectors");

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

interface KeypairFixture {
  did_key: string;
  private_key_raw_hex: string;
}

const keypair: KeypairFixture = JSON.parse(
  readFileSync(join(VENDOR_DIR, "keypair.json"), "utf8"),
);

describe("Agent → Verifier roundtrip", () => {
  it("fresh keypair: agent signs, verifier accepts", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "GET",
      url: "https://api.example.com/afauth/v1/accounts/me",
    });

    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
    });

    const headers = new Headers();
    for (const [k, v] of Object.entries(signed.headers)) headers.set(k, v);

    const result = await verifier.verify({
      method: signed.method,
      url: signed.url,
      headers,
      body: signed.body,
    });
    expect(result.agentDid).toBe(agent.did);
  });

  it("POST with body: content-digest is included and verifies", async () => {
    const agent = await Agent.generate();
    const body = JSON.stringify({ recipient: { type: "email", value: "alice@example.com" } });
    const signed = await agent.signRequest({
      method: "POST",
      url: "https://api.example.com/afauth/v1/accounts/me/owner-invitation",
      body,
    });

    expect(signed.headers["content-digest"]).toMatch(/^sha-256=:.+:$/);

    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
    });
    const headers = new Headers();
    for (const [k, v] of Object.entries(signed.headers)) headers.set(k, v);

    const result = await verifier.verify({
      method: signed.method,
      url: signed.url,
      headers,
      body: signed.body,
    });
    expect(result.agentDid).toBe(agent.did);
  });

  it("reference keypair derives the committed did:key", async () => {
    const agent = await Agent.fromPrivateKey(hexToBytes(keypair.private_key_raw_hex));
    expect(agent.did).toBe(keypair.did_key);
  });

  it("two signed requests reuse fresh nonces (so neither is rejected as replay)", async () => {
    const agent = await Agent.generate();
    const verifier = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
    });

    for (let i = 0; i < 2; i++) {
      const signed = await agent.signRequest({
        method: "GET",
        url: "https://api.example.com/afauth/v1/accounts/me",
      });
      const headers = new Headers();
      for (const [k, v] of Object.entries(signed.headers)) headers.set(k, v);
      await expect(
        verifier.verify({ method: signed.method, url: signed.url, headers, body: signed.body }),
      ).resolves.toMatchObject({ agentDid: agent.did });
    }
  });
});
