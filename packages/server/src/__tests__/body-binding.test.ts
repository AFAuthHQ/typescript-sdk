/**
 * §5.2 / §5.5 step 7 — the request BODY must be cryptographically bound
 * to the signature. The verifier MUST NOT trust the signer to
 * self-select whether `content-digest` is covered (same rationale as the
 * @method/@target-uri presence check in required-covered-components).
 *
 * The headline attack: a request signed WITHOUT covering content-digest
 * (either a non-conformant client, or a body-less signature onto which an
 * on-path attacker bolts a body) would otherwise verify with an
 * attacker-controlled body — e.g. rewriting the `recipient` of an
 * owner-invitation to redirect the §7 claim magic-link to the attacker.
 * Because `@signature-params` binds the covered-component LIST, an
 * attacker cannot strip content-digest from a signature that already
 * covered it; the gap is the verifier accepting an under-covered body at
 * all. The fix closes both the under-covering-client and the
 * inject-body-into-bodyless-signature paths.
 */

import { describe, expect, it } from "vitest";
import { Agent } from "@afauthhq/agent";
import { MemoryNonceStore, Verifier } from "../index.js";

function toHeaders(rec: Record<string, string>): Headers {
  const h = new Headers();
  for (const [k, v] of Object.entries(rec)) h.set(k, v);
  return h;
}

function reqOf(signed: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | Uint8Array | null;
}) {
  return { method: signed.method, url: signed.url, headers: toHeaders(signed.headers), body: signed.body };
}

function createdPlus1(sigInput: string): () => number {
  const created = Number(/created=(\d+)/.exec(sigInput)![1]);
  return () => created + 1;
}

function verifier(sigInput: string): Verifier {
  return new Verifier({
    nonceStore: new MemoryNonceStore(),
    serviceDid: "did:web:api.example.com",
    now: createdPlus1(sigInput),
  });
}

const OWNER_INVITE = "https://api.example.com/afauth/v1/accounts/me/owner-invitation";

describe("Verifier binds the request body (§5.2 content-digest)", () => {
  it("HEADLINE: rejects a body-bearing request whose signature omits content-digest", async () => {
    // A non-conformant signer covers only @method/@target-uri but sends a
    // body. signRequest still attaches a Content-Digest header, but it is
    // NOT in the covered set — so the body is unauthenticated.
    const agent = await Agent.generate();
    const signed = await agent.signRequest(
      {
        method: "POST",
        url: OWNER_INVITE,
        body: JSON.stringify({ recipient: { type: "email", value: "alice@example.com" } }),
      },
      { coveredComponents: ["@method", "@target-uri"] },
    );
    await expect(verifier(signed.headers["signature-input"]!).verify(reqOf(signed)))
      .rejects.toMatchObject({ code: "invalid_signature" });
  });

  it("HEADLINE: rejects a body injected onto a body-less signature (on-path tamper)", async () => {
    // The agent legitimately signs a body-less request: covered set is
    // [@method, @target-uri], no Content-Digest. An on-path attacker bolts
    // on a body. @signature-params is unchanged so the signature still
    // verifies — the body must not be honoured.
    const agent = await Agent.generate();
    const signed = await agent.signRequest({ method: "POST", url: OWNER_INVITE });
    const tampered = reqOf({
      ...signed,
      body: JSON.stringify({ recipient: { type: "email", value: "attacker@evil.com" } }),
    });
    await expect(verifier(signed.headers["signature-input"]!).verify(tampered))
      .rejects.toMatchObject({ code: "invalid_signature" });
  });

  it("rejects a stray Content-Digest header on a body-less request (§5.5: MUST be omitted)", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({ method: "GET", url: "https://api.example.com/afauth/v1/accounts/me" });
    const tampered = reqOf({
      ...signed,
      headers: { ...signed.headers, "content-digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:" },
    });
    await expect(verifier(signed.headers["signature-input"]!).verify(tampered))
      .rejects.toMatchObject({ code: "invalid_signature" });
  });

  it("regression: accepts a conformant body-bearing request (content-digest covered)", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: OWNER_INVITE,
      body: JSON.stringify({ recipient: { type: "email", value: "alice@example.com" } }),
    });
    const r = await verifier(signed.headers["signature-input"]!).verify(reqOf(signed));
    expect(r.agentDid).toBe(agent.did);
  });

  it("regression: still rejects a tampered body when content-digest IS covered (digest mismatch)", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: OWNER_INVITE,
      body: JSON.stringify({ recipient: { type: "email", value: "alice@example.com" } }),
    });
    const tampered = reqOf({
      ...signed,
      body: JSON.stringify({ recipient: { type: "email", value: "attacker@evil.com" } }),
    });
    await expect(verifier(signed.headers["signature-input"]!).verify(tampered))
      .rejects.toMatchObject({ code: "invalid_signature" });
  });

  it("regression: accepts a conformant body-less GET", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({ method: "GET", url: "https://api.example.com/afauth/v1/accounts/me" });
    const r = await verifier(signed.headers["signature-input"]!).verify(reqOf(signed));
    expect(r.agentDid).toBe(agent.did);
  });
});
