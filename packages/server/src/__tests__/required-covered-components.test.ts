/**
 * §5.2 / §5.5 step 1 — the verifier MUST reject a signature whose
 * covered components omit a REQUIRED component (`@method`, `@target-uri`).
 *
 * §5.2 lists `@method` and `@target-uri` as "Required when: Always", and
 * §12.2 leans on `@target-uri` for cross-service replay binding. A
 * verifier that only checks the components a signer *chose* to cover —
 * never that the required ones are present — silently loses that binding
 * for any signer that under-covers. conformance.md §"Signature
 * verification" makes this explicit: "reject requests with extra or
 * missing components."
 *
 * The headline test demonstrates the concrete consequence: a signature
 * that omits `@target-uri` would otherwise verify against a *different*
 * URL — i.e. be replayable across services for the same key (portable
 * DIDs are the §3.3/D.1 default).
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

describe("Verifier rejects missing required covered components (§5.2)", () => {
  it("rejects a signature whose covered set omits @target-uri", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest(
      { method: "GET", url: "https://api.example.com/afauth/v1/accounts/me" },
      { coveredComponents: ["@method"] }, // omits @target-uri
    );
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      now: createdPlus1(signed.headers["signature-input"]!),
    });
    await expect(v.verify(reqOf(signed))).rejects.toMatchObject({ code: "invalid_signature" });
  });

  it("rejects a signature whose covered set omits @method", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest(
      { method: "GET", url: "https://api.example.com/afauth/v1/accounts/me" },
      { coveredComponents: ["@target-uri"] }, // omits @method
    );
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      now: createdPlus1(signed.headers["signature-input"]!),
    });
    await expect(v.verify(reqOf(signed))).rejects.toMatchObject({ code: "invalid_signature" });
  });

  it("rejects a signature that covers nothing (empty component list)", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest(
      { method: "GET", url: "https://api.example.com/afauth/v1/accounts/me" },
      { coveredComponents: [] },
    );
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      now: createdPlus1(signed.headers["signature-input"]!),
    });
    await expect(v.verify(reqOf(signed))).rejects.toMatchObject({ code: "invalid_signature" });
  });

  it("HEADLINE: a signature omitting @target-uri must NOT verify against a different URL (cross-service replay, §12.2)", async () => {
    // The agent signs an operation for service A, omitting @target-uri.
    const agent = await Agent.generate();
    const signedForA = await agent.signRequest(
      { method: "GET", url: "https://service-a.example/op" },
      { coveredComponents: ["@method"] },
    );
    // An adversary (or a malicious service A) replays the *same* signature
    // to service B by rewriting only the URL. The same portable DID has an
    // account at B, and B's nonce store has never seen this nonce.
    const replayedToB = reqOf({ ...signedForA, url: "https://service-b.example/op" });
    const vB = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:service-b.example",
      now: createdPlus1(signedForA.headers["signature-input"]!),
    });
    // With the §5.2 enforcement, B rejects because @target-uri is not
    // covered. Without it, this replay SUCCEEDS — the bug.
    await expect(vB.verify(replayedToB)).rejects.toMatchObject({ code: "invalid_signature" });
  });

  it("still accepts a fully-covered GET (regression guard)", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "GET",
      url: "https://api.example.com/afauth/v1/accounts/me",
    });
    const v = new Verifier({
      nonceStore: new MemoryNonceStore(),
      serviceDid: "did:web:example.com",
      now: createdPlus1(signed.headers["signature-input"]!),
    });
    const r = await v.verify(reqOf(signed));
    expect(r.agentDid).toBe(agent.did);
  });
});
