/**
 * Agent SDK: signing requests with Uint8Array bodies.
 *
 * RFC 9421 §2 defines Content-Digest over bytes. JS agents that need
 * to publish binary content (ZIP, multipart, protobuf, gRPC frames)
 * must be able to sign the raw bytes — not a UTF-8 roundtrip of them.
 */
import { describe, expect, it } from "vitest";
import { sha256ContentDigest } from "@afauthhq/core";
import { Agent } from "../index.js";

describe("Agent.signRequest with Uint8Array body", () => {
  it("signs a binary body and the content-digest matches a hash of the raw bytes", async () => {
    const agent = await Agent.generate();
    const body = new Uint8Array([
      0x50, 0x4b, 0x03, 0x04,
      0xff, 0xfe, 0xc0, 0xc1, 0x80, 0x81, 0x82,
    ]);
    const signed = await agent.signRequest({
      method: "POST",
      url: "https://api.example.com/v1/artifacts/upload",
      body,
    });
    expect(signed.headers["content-digest"]).toBe(sha256ContentDigest(body));
    // Body passes through unchanged for the outgoing request.
    expect(signed.body).toBe(body);
  });

  it("does not default content-type to application/json on a binary body", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: "https://api.example.com/v1/artifacts/upload",
      body: new Uint8Array([0xff, 0xfe, 0x00, 0x01]),
    });
    expect(signed.headers["content-type"]).toBeUndefined();
  });

  it("still defaults content-type to application/json on a string body", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: "https://api.example.com/afauth/v1/accounts/me/owner-invitation",
      body: JSON.stringify({ recipient: { type: "email", value: "alice@example.com" } }),
    });
    expect(signed.headers["content-type"]).toBe("application/json");
  });

  it("an empty Uint8Array body is treated as no body (no content-digest, no covered)", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: "https://api.example.com/v1/empty",
      body: new Uint8Array(0),
    });
    expect(signed.headers["content-digest"]).toBeUndefined();
    expect(signed.headers["signature-input"]).not.toContain("content-digest");
  });
});
