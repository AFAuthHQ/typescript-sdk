import { describe, expect, it } from "vitest";
import { MemoryNonceStore } from "../index.js";

describe("MemoryNonceStore", () => {
  it("accepts a fresh nonce", async () => {
    const store = new MemoryNonceStore();
    expect(await store.seen("did:key:zAlice", "n1", 60)).toBe(true);
  });

  it("rejects a replayed nonce within TTL", async () => {
    const store = new MemoryNonceStore();
    await store.seen("did:key:zAlice", "n1", 60);
    expect(await store.seen("did:key:zAlice", "n1", 60)).toBe(false);
  });

  it("scopes nonces per keyid", async () => {
    const store = new MemoryNonceStore();
    await store.seen("did:key:zAlice", "n1", 60);
    expect(await store.seen("did:key:zBob", "n1", 60)).toBe(true);
  });
});
