/**
 * KvNonceStore, KvRevocationList, KvRateLimiter behaviour against a
 * miniflare-provided KV namespace.
 *
 * Each store ships with limitations documented in its JSDoc — the
 * 60-second KV TTL floor, eventual consistency in `KvNonceStore`, no
 * automatic expiry in `KvRevocationList`. These tests pin the
 * observable behaviour callers can rely on; they don't try to prove
 * KV consistency guarantees (which miniflare doesn't simulate
 * faithfully anyway).
 */

import { Miniflare } from "miniflare";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { KvNonceStore, KvRateLimiter, KvRevocationList } from "../index.js";

let mf: Miniflare;
let kv: KVNamespace;

beforeEach(async () => {
  mf = new Miniflare({
    modules: true,
    script: `export default { fetch: () => new Response("ok") };`,
    kvNamespaces: ["KV"],
  });
  kv = (await mf.getKVNamespace("KV")) as unknown as KVNamespace;
});

afterEach(async () => {
  await mf.dispose();
});

describe("KvNonceStore", () => {
  it("returns true on first seen and false on the same (keyid, nonce) within TTL", async () => {
    const store = new KvNonceStore(kv);
    const fresh = await store.seen("did:key:zABC", "nonce-1", 60);
    expect(fresh).toBe(true);
    const replay = await store.seen("did:key:zABC", "nonce-1", 60);
    expect(replay).toBe(false);
  });

  it("scopes nonces per keyid (§5.6)", async () => {
    const store = new KvNonceStore(kv);
    expect(await store.seen("did:key:zA", "shared-nonce", 60)).toBe(true);
    expect(await store.seen("did:key:zB", "shared-nonce", 60)).toBe(true);
  });

  it("clamps the KV expirationTtl floor to 60s", async () => {
    // The store's contract: callers may pass any positive ttlSeconds;
    // the store will floor to 60 internally because KV refuses lower.
    // We can't observe the chosen TTL directly through the public API,
    // but we can confirm that passing ttl=1 still succeeds (the put
    // would otherwise throw "expirationTtl must be at least 60 seconds").
    const store = new KvNonceStore(kv);
    await expect(store.seen("did:key:zFloor", "n", 1)).resolves.toBe(true);
  });
});

describe("KvRevocationList", () => {
  it("isRevoked is false for an unknown DID", async () => {
    const list = new KvRevocationList(kv);
    expect(await list.isRevoked("did:key:zUnknown")).toBe(false);
  });

  it("add → isRevoked round-trips", async () => {
    const list = new KvRevocationList(kv);
    await list.add("did:key:zRevoked", "2026-05-25T00:00:00Z");
    expect(await list.isRevoked("did:key:zRevoked")).toBe(true);
    // Distinct DIDs remain unrevoked.
    expect(await list.isRevoked("did:key:zOther")).toBe(false);
  });
});

describe("KvRateLimiter", () => {
  it("accepts up to `limit` calls in a window, then refuses with retryAfter", async () => {
    let now = 1_000_000;
    const limiter = new KvRateLimiter(kv, { now: () => now });
    const cfg = { windowSeconds: 60, limit: 3 };
    for (let i = 0; i < 3; i++) {
      const d = await limiter.take("user:alice", cfg);
      expect(d.ok).toBe(true);
    }
    const refused = await limiter.take("user:alice", cfg);
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.retryAfter).toBeGreaterThan(0);
      expect(refused.remaining).toBe(0);
      expect(refused.resetAt).toBe(1_000_000 + 60);
    }
  });

  it("resets when the window elapses", async () => {
    let now = 2_000_000;
    const limiter = new KvRateLimiter(kv, { now: () => now });
    const cfg = { windowSeconds: 60, limit: 1 };
    expect((await limiter.take("k", cfg)).ok).toBe(true);
    expect((await limiter.take("k", cfg)).ok).toBe(false);
    now += 61;
    expect((await limiter.take("k", cfg)).ok).toBe(true);
  });

  it("isolates buckets by key", async () => {
    const limiter = new KvRateLimiter(kv);
    const cfg = { windowSeconds: 60, limit: 1 };
    expect((await limiter.take("alice", cfg)).ok).toBe(true);
    // Different key, fresh bucket.
    expect((await limiter.take("bob", cfg)).ok).toBe(true);
    expect((await limiter.take("alice", cfg)).ok).toBe(false);
  });

  it("decrements remaining on each accepted call", async () => {
    const limiter = new KvRateLimiter(kv);
    const cfg = { windowSeconds: 60, limit: 3 };
    const first = await limiter.take("k", cfg);
    const second = await limiter.take("k", cfg);
    const third = await limiter.take("k", cfg);
    expect(first.ok && first.remaining).toBe(2);
    expect(second.ok && second.remaining).toBe(1);
    expect(third.ok && third.remaining).toBe(0);
  });
});
