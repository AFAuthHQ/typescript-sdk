/**
 * DurableObjectNonceStore tests via miniflare. Exercises the §5.6
 * atomicity guarantee that KvNonceStore can't deliver: under a barrage
 * of concurrent `seen()` calls with the same (keyid, nonce), exactly
 * one returns `true`.
 *
 * The DO actor is the in-package `createNonceDurableObject()` class.
 * miniflare wires it via the `script` + `durableObjects` bindings.
 */

import { Miniflare } from "miniflare";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { DurableObjectNonceStore } from "../index.js";

let mf: Miniflare;
let store: DurableObjectNonceStore;

const WORKER_SCRIPT = `
  export class AFAuthNonceDO {
    constructor(state) {
      this.state = state;
    }
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname !== "/seen" || req.method !== "POST") {
        return new Response("not found", { status: 404 });
      }
      const nonce = url.searchParams.get("nonce");
      const ttlRaw = url.searchParams.get("ttl");
      if (!nonce || !ttlRaw) {
        return Response.json({ error: "missing nonce or ttl" }, { status: 400 });
      }
      const ttl = Math.max(1, Number.parseInt(ttlRaw, 10) || 0);
      const nowSec = Math.floor(Date.now() / 1000);
      const key = "n:" + nonce;
      return this.state.blockConcurrencyWhile(async () => {
        const existing = await this.state.storage.get(key);
        if (existing !== undefined && existing > nowSec) {
          return Response.json({ fresh: false });
        }
        await this.state.storage.put(key, nowSec + ttl);
        return Response.json({ fresh: true });
      });
    }
  }
  export default {
    fetch() { return new Response("ok"); }
  };
`;

beforeEach(async () => {
  mf = new Miniflare({
    modules: true,
    script: WORKER_SCRIPT,
    durableObjects: { AFAUTH_NONCE_DO: "AFAuthNonceDO" },
  });
  const ns = await mf.getDurableObjectNamespace("AFAUTH_NONCE_DO");
  store = new DurableObjectNonceStore(ns as unknown as DurableObjectNamespace);
});

afterEach(async () => {
  await mf.dispose();
});

describe("DurableObjectNonceStore", () => {
  it("returns true on first seen, false on replay", async () => {
    const first = await store.seen("did:key:zAgent", "nonce-1", 60);
    expect(first).toBe(true);
    const replay = await store.seen("did:key:zAgent", "nonce-1", 60);
    expect(replay).toBe(false);
  });

  it("distinct nonces for same keyid are both fresh", async () => {
    expect(await store.seen("did:key:zAgent", "nonce-a", 60)).toBe(true);
    expect(await store.seen("did:key:zAgent", "nonce-b", 60)).toBe(true);
  });

  it("same nonce under different keyids both fresh (§5.6 scope)", async () => {
    expect(await store.seen("did:key:zAgent1", "nonce-x", 60)).toBe(true);
    expect(await store.seen("did:key:zAgent2", "nonce-x", 60)).toBe(true);
  });

  it("atomic under concurrent fan-out: exactly one of N calls returns true", async () => {
    // The DO's blockConcurrencyWhile serializes these — the §C.2
    // atomicity guarantee KvNonceStore cannot provide.
    const N = 20;
    const calls = Array.from({ length: N }, () =>
      store.seen("did:key:zRace", "shared-nonce", 60),
    );
    const results = await Promise.all(calls);
    const trues = results.filter((r) => r === true).length;
    expect(trues).toBe(1);
    expect(results.filter((r) => r === false).length).toBe(N - 1);
  });
});
