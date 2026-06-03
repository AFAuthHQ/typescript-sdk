/**
 * D1SubHUniquenessStore tests against an in-process D1 backend provided by
 * miniflare, with the §10.4.4 schema (migrations/0002_subh_uniqueness.sql)
 * applied.
 *
 * Coverage:
 *   - claim: first wins, different DID conflicts (existingDid), same DID idempotent
 *   - claim scoping: (iss, sub_h) — same sub_h under a different iss is a distinct slot
 *   - rekey: slot follows a key rotation to the new DID
 *   - releaseByDid: slot frees, principal can re-claim
 *   - atomic claim: concurrent claims for the same slot yield exactly one winner
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Miniflare } from "miniflare";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { D1SubHUniquenessStore } from "../index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA = fs.readFileSync(
  path.join(__dirname, "..", "..", "migrations", "0002_subh_uniqueness.sql"),
  "utf8",
);

let mf: Miniflare;
let store: D1SubHUniquenessStore;

beforeEach(async () => {
  mf = new Miniflare({
    modules: true,
    script: `export default { fetch: () => new Response("ok") };`,
    d1Databases: { DB: ":memory:" },
  });
  const db = await mf.getD1Database("DB");
  const stripped = SCHEMA.split("\n")
    .map((line) => line.replace(/--.*$/, ""))
    .join("\n");
  for (const stmt of stripped.split(/;\s*\n/)) {
    const s = stmt.trim();
    if (!s) continue;
    await db.exec(s.replace(/\n/g, " "));
  }
  store = new D1SubHUniquenessStore(db as unknown as D1Database);
});

afterEach(async () => {
  await mf.dispose();
});

const ISS = "afauth-trust";
const SUB_H = "8f3cZ_K9qWmA-LpQ7tVnRsxBcD2yE0HfJgIuYpXoNkM";
const A = "did:key:zAlice";
const B = "did:key:zBob";
const C = "did:key:zCarol";

describe("D1SubHUniquenessStore", () => {
  it("first claim wins; a different DID conflicts; the same DID is idempotent", async () => {
    expect(await store.claim(ISS, SUB_H, A)).toEqual({ ok: true });
    expect(await store.claim(ISS, SUB_H, A)).toEqual({ ok: true });
    expect(await store.claim(ISS, SUB_H, B)).toEqual({ ok: false, existingDid: A });
  });

  it("scopes the slot by (iss, sub_h): the same sub_h under another iss is a distinct slot", async () => {
    expect(await store.claim("iss-1", SUB_H, A)).toEqual({ ok: true });
    expect(await store.claim("iss-2", SUB_H, B)).toEqual({ ok: true });
  });

  it("rekey moves the slot to the new DID", async () => {
    await store.claim(ISS, SUB_H, A);
    await store.rekey(A, B);
    expect(await store.claim(ISS, SUB_H, C)).toEqual({ ok: false, existingDid: B });
    expect(await store.claim(ISS, SUB_H, B)).toEqual({ ok: true });
  });

  it("releaseByDid frees the slot for a fresh claim", async () => {
    await store.claim(ISS, SUB_H, A);
    await store.releaseByDid(A);
    expect(await store.claim(ISS, SUB_H, B)).toEqual({ ok: true });
  });

  it("rekey/releaseByDid on an unheld DID are no-ops", async () => {
    await expect(store.rekey("did:key:zNobody", B)).resolves.toBeUndefined();
    await expect(store.releaseByDid("did:key:zNobody")).resolves.toBeUndefined();
  });

  it("concurrent claims for the same slot yield exactly one winner (atomic)", async () => {
    const results = await Promise.all([
      store.claim(ISS, SUB_H, A),
      store.claim(ISS, SUB_H, B),
      store.claim(ISS, SUB_H, C),
    ]);
    const winners = results.filter((r) => r.ok);
    expect(winners).toHaveLength(1);
    // The two losers report the same existing winner.
    const losers = results.filter((r) => !r.ok);
    expect(new Set(losers.map((l) => l.existingDid)).size).toBe(1);
  });
});
