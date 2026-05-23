/**
 * D1AccountStore tests against an in-process D1 backend provided by
 * miniflare. The test miniflare instance is initialised once per test
 * with the v0.1 schema (migrations/0001_init.sql) applied.
 *
 * Coverage:
 *   - createUnclaimed: idempotent
 *   - setPendingInvitation: §7.3 atomic supersession (UNIQUE constraint)
 *   - completeClaimByToken: state transition + invitation cleanup
 *   - rotateKey: did swap, pending invitation FK update
 *   - revoke: revoked flag persists
 *   - findByPendingToken: expiry drops stale entries
 *   - get: pendingRecipient surfaces when an invitation is open
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Miniflare } from "miniflare";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { D1AccountStore } from "../index.js";
import type { Recipient } from "@afauthhq/core";
import type { Account } from "@afauthhq/server";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA = fs.readFileSync(
  path.join(__dirname, "..", "..", "migrations", "0001_init.sql"),
  "utf8",
);

let mf: Miniflare;
let store: D1AccountStore;

beforeEach(async () => {
  mf = new Miniflare({
    modules: true,
    script: `export default { fetch: () => new Response("ok") };`,
    d1Databases: { DB: ":memory:" },
  });
  const db = await mf.getD1Database("DB");
  // miniflare's `exec` accepts a single statement; split the migration
  // file on `;` boundaries (none of our statements contain a `;` inside
  // a string literal, so a trivial split is safe). Strip `-- comments`
  // line-by-line BEFORE collapsing newlines — otherwise a `--` comment
  // runs into the rest of the statement after newlines are removed.
  const stripped = SCHEMA.split("\n")
    .map((line) => line.replace(/--.*$/, ""))
    .join("\n");
  for (const stmt of stripped.split(/;\s*\n/)) {
    const s = stmt.trim();
    if (!s) continue;
    await db.exec(s.replace(/\n/g, " "));
  }
  // D1AccountStore's `D1Database` type matches miniflare's binding.
  store = new D1AccountStore(db as unknown as D1Database);
});

afterEach(async () => {
  await mf.dispose();
});

const aliceEmail: Recipient = { type: "email", value: "alice@example.com" };
const bobEmail: Recipient = { type: "email", value: "bob@example.com" };

describe("D1AccountStore", () => {
  it("createUnclaimed is idempotent and starts in UNCLAIMED", async () => {
    const first = await store.createUnclaimed("did:key:zAgent");
    expect(first.state).toBe("UNCLAIMED");
    const second = await store.createUnclaimed("did:key:zAgent");
    expect(second.did).toBe(first.did);
    expect(second.state).toBe("UNCLAIMED");
  });

  it("get returns null for an unknown did", async () => {
    expect(await store.get("did:key:zNope")).toBeNull();
  });

  it("setPendingInvitation transitions to INVITED and stores recipient", async () => {
    await store.createUnclaimed("did:key:zAgent");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation("did:key:zAgent", aliceEmail, "token-1", expiresAt);
    const a = await store.get("did:key:zAgent");
    expect(a?.state).toBe("INVITED");
    expect(a?.pendingRecipient).toEqual(aliceEmail);
  });

  it("setPendingInvitation atomically supersedes a prior invitation (§7.3)", async () => {
    await store.createUnclaimed("did:key:zAgent");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation("did:key:zAgent", aliceEmail, "token-1", expiresAt);
    await store.setPendingInvitation("did:key:zAgent", bobEmail, "token-2", expiresAt);

    expect(await store.findByPendingToken("token-1")).toBeNull(); // superseded
    const viaNew = await store.findByPendingToken("token-2");
    expect(viaNew?.pendingRecipient).toEqual(bobEmail);
  });

  it("findByPendingToken drops expired entries", async () => {
    await store.createUnclaimed("did:key:zAgent");
    const past = new Date(Date.now() - 1000).toISOString();
    // Insert directly through the public path; setPendingInvitation
    // accepts past expiresAt without complaint (the SDK is responsible
    // for validating freshness elsewhere).
    await store.setPendingInvitation("did:key:zAgent", aliceEmail, "token-old", past);
    expect(await store.findByPendingToken("token-old")).toBeNull();
  });

  it("completeClaimByToken transitions to CLAIMED and removes the invitation", async () => {
    await store.createUnclaimed("did:key:zAgent");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation("did:key:zAgent", aliceEmail, "token-1", expiresAt);

    const owner: NonNullable<Account["owner"]> = {
      identity: aliceEmail,
      userId: "usr_alice",
      claimedAt: new Date().toISOString(),
    };
    const claimed = await store.completeClaimByToken("token-1", owner);
    expect(claimed?.state).toBe("CLAIMED");
    expect(claimed?.owner).toEqual(owner);
    // The invitation row is gone.
    expect(await store.findByPendingToken("token-1")).toBeNull();
    // The account row's pendingRecipient is not surfaced post-claim.
    const fetched = await store.get("did:key:zAgent");
    expect(fetched?.pendingRecipient).toBeUndefined();
  });

  it("rotateKey swaps the account DID and re-points any pending invitation", async () => {
    await store.createUnclaimed("did:key:zOld");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation("did:key:zOld", aliceEmail, "token-r", expiresAt);

    await store.rotateKey("did:key:zOld", "did:key:zNew", new Date().toISOString());

    expect(await store.get("did:key:zOld")).toBeNull();
    const fresh = await store.get("did:key:zNew");
    expect(fresh).not.toBeNull();
    expect(fresh?.state).toBe("INVITED");
    expect(fresh?.pendingRecipient).toEqual(aliceEmail);

    // The token still resolves; just points at the new DID now.
    const viaToken = await store.findByPendingToken("token-r");
    expect(viaToken?.did).toBe("did:key:zNew");
  });

  it("revoke sets the revoked flag", async () => {
    await store.createUnclaimed("did:key:zAgent");
    await store.revoke("did:key:zAgent", new Date().toISOString());
    const a = await store.get("did:key:zAgent");
    expect(a?.revoked).toBe(true);
  });

  it("setPendingInvitation on a revoked account throws revoked_key", async () => {
    await store.createUnclaimed("did:key:zAgent");
    await store.revoke("did:key:zAgent", new Date().toISOString());
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await expect(
      store.setPendingInvitation("did:key:zAgent", aliceEmail, "t", expiresAt),
    ).rejects.toThrow(/revoked/);
  });

  it("setPendingInvitation on a CLAIMED account throws already_claimed", async () => {
    await store.createUnclaimed("did:key:zAgent");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation("did:key:zAgent", aliceEmail, "t1", expiresAt);
    await store.completeClaimByToken("t1", {
      identity: aliceEmail,
      userId: "u",
      claimedAt: new Date().toISOString(),
    });
    await expect(
      store.setPendingInvitation("did:key:zAgent", aliceEmail, "t2", expiresAt),
    ).rejects.toThrow(/already claimed/);
  });

  it("setPendingInvitation on an unknown account throws unknown_account", async () => {
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await expect(
      store.setPendingInvitation("did:key:zGhost", aliceEmail, "t", expiresAt),
    ).rejects.toThrow(/does not exist/);
  });

  it("get surfaces pendingRecipient when an invitation is open", async () => {
    await store.createUnclaimed("did:key:zAgent");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation("did:key:zAgent", aliceEmail, "tt", expiresAt);
    const fetched = await store.get("did:key:zAgent");
    expect(fetched?.state).toBe("INVITED");
    expect(fetched?.pendingRecipient).toEqual(aliceEmail);
  });

  describe("SweepableAccountStore", () => {
    it("listOpenAccounts returns UNCLAIMED + INVITED, omits CLAIMED", async () => {
      await store.createUnclaimed("did:key:zUnclaimed");

      await store.createUnclaimed("did:key:zInvited");
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      await store.setPendingInvitation("did:key:zInvited", aliceEmail, "tok", expiresAt);

      await store.createUnclaimed("did:key:zClaimed");
      await store.setPendingInvitation("did:key:zClaimed", bobEmail, "tok2", expiresAt);
      await store.completeClaimByToken("tok2", {
        identity: bobEmail,
        userId: "u_b",
        claimedAt: new Date().toISOString(),
      });

      const open = await store.listOpenAccounts();
      const dids = open.map((a) => a.did).sort();
      expect(dids).toEqual(["did:key:zInvited", "did:key:zUnclaimed"]);
    });

    it("expire flips state to EXPIRED and drops the pending invitation row", async () => {
      await store.createUnclaimed("did:key:zStale");
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      await store.setPendingInvitation("did:key:zStale", aliceEmail, "stale-tok", expiresAt);

      const expiredAt = new Date().toISOString();
      const out = await store.expire("did:key:zStale", expiredAt);
      expect(out.state).toBe("EXPIRED");

      // listOpenAccounts no longer surfaces it.
      const open = await store.listOpenAccounts();
      expect(open.map((a) => a.did)).not.toContain("did:key:zStale");

      // The pending invitation has been dropped.
      expect(await store.findByPendingToken("stale-tok")).toBeNull();
    });

    it("expire is idempotent on already-EXPIRED accounts", async () => {
      await store.createUnclaimed("did:key:zAgent");
      await store.expire("did:key:zAgent", new Date().toISOString());
      const again = await store.expire("did:key:zAgent", new Date().toISOString());
      expect(again.state).toBe("EXPIRED");
    });

    it("expire on CLAIMED throws already_claimed (Appendix A forbids the transition)", async () => {
      await store.createUnclaimed("did:key:zClaimed");
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      await store.setPendingInvitation("did:key:zClaimed", bobEmail, "tk", expiresAt);
      await store.completeClaimByToken("tk", {
        identity: bobEmail,
        userId: "u",
        claimedAt: new Date().toISOString(),
      });
      await expect(
        store.expire("did:key:zClaimed", new Date().toISOString()),
      ).rejects.toThrow(/CLAIMED/);
    });

    it("expire on unknown account throws unknown_account", async () => {
      await expect(store.expire("did:key:zNope", new Date().toISOString())).rejects.toThrow(
        /does not exist/,
      );
    });
  });
});
