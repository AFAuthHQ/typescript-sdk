/**
 * D1AccountStore tests against an in-process D1 backend (miniflare),
 * initialised per test with the multi-agent schema (migrations/0001_init.sql).
 *
 * Coverage:
 *   - signupAgent: (iss, sub_h) grouping (one account, many devices), atomic;
 *     no-principal singletons; idempotent on did
 *   - setPendingInvitation: §7.3 atomic supersession
 *   - completeClaimByToken: state transition + invitation cleanup
 *   - rotateAgent: credential swap, account_id stable
 *   - revoke (whole account) / revokeAgent (single device)
 *   - findByPendingToken: expiry drops stale entries
 *   - SweepableAccountStore: listOpenAccounts / expire
 *   - reKey (§8.2 resume)
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
  const stripped = SCHEMA.split("\n")
    .map((line) => line.replace(/--.*$/, ""))
    .join("\n");
  for (const stmt of stripped.split(/;\s*\n/)) {
    const s = stmt.trim();
    if (!s) continue;
    await db.exec(s.replace(/\n/g, " "));
  }
  store = new D1AccountStore(db as unknown as D1Database);
});

afterEach(async () => {
  await mf.dispose();
});

const aliceEmail: Recipient = { type: "email", value: "alice@example.com" };
const bobEmail: Recipient = { type: "email", value: "bob@example.com" };
const SUB_H = "8f3cZ_K9qWmA-LpQ7tVnRsxBcD2yE0HfJgIuYpXoNkM";

/** Seed a singleton account for `did`; returns its account_id. */
async function seed(did: string): Promise<string> {
  return (await store.signupAgent({ did })).account.accountId;
}

describe("D1AccountStore — multi-agent model", () => {
  it("signupAgent: a second device sharing (iss, sub_h) joins the same account", async () => {
    const P = { iss: "afauth-trust", subH: SUB_H };
    const first = await store.signupAgent({ did: "did:key:zPc", principal: P });
    expect(first.attached).toBe(false);
    const second = await store.signupAgent({ did: "did:key:zPhone", principal: P });
    expect(second.attached).toBe(true);
    expect(second.account.accountId).toBe(first.account.accountId);
    expect(second.account.agents.map((a) => a.did).sort()).toEqual(
      ["did:key:zPc", "did:key:zPhone"].sort(),
    );
    expect((await store.getByAgentDid("did:key:zPc"))!.accountId).toBe(first.account.accountId);
    expect((await store.getByAgentDid("did:key:zPhone"))!.accountId).toBe(first.account.accountId);
    expect((await store.findByPrincipal(P.iss, P.subH))!.accountId).toBe(first.account.accountId);
  });

  it("signupAgent: no-principal agents get distinct singletons; idempotent on did", async () => {
    const a = await store.signupAgent({ did: "did:key:zA" });
    const b = await store.signupAgent({ did: "did:key:zB" });
    expect(a.account.accountId).not.toBe(b.account.accountId);
    const again = await store.signupAgent({ did: "did:key:zA" });
    expect(again.attached).toBe(false);
    expect(again.account.accountId).toBe(a.account.accountId);
  });

  it("getByAgentDid returns null for an unknown did", async () => {
    expect(await store.getByAgentDid("did:key:zNope")).toBeNull();
  });

  it("setPendingInvitation transitions to INVITED and stores recipient", async () => {
    const id = await seed("did:key:zAgent");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation(id, aliceEmail, "token-1", expiresAt);
    const a = await store.getByAgentDid("did:key:zAgent");
    expect(a?.state).toBe("INVITED");
    expect(a?.pendingRecipient).toEqual(aliceEmail);
  });

  it("setPendingInvitation atomically supersedes a prior invitation (§7.3)", async () => {
    const id = await seed("did:key:zAgent");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation(id, aliceEmail, "token-1", expiresAt);
    await store.setPendingInvitation(id, bobEmail, "token-2", expiresAt);
    expect(await store.findByPendingToken("token-1")).toBeNull();
    expect((await store.findByPendingToken("token-2"))?.pendingRecipient).toEqual(bobEmail);
  });

  it("findByPendingToken drops expired entries", async () => {
    const id = await seed("did:key:zAgent");
    const past = new Date(Date.now() - 1000).toISOString();
    await store.setPendingInvitation(id, aliceEmail, "token-old", past);
    expect(await store.findByPendingToken("token-old")).toBeNull();
  });

  it("completeClaimByToken transitions to CLAIMED and removes the invitation", async () => {
    const id = await seed("did:key:zAgent");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation(id, aliceEmail, "token-1", expiresAt);
    const owner: NonNullable<Account["owner"]> = {
      identity: aliceEmail,
      userId: "usr_alice",
      claimedAt: new Date().toISOString(),
    };
    const claimed = await store.completeClaimByToken("token-1", owner);
    expect(claimed?.state).toBe("CLAIMED");
    expect(claimed?.owner).toEqual(owner);
    expect(await store.findByPendingToken("token-1")).toBeNull();
    expect((await store.getByAgentDid("did:key:zAgent"))?.pendingRecipient).toBeUndefined();
  });

  it("rotateAgent swaps the credential DID; account_id stable, pending invitation preserved", async () => {
    const id = await seed("did:key:zOld");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation(id, aliceEmail, "token-r", expiresAt);
    const rotated = await store.rotateAgent("did:key:zOld", "did:key:zNew", new Date().toISOString());
    expect(rotated.accountId).toBe(id); // stable across rotation
    expect(await store.getByAgentDid("did:key:zOld")).toBeNull();
    const fresh = await store.getByAgentDid("did:key:zNew");
    expect(fresh?.state).toBe("INVITED");
    expect(fresh?.pendingRecipient).toEqual(aliceEmail);
    expect((await store.findByPendingToken("token-r"))?.accountId).toBe(id);
  });

  it("revoke sets the whole-account revoked flag", async () => {
    const id = await seed("did:key:zAgent");
    await store.revoke(id, new Date().toISOString());
    expect((await store.getByAgentDid("did:key:zAgent"))?.revoked).toBe(true);
  });

  it("revokeAgent flags a single device; the account survives", async () => {
    const P = { iss: "x", subH: SUB_H };
    await store.signupAgent({ did: "did:key:zPc", principal: P });
    await store.signupAgent({ did: "did:key:zPhone", principal: P });
    const out = await store.revokeAgent("did:key:zPc", new Date().toISOString());
    expect(out.revoked).toBeFalsy(); // account not revoked
    expect(out.agents.find((a) => a.did === "did:key:zPc")?.revoked).toBe(true);
    expect(out.agents.find((a) => a.did === "did:key:zPhone")?.revoked).toBeFalsy();
  });

  it("setPendingInvitation on a revoked account throws revoked_key", async () => {
    const id = await seed("did:key:zAgent");
    await store.revoke(id, new Date().toISOString());
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await expect(store.setPendingInvitation(id, aliceEmail, "t", expiresAt)).rejects.toThrow(/revoked/);
  });

  it("setPendingInvitation on a CLAIMED account throws already_claimed", async () => {
    const id = await seed("did:key:zAgent");
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await store.setPendingInvitation(id, aliceEmail, "t1", expiresAt);
    await store.completeClaimByToken("t1", {
      identity: aliceEmail,
      userId: "u",
      claimedAt: new Date().toISOString(),
    });
    await expect(store.setPendingInvitation(id, aliceEmail, "t2", expiresAt)).rejects.toThrow(/already claimed/);
  });

  it("setPendingInvitation on an unknown account throws unknown_account", async () => {
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await expect(store.setPendingInvitation("acct_ghost", aliceEmail, "t", expiresAt)).rejects.toThrow(/does not exist/);
  });

  describe("SweepableAccountStore", () => {
    it("listOpenAccounts returns UNCLAIMED + INVITED, omits CLAIMED", async () => {
      const u = await seed("did:key:zUnclaimed");
      const i = await seed("did:key:zInvited");
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      await store.setPendingInvitation(i, aliceEmail, "tok", expiresAt);
      const c = await seed("did:key:zClaimed");
      await store.setPendingInvitation(c, bobEmail, "tok2", expiresAt);
      await store.completeClaimByToken("tok2", {
        identity: bobEmail,
        userId: "u_b",
        claimedAt: new Date().toISOString(),
      });
      const open = await store.listOpenAccounts();
      expect(open.map((a) => a.accountId).sort()).toEqual([i, u].sort());
    });

    it("expire flips state to EXPIRED and drops the pending invitation row", async () => {
      const id = await seed("did:key:zStale");
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      await store.setPendingInvitation(id, aliceEmail, "stale-tok", expiresAt);
      const out = await store.expire(id, new Date().toISOString());
      expect(out.state).toBe("EXPIRED");
      expect((await store.listOpenAccounts()).map((a) => a.accountId)).not.toContain(id);
      expect(await store.findByPendingToken("stale-tok")).toBeNull();
    });

    it("expire is idempotent on already-EXPIRED accounts", async () => {
      const id = await seed("did:key:zAgent");
      await store.expire(id, new Date().toISOString());
      expect((await store.expire(id, new Date().toISOString())).state).toBe("EXPIRED");
    });

    it("expire on CLAIMED throws already_claimed (Appendix A forbids the transition)", async () => {
      const id = await seed("did:key:zClaimed");
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      await store.setPendingInvitation(id, bobEmail, "tk", expiresAt);
      await store.completeClaimByToken("tk", {
        identity: bobEmail,
        userId: "u",
        claimedAt: new Date().toISOString(),
      });
      await expect(store.expire(id, new Date().toISOString())).rejects.toThrow(/CLAIMED/);
    });

    it("expire on unknown account throws unknown_account", async () => {
      await expect(store.expire("acct_ghost", new Date().toISOString())).rejects.toThrow(/does not exist/);
    });
  });

  describe("reKey (§8.2 owner re-key resume)", () => {
    async function claimedThenRevoked(): Promise<{
      owner: NonNullable<Account["owner"]>;
      accountId: string;
    }> {
      const exp = new Date(Date.now() + 3600_000).toISOString();
      const accountId = (await store.signupAgent({ did: "did:key:zOld" })).account.accountId;
      await store.setPendingInvitation(accountId, aliceEmail, "tok", exp);
      const owner: NonNullable<Account["owner"]> = {
        identity: aliceEmail,
        userId: "usr_alice",
        claimedAt: new Date().toISOString(),
      };
      await store.completeClaimByToken("tok", owner);
      await store.revoke(accountId, new Date().toISOString());
      return { owner, accountId };
    }

    it("a plain rotateAgent leaves the account flagged revoked", async () => {
      await claimedThenRevoked();
      await store.rotateAgent("did:key:zOld", "did:key:zRot", new Date().toISOString());
      expect((await store.getByAgentDid("did:key:zRot"))?.revoked).toBe(true);
    });

    it("reKey swaps the DID in one batch, clears revoked, preserves owner, drops the old DID", async () => {
      const { owner, accountId } = await claimedThenRevoked();
      const out = await store.reKey("did:key:zOld", "did:key:zNew", new Date().toISOString());
      expect(out.accountId).toBe(accountId); // stable
      expect(out.agents.map((a) => a.did)).toContain("did:key:zNew");
      expect(out.state).toBe("CLAIMED");
      expect(out.revoked).toBeFalsy();
      const fresh = await store.getByAgentDid("did:key:zNew");
      expect(fresh?.revoked).toBeFalsy();
      expect(fresh?.owner).toEqual(owner);
      expect(await store.getByAgentDid("did:key:zOld")).toBeNull();
    });

    it("reKey on an unknown account throws unknown_account", async () => {
      await expect(
        store.reKey("did:key:zGhost", "did:key:zNew", new Date().toISOString()),
      ).rejects.toThrow(/does not exist|no account/);
    });
  });
});
