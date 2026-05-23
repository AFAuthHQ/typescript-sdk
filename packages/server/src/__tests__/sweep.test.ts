/**
 * §6.1 / Appendix A TTL sweep.
 *
 * Coverage:
 *   - `sweepExpiredAccounts` only transitions accounts whose age
 *     exceeds `unclaimedTtlSeconds`.
 *   - Both UNCLAIMED → EXPIRED and INVITED → EXPIRED transitions run.
 *   - CLAIMED accounts are NEVER touched (Appendix A forbids
 *     CLAIMED → EXPIRED).
 *   - Idempotent under repeated invocation.
 *   - Bad TTLs reject before mutating.
 *   - EXPIRED rejection in handleOwnerInvitation and handleKeyRotation
 *     — each returns 410 account_expired.
 */

import { describe, expect, it, vi } from "vitest";
import { Agent } from "@afauthhq/agent";
import type { Recipient } from "@afauthhq/core";
import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  Server,
  sweepExpiredAccounts,
  type DiscoveryDocument,
} from "../index.js";

const BASE_URL = "https://api.example.com";

const DISCOVERY: DiscoveryDocument = {
  afauth_version: "0.1",
  service_did: "did:web:api.example.com",
  endpoints: {
    accounts: "/afauth/v1/accounts",
    owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
    claim_page: "/claim",
    claim_completion: "/afauth/v1/claim",
    key_rotation: "/afauth/v1/accounts/me/keys/rotate",
  },
  signature_algorithms: ["ed25519"],
  features: ["key_rotation"],
  recipient_types: ["email"],
};

function buildServer() {
  const accounts = new MemoryAccountStore();
  const server = new Server({
    nonceStore: new MemoryNonceStore(),
    revocationList: new MemoryRevocationList(),
    serviceDid: DISCOVERY.service_did,
    accounts,
    recipients: { email: consoleEmailHandler },
    discovery: DISCOVERY,
    baseUrl: BASE_URL,
  });
  return { server, accounts };
}

async function toRequest(signed: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | Uint8Array | null;
}): Promise<Request> {
  const init: RequestInit = { method: signed.method, headers: signed.headers };
  if (signed.body !== null) init.body = signed.body as BodyInit;
  return new Request(signed.url, init);
}

describe("sweepExpiredAccounts", () => {
  it("expires only accounts whose createdAt is older than ttl", async () => {
    const accounts = new MemoryAccountStore();
    const oldDid = "did:key:zOld";
    const newDid = "did:key:zNew";

    const before = await accounts.createUnclaimed(oldDid);
    // Rewrite createdAt to look 2 hours old.
    (before as { createdAt: string }).createdAt = new Date(
      Date.now() - 2 * 60 * 60 * 1000,
    ).toISOString();

    await accounts.createUnclaimed(newDid); // fresh — createdAt = now

    const result = await sweepExpiredAccounts(accounts, { unclaimedTtlSeconds: 3600 });
    expect(result.scanned).toBe(2);
    expect(result.expired).toEqual([oldDid]);

    expect((await accounts.get(oldDid))?.state).toBe("EXPIRED");
    expect((await accounts.get(newDid))?.state).toBe("UNCLAIMED");
  });

  it("expires both UNCLAIMED and INVITED accounts past the TTL", async () => {
    const accounts = new MemoryAccountStore();
    const unclaimedDid = "did:key:zUnclaimed";
    const invitedDid = "did:key:zInvited";

    const a = await accounts.createUnclaimed(unclaimedDid);
    (a as { createdAt: string }).createdAt = new Date(Date.now() - 10000 * 1000).toISOString();

    const b = await accounts.createUnclaimed(invitedDid);
    (b as { createdAt: string }).createdAt = new Date(Date.now() - 10000 * 1000).toISOString();
    await accounts.setPendingInvitation(
      invitedDid,
      { type: "email", value: "alice@example.com" },
      "token-xyz",
      new Date(Date.now() + 3600 * 1000).toISOString(),
    );

    const result = await sweepExpiredAccounts(accounts, { unclaimedTtlSeconds: 3600 });
    expect(result.expired.sort()).toEqual([invitedDid, unclaimedDid].sort());

    const inv = await accounts.get(invitedDid);
    expect(inv?.state).toBe("EXPIRED");
    // The pending invitation has been dropped — the token no longer resolves.
    expect(await accounts.findByPendingToken("token-xyz")).toBeNull();
  });

  it("never touches CLAIMED accounts (Appendix A forbids the transition)", async () => {
    const { server, accounts } = buildServer();
    const agent = await Agent.generate();
    const recipient: Recipient = { type: "email", value: "alice@example.com" };

    // Walk to CLAIMED.
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await server.handleOwnerInvitation(
        await toRequest(await agent.buildOwnerInvitation({ baseUrl: BASE_URL, recipient })),
      );
      const link = consoleSpy.mock.calls[0]![0] as string;
      const token = new URL(/https?:\/\/\S+/.exec(link)![0]).searchParams.get("token")!;
      await server.handleClaimCompletion(
        new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" }),
        { authenticated: recipient, userId: "usr_alice" },
      );
    } finally {
      consoleSpy.mockRestore();
    }

    // Force createdAt back so the sweep would target this account
    // if it didn't skip CLAIMED.
    const claimed = (await accounts.get(agent.did))!;
    (claimed as { createdAt: string }).createdAt = new Date(
      Date.now() - 24 * 60 * 60 * 1000,
    ).toISOString();

    const result = await sweepExpiredAccounts(accounts, { unclaimedTtlSeconds: 3600 });
    // CLAIMED accounts aren't even returned by listOpenAccounts.
    expect(result.scanned).toBe(0);
    expect(result.expired).toEqual([]);
    expect((await accounts.get(agent.did))?.state).toBe("CLAIMED");
  });

  it("is idempotent — a second sweep is a no-op", async () => {
    const accounts = new MemoryAccountStore();
    const did = "did:key:zStale";
    const acc = await accounts.createUnclaimed(did);
    (acc as { createdAt: string }).createdAt = new Date(Date.now() - 7200 * 1000).toISOString();

    const first = await sweepExpiredAccounts(accounts, { unclaimedTtlSeconds: 3600 });
    expect(first.expired).toEqual([did]);

    const second = await sweepExpiredAccounts(accounts, { unclaimedTtlSeconds: 3600 });
    expect(second.expired).toEqual([]);
    expect(second.scanned).toBe(0);
  });

  it("respects the `now` injection for deterministic time", async () => {
    const accounts = new MemoryAccountStore();
    const did = "did:key:zPredict";
    await accounts.createUnclaimed(did);

    // With now == account.createdAt, the account is 0s old; ttl=3600 → not expired.
    const fakeNow = new Date();
    const noop = await sweepExpiredAccounts(accounts, {
      unclaimedTtlSeconds: 3600,
      now: () => fakeNow,
    });
    expect(noop.expired).toEqual([]);

    // Advance the clock; same account, same ttl → now it expires.
    const future = new Date(fakeNow.getTime() + 7200 * 1000);
    const swept = await sweepExpiredAccounts(accounts, {
      unclaimedTtlSeconds: 3600,
      now: () => future,
    });
    expect(swept.expired).toEqual([did]);
  });

  it("rejects non-positive unclaimedTtlSeconds before mutating", async () => {
    const accounts = new MemoryAccountStore();
    await accounts.createUnclaimed("did:key:zAny");
    await expect(
      sweepExpiredAccounts(accounts, { unclaimedTtlSeconds: 0 }),
    ).rejects.toThrow(/positive number/);
    await expect(
      sweepExpiredAccounts(accounts, { unclaimedTtlSeconds: -1 }),
    ).rejects.toThrow(/positive number/);
    // The account was untouched.
    expect((await accounts.get("did:key:zAny"))?.state).toBe("UNCLAIMED");
  });
});

describe("MemoryAccountStore.expire", () => {
  it("idempotent on already-EXPIRED accounts", async () => {
    const store = new MemoryAccountStore();
    await store.createUnclaimed("did:key:zX");
    await store.expire("did:key:zX", new Date().toISOString());
    const second = await store.expire("did:key:zX", new Date().toISOString());
    expect(second.state).toBe("EXPIRED");
  });

  it("rejects expire on CLAIMED with 409 already_claimed", async () => {
    const { server, accounts } = buildServer();
    const agent = await Agent.generate();
    const recipient: Recipient = { type: "email", value: "alice@example.com" };
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await server.handleOwnerInvitation(
        await toRequest(await agent.buildOwnerInvitation({ baseUrl: BASE_URL, recipient })),
      );
      const link = consoleSpy.mock.calls[0]![0] as string;
      const token = new URL(/https?:\/\/\S+/.exec(link)![0]).searchParams.get("token")!;
      await server.handleClaimCompletion(
        new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" }),
        { authenticated: recipient, userId: "usr_alice" },
      );
    } finally {
      consoleSpy.mockRestore();
    }

    await expect(accounts.expire(agent.did, new Date().toISOString())).rejects.toMatchObject({
      code: "already_claimed",
      status: 409,
    });
  });

  it("rejects expire on unknown account", async () => {
    const store = new MemoryAccountStore();
    await expect(store.expire("did:key:zNope", new Date().toISOString())).rejects.toMatchObject({
      code: "unknown_account",
      status: 404,
    });
  });
});

describe("EXPIRED rejection in Server handlers", () => {
  async function buildExpired(): Promise<{ server: Server; agent: Agent }> {
    const { server, accounts } = buildServer();
    const agent = await Agent.generate();
    await accounts.createUnclaimed(agent.did);
    await accounts.expire(agent.did, new Date().toISOString());
    return { server, agent };
  }

  it("handleOwnerInvitation returns 410 account_expired", async () => {
    const { server, agent } = await buildExpired();
    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "alice@example.com" },
    });
    await expect(server.handleOwnerInvitation(await toRequest(signed))).rejects.toMatchObject({
      code: "account_expired",
      status: 410,
    });
  });

  it("handleKeyRotation returns 410 account_expired", async () => {
    const { server, agent } = await buildExpired();
    const newAgent = await Agent.generate();
    const signed = await agent.buildKeyRotation({ baseUrl: BASE_URL, newDid: newAgent.did });
    await expect(server.handleKeyRotation(await toRequest(signed))).rejects.toMatchObject({
      code: "account_expired",
      status: 410,
    });
  });

  it("handleAccountIntrospection still succeeds on EXPIRED (reads are informational)", async () => {
    const { server, agent } = await buildExpired();
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const resp = await server.handleAccountIntrospection(await toRequest(signed));
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { account_did: string; state: string };
    expect(body.state).toBe("EXPIRED");
    expect(body.account_did).toBe(agent.did);
  });
});
