/**
 * M3 conformance: pre-claim key rotation + revocation.
 *
 * Conformance gate (per scope doc):
 *   "regression test: post-rotation signature with old key returns
 *    401 revoked_key"
 *
 * Plus §8.4 owner-initiated revocation and the storage invariants
 * around rotation while INVITED / CLAIMED.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Agent } from "@afauthhq/agent";
import type { Recipient } from "@afauthhq/core";
import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  Server,
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
  const revocationList = new MemoryRevocationList();
  const server = new Server({
    nonceStore: new MemoryNonceStore(),
    serviceDid: DISCOVERY.service_did,
    accounts,
    revocationList,
    recipients: { email: consoleEmailHandler },
    discovery: DISCOVERY,
    baseUrl: BASE_URL,
  });
  return { server, accounts, revocationList };
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

describe("M3 pre-claim key rotation (§8.1)", () => {
  it("agent rotates from old DID to new DID; account uses new DID afterward", async () => {
    const { server, accounts } = buildServer();
    const oldAgent = await Agent.generate();
    const newAgent = await Agent.generate();

    // Implicit signup via introspection so an account exists.
    const introspection = await oldAgent.buildAccountIntrospection({ baseUrl: BASE_URL });
    await server.handleAccountIntrospection(await toRequest(introspection));

    // Rotate.
    const rotation = await oldAgent.buildKeyRotation({ baseUrl: BASE_URL, newDid: newAgent.did });
    const resp = await server.handleKeyRotation(await toRequest(rotation));
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { account_did: string; old_revoked_at: string };
    expect(body.account_did).toBe(newAgent.did);
    expect(body.old_revoked_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);

    // Account is now under the new DID; old DID is gone.
    expect(await accounts.get(oldAgent.did)).toBeNull();
    const updated = await accounts.get(newAgent.did);
    expect(updated?.state).toBe("UNCLAIMED");
  });

  it("conformance gate: old key signed request after rotation → 401 revoked_key", async () => {
    const { server } = buildServer();
    const oldAgent = await Agent.generate();
    const newAgent = await Agent.generate();

    // Sign up + rotate.
    await server.handleAccountIntrospection(
      await toRequest(await oldAgent.buildAccountIntrospection({ baseUrl: BASE_URL })),
    );
    await server.handleKeyRotation(
      await toRequest(await oldAgent.buildKeyRotation({ baseUrl: BASE_URL, newDid: newAgent.did })),
    );

    // Sign a fresh request with the OLD key — should be rejected.
    const stale = await oldAgent.buildAccountIntrospection({ baseUrl: BASE_URL });
    await expect(server.handleAccountIntrospection(await toRequest(stale))).rejects.toMatchObject({
      code: "revoked_key",
      status: 401,
    });
  });

  it("post-rotation: new key signed request succeeds and returns new account", async () => {
    const { server } = buildServer();
    const oldAgent = await Agent.generate();
    const newAgent = await Agent.generate();

    await server.handleAccountIntrospection(
      await toRequest(await oldAgent.buildAccountIntrospection({ baseUrl: BASE_URL })),
    );
    await server.handleKeyRotation(
      await toRequest(await oldAgent.buildKeyRotation({ baseUrl: BASE_URL, newDid: newAgent.did })),
    );

    const fresh = await newAgent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const resp = await server.handleAccountIntrospection(await toRequest(fresh));
    const body = (await resp.json()) as { account_did: string; state: string };
    expect(body.account_did).toBe(newAgent.did);
    expect(body.state).toBe("UNCLAIMED");
  });

  it("rotation while INVITED preserves pending invitation under the new DID", async () => {
    const { server, accounts } = buildServer();
    const oldAgent = await Agent.generate();
    const newAgent = await Agent.generate();
    const recipient: Recipient = { type: "email", value: "alice@example.com" };

    // Sign up + invite.
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await server.handleOwnerInvitation(
      await toRequest(await oldAgent.buildOwnerInvitation({ baseUrl: BASE_URL, recipient })),
    );

    const preRotate = await accounts.get(oldAgent.did);
    expect(preRotate?.state).toBe("INVITED");

    // Rotate while INVITED.
    await server.handleKeyRotation(
      await toRequest(await oldAgent.buildKeyRotation({ baseUrl: BASE_URL, newDid: newAgent.did })),
    );

    const postRotate = await accounts.get(newAgent.did);
    expect(postRotate?.state).toBe("INVITED");
    expect(postRotate?.pendingRecipient).toEqual(recipient);

    // Magic-link token still resolves; the human can still claim.
    const link = spy.mock.calls[0]![0] as string;
    const token = new URL(/https?:\/\/\S+/.exec(link)![0]).searchParams.get("token")!;
    const claimReq = new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" });
    const claimResp = await server.handleClaimCompletion(claimReq, {
      authenticated: recipient,
      userId: "usr_alice",
    });
    expect(claimResp.status).toBe(200);
    const final = await accounts.get(newAgent.did);
    expect(final?.state).toBe("CLAIMED");

    spy.mockRestore();
  });

  it("rotation while CLAIMED rejected — §8.2 post-claim is out of v0.1 scope", async () => {
    const { server } = buildServer();
    const agent = await Agent.generate();
    const recipient: Recipient = { type: "email", value: "alice@example.com" };
    const newAgent = await Agent.generate();

    // Walk the agent to CLAIMED.
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await server.handleOwnerInvitation(
      await toRequest(await agent.buildOwnerInvitation({ baseUrl: BASE_URL, recipient })),
    );
    const link = spy.mock.calls[0]![0] as string;
    const token = new URL(/https?:\/\/\S+/.exec(link)![0]).searchParams.get("token")!;
    await server.handleClaimCompletion(
      new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" }),
      { authenticated: recipient, userId: "usr_alice" },
    );
    spy.mockRestore();

    // Attempt rotation post-claim.
    await expect(
      server.handleKeyRotation(
        await toRequest(await agent.buildKeyRotation({ baseUrl: BASE_URL, newDid: newAgent.did })),
      ),
    ).rejects.toMatchObject({ code: "owner_authentication_required", status: 403 });
  });

  it("invalid new_account_did rejected with 400 malformed_request", async () => {
    const { server } = buildServer();
    const agent = await Agent.generate();
    await server.handleAccountIntrospection(
      await toRequest(await agent.buildAccountIntrospection({ baseUrl: BASE_URL })),
    );

    // The Agent builder takes a Did string, so we use signRequest with a bad body.
    const badRotation = await agent.signRequest({
      method: "POST",
      url: `${BASE_URL}/afauth/v1/accounts/me/keys/rotate`,
      body: JSON.stringify({ new_account_did: "did:key:zINVALID" }),
    });
    await expect(server.handleKeyRotation(await toRequest(badRotation))).rejects.toMatchObject({
      code: "malformed_request",
      status: 400,
    });
  });

  it("rotating to the same DID rejected", async () => {
    const { server } = buildServer();
    const agent = await Agent.generate();
    await server.handleAccountIntrospection(
      await toRequest(await agent.buildAccountIntrospection({ baseUrl: BASE_URL })),
    );
    const selfRotation = await agent.buildKeyRotation({ baseUrl: BASE_URL, newDid: agent.did });
    await expect(server.handleKeyRotation(await toRequest(selfRotation))).rejects.toMatchObject({
      code: "malformed_request",
      status: 400,
    });
  });
});

describe("M3 owner-initiated revocation (§8.4)", () => {
  let spy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });
  afterEach(() => {
    spy.mockRestore();
  });

  it("revoke() marks account revoked AND adds DID to revocation list", async () => {
    const { server, accounts, revocationList } = buildServer();
    const agent = await Agent.generate();
    const recipient: Recipient = { type: "email", value: "alice@example.com" };

    // Walk to CLAIMED.
    await server.handleOwnerInvitation(
      await toRequest(await agent.buildOwnerInvitation({ baseUrl: BASE_URL, recipient })),
    );
    const token = new URL(
      /https?:\/\/\S+/.exec(spy.mock.calls[0]![0] as string)![0],
    ).searchParams.get("token")!;
    await server.handleClaimCompletion(
      new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" }),
      { authenticated: recipient, userId: "usr_alice" },
    );

    // Owner revokes.
    await server.revoke(agent.did);

    expect((await accounts.get(agent.did))?.revoked).toBe(true);
    expect(await revocationList.isRevoked(agent.did)).toBe(true);
  });

  it("post-revocation request returns 401 revoked_key", async () => {
    const { server } = buildServer();
    const agent = await Agent.generate();
    await server.handleAccountIntrospection(
      await toRequest(await agent.buildAccountIntrospection({ baseUrl: BASE_URL })),
    );

    await server.revoke(agent.did);

    const fresh = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    await expect(server.handleAccountIntrospection(await toRequest(fresh))).rejects.toMatchObject({
      code: "revoked_key",
      status: 401,
    });
  });

  it("revoke() on unknown account → 404 unknown_account", async () => {
    const { server } = buildServer();
    await expect(server.revoke("did:key:zUnknown")).rejects.toMatchObject({
      code: "unknown_account",
      status: 404,
    });
  });
});

describe("Verifier without a revocation list (backward compat)", () => {
  it("skips revocation check when no list is supplied", async () => {
    // Build a Server WITHOUT a revocationList.
    const accounts = new MemoryAccountStore();
    const server = new Server({
      nonceStore: new MemoryNonceStore(),
      serviceDid: DISCOVERY.service_did,
      accounts,
      recipients: { email: consoleEmailHandler },
      discovery: DISCOVERY,
      baseUrl: BASE_URL,
    });

    const agent = await Agent.generate();
    const resp = await server.handleAccountIntrospection(
      await toRequest(await agent.buildAccountIntrospection({ baseUrl: BASE_URL })),
    );
    expect(resp.status).toBe(200);
  });
});

describe("MemoryAccountStore.reKey — §8.2 owner re-key resume", () => {
  const alice: Recipient = { type: "email", value: "alice@example.com" };

  async function claimedThenRevoked() {
    const accounts = new MemoryAccountStore();
    const exp = new Date(Date.now() + 3600_000).toISOString();
    await accounts.createUnclaimed("did:key:zOld");
    await accounts.setPendingInvitation("did:key:zOld", alice, "tok", exp);
    const owner = {
      identity: alice,
      userId: "usr_alice",
      claimedAt: new Date().toISOString(),
    };
    await accounts.completeClaimByToken("tok", owner);
    await accounts.revoke("did:key:zOld", new Date().toISOString());
    return { accounts, owner };
  }

  it("the bug reKey fixes: a plain rotateKey carries revoked=true onto the new DID", async () => {
    const { accounts } = await claimedThenRevoked();
    await accounts.rotateKey("did:key:zOld", "did:key:zRot", new Date().toISOString());
    // Why reKey exists: rotate alone spreads the old row forward, so a
    // "revoke then install new key" via rotateKey leaves the new DID
    // still flagged revoked.
    expect((await accounts.get("did:key:zRot"))?.revoked).toBe(true);
  });

  it("reKey installs the new DID, CLEARS revoked, preserves owner, drops the old DID", async () => {
    const { accounts, owner } = await claimedThenRevoked();
    const out = await accounts.reKey("did:key:zOld", "did:key:zNew", new Date().toISOString());

    expect(out.did).toBe("did:key:zNew");
    expect(out.state).toBe("CLAIMED");
    // The load-bearing assertion is the ROW flag — NOT "the Verifier
    // accepts the new key", which is true regardless because the new DID
    // is never added to the revocation list.
    expect(out.revoked).toBeFalsy();
    expect((await accounts.get("did:key:zNew"))?.revoked).toBeFalsy();
    // Owner binding carries forward — the same human keeps the account.
    expect((await accounts.get("did:key:zNew"))?.owner).toEqual(owner);
    // Old DID is gone.
    expect(await accounts.get("did:key:zOld")).toBeNull();
    // A flag-reading surface agrees it is clean: setPendingInvitation no
    // longer short-circuits on `revoked` (it now hits the CLAIMED guard).
    await expect(
      accounts.setPendingInvitation(
        "did:key:zNew",
        alice,
        "t2",
        new Date(Date.now() + 3600_000).toISOString(),
      ),
    ).rejects.toThrow(/already claimed/);
  });

  it("reKey on an unknown account → 404 unknown_account", async () => {
    const accounts = new MemoryAccountStore();
    await expect(
      accounts.reKey("did:key:zGhost", "did:key:zNew", new Date().toISOString()),
    ).rejects.toMatchObject({ code: "unknown_account", status: 404 });
  });
});

describe("Server.handleKeyReKey + handleKeyRevocation — owner-gated (§8.2 / §8.4)", () => {
  let spy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });
  afterEach(() => spy.mockRestore());

  const recipient: Recipient = { type: "email", value: "alice@example.com" };

  /** Walk a freshly-generated agent to CLAIMED under owner `usr_alice`. */
  async function claimed(server: Server) {
    const agent = await Agent.generate();
    await server.handleOwnerInvitation(
      await toRequest(await agent.buildOwnerInvitation({ baseUrl: BASE_URL, recipient })),
    );
    const token = new URL(
      /https?:\/\/\S+/.exec(spy.mock.calls[0]![0] as string)![0],
    ).searchParams.get("token")!;
    await server.handleClaimCompletion(
      new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" }),
      { authenticated: recipient, userId: "usr_alice" },
    );
    spy.mockClear();
    return agent;
  }

  /** Owner session for `usr_alice`; `ageSeconds` backdates the auth event. */
  function ownerSession(userId = "usr_alice", ageSeconds = 0) {
    return {
      authenticated: recipient,
      userId,
      authenticatedAt: new Date(Date.now() - ageSeconds * 1000).toISOString(),
    };
  }

  function reKeyReq(currentDid: string, newDid: string): Request {
    return new Request(`${BASE_URL}/afauth/v1/accounts/me/keys/rekey`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ current_account_did: currentDid, new_account_did: newDid }),
    });
  }

  function revokeReq(accountDid: string): Request {
    return new Request(`${BASE_URL}/afauth/v1/accounts/me/keys/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ account_did: accountDid }),
    });
  }

  // ----- re-key (§8.2) -----

  it("resumes a revoked CLAIMED account under a new key; old key→401, new key works", async () => {
    const { server, accounts, revocationList } = buildServer();
    const oldAgent = await claimed(server);
    const newAgent = await Agent.generate();

    await server.revoke(oldAgent.did); // owner suspects compromise → revoke

    const resp = await server.handleKeyReKey(
      reKeyReq(oldAgent.did, newAgent.did),
      ownerSession(),
    );
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { account_did: string; state: string };
    expect(body.account_did).toBe(newAgent.did);
    expect(body.state).toBe("CLAIMED");

    // Account lives under the new DID, revoked cleared, old DID gone.
    expect((await accounts.get(newAgent.did))?.revoked).toBeFalsy();
    expect(await accounts.get(oldAgent.did)).toBeNull();
    // Old key is locked out at the Verifier.
    expect(await revocationList.isRevoked(oldAgent.did)).toBe(true);
    await expect(
      server.handleAccountIntrospection(
        await toRequest(await oldAgent.buildAccountIntrospection({ baseUrl: BASE_URL })),
      ),
    ).rejects.toMatchObject({ code: "revoked_key", status: 401 });
    // New key works.
    const fresh = await server.handleAccountIntrospection(
      await toRequest(await newAgent.buildAccountIntrospection({ baseUrl: BASE_URL })),
    );
    expect(fresh.status).toBe(200);
  });

  it("re-keys a healthy (non-revoked) CLAIMED account too", async () => {
    const { server, accounts } = buildServer();
    const oldAgent = await claimed(server);
    const newAgent = await Agent.generate();
    const resp = await server.handleKeyReKey(reKeyReq(oldAgent.did, newAgent.did), ownerSession());
    expect(resp.status).toBe(200);
    expect((await accounts.get(newAgent.did))?.revoked).toBeFalsy();
  });

  it("stale owner session → 403 owner_session_too_stale", async () => {
    const { server } = buildServer();
    const oldAgent = await claimed(server);
    const newAgent = await Agent.generate();
    await expect(
      server.handleKeyReKey(reKeyReq(oldAgent.did, newAgent.did), ownerSession("usr_alice", 10_000)),
    ).rejects.toMatchObject({ code: "owner_session_too_stale", status: 403 });
  });

  it("SECURITY: a non-owner session cannot re-key another owner's account, and leaves it untouched", async () => {
    const { server, accounts } = buildServer();
    const oldAgent = await claimed(server);
    const newAgent = await Agent.generate();
    await expect(
      server.handleKeyReKey(reKeyReq(oldAgent.did, newAgent.did), ownerSession("usr_mallory")),
    ).rejects.toMatchObject({ code: "owner_authentication_required", status: 403 });
    // Victim account is byte-for-byte unchanged; the attacker's DID never materialised.
    expect((await accounts.get(oldAgent.did))?.owner?.userId).toBe("usr_alice");
    expect(await accounts.get(newAgent.did)).toBeNull();
  });

  it("re-key on an UNCLAIMED account → 409 not_claimed", async () => {
    const { server } = buildServer();
    const oldAgent = await Agent.generate();
    await server.handleAccountIntrospection(
      await toRequest(await oldAgent.buildAccountIntrospection({ baseUrl: BASE_URL })),
    ); // implicit signup → UNCLAIMED
    const newAgent = await Agent.generate();
    await expect(
      server.handleKeyReKey(reKeyReq(oldAgent.did, newAgent.did), ownerSession()),
    ).rejects.toMatchObject({ code: "not_claimed", status: 409 });
  });

  it("re-key to the same DID → 400 malformed_request", async () => {
    const { server } = buildServer();
    const agent = await claimed(server);
    await expect(
      server.handleKeyReKey(reKeyReq(agent.did, agent.did), ownerSession()),
    ).rejects.toMatchObject({ code: "malformed_request", status: 400 });
  });

  it("re-key to a DID that already names an account → 409 already_claimed (collision guard)", async () => {
    const { server } = buildServer();
    const agentA = await claimed(server);
    // A second existing account to collide with.
    const agentB = await Agent.generate();
    await server.handleAccountIntrospection(
      await toRequest(await agentB.buildAccountIntrospection({ baseUrl: BASE_URL })),
    );
    await expect(
      server.handleKeyReKey(reKeyReq(agentA.did, agentB.did), ownerSession()),
    ).rejects.toMatchObject({ code: "already_claimed", status: 409 });
  });

  // ----- revoke (§8.4) -----

  it("owner revoke → 200 then the agent key is locked out (401 revoked_key)", async () => {
    const { server, accounts } = buildServer();
    const agent = await claimed(server);
    const resp = await server.handleKeyRevocation(revokeReq(agent.did), ownerSession());
    expect(resp.status).toBe(200);
    expect((await accounts.get(agent.did))?.revoked).toBe(true);
    await expect(
      server.handleAccountIntrospection(
        await toRequest(await agent.buildAccountIntrospection({ baseUrl: BASE_URL })),
      ),
    ).rejects.toMatchObject({ code: "revoked_key", status: 401 });
  });

  it("owner revoke is idempotent (re-revoke → 200)", async () => {
    const { server } = buildServer();
    const agent = await claimed(server);
    expect((await server.handleKeyRevocation(revokeReq(agent.did), ownerSession())).status).toBe(200);
    expect((await server.handleKeyRevocation(revokeReq(agent.did), ownerSession())).status).toBe(200);
  });

  it("revoke: stale session → 403, non-owner → 403 (and account NOT revoked), unknown → 404, UNCLAIMED → 409", async () => {
    const { server, accounts } = buildServer();
    const agent = await claimed(server);

    await expect(
      server.handleKeyRevocation(revokeReq(agent.did), ownerSession("usr_alice", 10_000)),
    ).rejects.toMatchObject({ code: "owner_session_too_stale", status: 403 });

    await expect(
      server.handleKeyRevocation(revokeReq(agent.did), ownerSession("usr_mallory")),
    ).rejects.toMatchObject({ code: "owner_authentication_required", status: 403 });
    expect((await accounts.get(agent.did))?.revoked).toBeFalsy(); // not revoked by the impostor

    await expect(
      server.handleKeyRevocation(revokeReq("did:key:zNope"), ownerSession()),
    ).rejects.toMatchObject({ code: "unknown_account", status: 404 });

    const unclaimed = await Agent.generate();
    await server.handleAccountIntrospection(
      await toRequest(await unclaimed.buildAccountIntrospection({ baseUrl: BASE_URL })),
    );
    await expect(
      server.handleKeyRevocation(revokeReq(unclaimed.did), ownerSession()),
    ).rejects.toMatchObject({ code: "not_claimed", status: 409 });
  });
});
