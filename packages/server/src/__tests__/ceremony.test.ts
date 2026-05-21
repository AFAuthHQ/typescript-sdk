/**
 * M2 end-to-end ceremony.
 *
 * Walks an agent through implicit signup → owner-invitation → claim
 * completion, exercising:
 *   - Verifier.verify on the signed invitation request
 *   - MemoryAccountStore atomic invitation + claim
 *   - consoleEmailHandler.initiate / matches
 *   - Server.handleOwnerInvitation and handleClaimCompletion
 *
 * The reference email handler logs the magic link to console.error;
 * the test intercepts that output to extract the claim token, exactly
 * the way a real human user would follow the link.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Agent } from "@afauth/agent";
import type { Recipient } from "@afauth/core";
import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
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
  },
  signature_algorithms: ["ed25519"],
  recipient_types: ["email"],
};

function buildServer(): { server: Server; accounts: MemoryAccountStore } {
  const accounts = new MemoryAccountStore();
  const server = new Server({
    nonceStore: new MemoryNonceStore(),
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
  body: string | null;
}): Promise<Request> {
  const init: RequestInit = { method: signed.method, headers: signed.headers };
  if (signed.body !== null) init.body = signed.body;
  return new Request(signed.url, init);
}

describe("M2 owner-invitation + claim-completion ceremony", () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });
  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it("agent invites → email handler logs link → claim completes → CLAIMED", async () => {
    const { server, accounts } = buildServer();
    const agent = await Agent.generate();
    const recipient: Recipient = { type: "email", value: "alice@example.com" };

    // ----- Step 1: agent posts owner-invitation -----
    const signed = await agent.buildOwnerInvitation({ baseUrl: BASE_URL, recipient });
    const inviteResp = await server.handleOwnerInvitation(await toRequest(signed));

    expect(inviteResp.status).toBe(202);
    const inviteBody = (await inviteResp.json()) as {
      invitation_id: string;
      state: string;
      expires_at: string;
    };
    expect(inviteBody.state).toBe("INVITED");
    expect(inviteBody.invitation_id).toMatch(/^inv_/);

    // The handler logged the magic link to console.error.
    expect(consoleSpy).toHaveBeenCalledOnce();
    const logged = consoleSpy.mock.calls[0]![0] as string;
    expect(logged).toContain("alice@example.com");
    const linkMatch = /https?:\/\/\S+/.exec(logged);
    expect(linkMatch, "logged line should contain a URL").not.toBeNull();
    const claimUrl = new URL(linkMatch![0]);
    const token = claimUrl.searchParams.get("token");
    expect(token, "magic link should carry a token").toBeTruthy();

    // Account state pre-claim: INVITED, no owner yet, has pendingRecipient.
    const pre = await accounts.get(agent.did);
    expect(pre?.state).toBe("INVITED");
    expect(pre?.owner).toBeUndefined();
    expect(pre?.pendingRecipient).toEqual(recipient);

    // ----- Step 2: human follows the link, claim page POSTs -----
    const claimReq = new Request(`${BASE_URL}/afauth/v1/claim/${token!}`, { method: "POST" });
    const claimResp = await server.handleClaimCompletion(claimReq, {
      authenticated: recipient,
      userId: "usr_alice",
    });

    expect(claimResp.status).toBe(200);
    const claimBody = (await claimResp.json()) as {
      account_did: string;
      state: string;
      owner: { identity: Recipient; user_id: string; claimed_at: string };
    };
    expect(claimBody.state).toBe("CLAIMED");
    expect(claimBody.account_did).toBe(agent.did);
    expect(claimBody.owner.identity).toEqual(recipient);
    expect(claimBody.owner.user_id).toBe("usr_alice");

    // Account state post-claim: CLAIMED, owner present, pending cleared.
    const post = await accounts.get(agent.did);
    expect(post?.state).toBe("CLAIMED");
    expect(post?.owner?.identity).toEqual(recipient);
    expect(post?.pendingRecipient).toBeUndefined();
  });

  it("§7.7 match relation: mismatched email rejected with 403 owner_authentication_required", async () => {
    const { server } = buildServer();
    const agent = await Agent.generate();

    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "alice@example.com" },
    });
    await server.handleOwnerInvitation(await toRequest(signed));

    const link = consoleSpy.mock.calls[0]![0] as string;
    const token = new URL(/https?:\/\/\S+/.exec(link)![0]).searchParams.get("token")!;

    const claimReq = new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" });
    const wrongIdentity: Recipient = { type: "email", value: "mallory@example.com" };

    await expect(
      server.handleClaimCompletion(claimReq, {
        authenticated: wrongIdentity,
        userId: "usr_mallory",
      }),
    ).rejects.toMatchObject({ code: "owner_authentication_required", status: 403 });
  });

  it("invitation case-insensitivity: pending alice@... matches Alice@...", async () => {
    const { server } = buildServer();
    const agent = await Agent.generate();

    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "alice@example.com" },
    });
    await server.handleOwnerInvitation(await toRequest(signed));

    const link = consoleSpy.mock.calls[0]![0] as string;
    const token = new URL(/https?:\/\/\S+/.exec(link)![0]).searchParams.get("token")!;

    const claimReq = new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" });
    const resp = await server.handleClaimCompletion(claimReq, {
      authenticated: { type: "email", value: "Alice@Example.COM" },
      userId: "usr_alice",
    });
    expect(resp.status).toBe(200);
  });

  it("token replay: second claim with same token is 410 invitation_expired", async () => {
    const { server } = buildServer();
    const agent = await Agent.generate();

    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "alice@example.com" },
    });
    await server.handleOwnerInvitation(await toRequest(signed));
    const link = consoleSpy.mock.calls[0]![0] as string;
    const token = new URL(/https?:\/\/\S+/.exec(link)![0]).searchParams.get("token")!;

    const claimReq = new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" });
    await server.handleClaimCompletion(claimReq, {
      authenticated: { type: "email", value: "alice@example.com" },
      userId: "usr_alice",
    });

    await expect(
      server.handleClaimCompletion(claimReq, {
        authenticated: { type: "email", value: "alice@example.com" },
        userId: "usr_alice",
      }),
    ).rejects.toMatchObject({ status: 410 });
  });

  it("new invitation invalidates the prior token (§7.3 atomicity)", async () => {
    const { server } = buildServer();
    const agent = await Agent.generate();

    // First invitation.
    const signed1 = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "alice@example.com" },
    });
    await server.handleOwnerInvitation(await toRequest(signed1));
    const token1 = new URL(
      /https?:\/\/\S+/.exec(consoleSpy.mock.calls[0]![0] as string)![0],
    ).searchParams.get("token")!;

    // Second invitation — supersedes the first.
    const signed2 = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "bob@example.com" },
    });
    await server.handleOwnerInvitation(await toRequest(signed2));

    // First token is now invalid.
    const claimReq = new Request(`${BASE_URL}/afauth/v1/claim/${token1}`, { method: "POST" });
    await expect(
      server.handleClaimCompletion(claimReq, {
        authenticated: { type: "email", value: "alice@example.com" },
        userId: "usr_alice",
      }),
    ).rejects.toMatchObject({ code: "invitation_not_found" });
  });

  it("unsupported recipient type → 400 unsupported_recipient_type", async () => {
    // Discovery declares email-only; agent sends phone.
    const { server } = buildServer();
    const agent = await Agent.generate();
    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "phone", value: "+14155550100" },
    });
    await expect(server.handleOwnerInvitation(await toRequest(signed))).rejects.toMatchObject({
      code: "unsupported_recipient_type",
      status: 400,
    });
  });

  it("account-introspection on first GET implicitly creates UNCLAIMED account", async () => {
    const { server, accounts } = buildServer();
    const agent = await Agent.generate();
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });

    const resp = await server.handleAccountIntrospection(await toRequest(signed));
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { account_did: string; state: string; owner?: unknown };
    expect(body.account_did).toBe(agent.did);
    expect(body.state).toBe("UNCLAIMED");
    expect(body.owner).toBeUndefined();

    // The account is now persisted.
    const stored = await accounts.get(agent.did);
    expect(stored?.state).toBe("UNCLAIMED");
  });

  it("discovery handler returns the configured document", async () => {
    const { server } = buildServer();
    const resp = await server.handleDiscovery(
      new Request(`${BASE_URL}/.well-known/afauth`, { method: "GET" }),
    );
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as DiscoveryDocument;
    expect(body.afauth_version).toBe("0.1");
    expect(body.service_did).toBe(DISCOVERY.service_did);
  });
});
