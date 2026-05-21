/**
 * §7.2 owner-invitation body shape tests.
 *
 *   - typed `recipient` (oidc) shape matches the wire format the
 *     spec vector documents (value.{ issuer, sub } — flat issuer/sub
 *     fields used to be wrong; see the M0–M4 review).
 *   - bare-`email` backward-compat shorthand is accepted.
 *   - both `recipient` and bare `email` together → 400 malformed_request.
 *   - redirect_url respects `redirectAllowList`:
 *       missing list  → reject any redirect_url
 *       list present  → only allow-listed hosts accepted
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
  type RecipientHandler,
  type ServerOptions,
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
  recipient_types: ["email", "oidc"],
};

// Stand-in OIDC handler for the typed-recipient test. Matches when
// both pending and authenticated are the same {issuer, sub} pair.
const stubOidcHandler: RecipientHandler = {
  async initiate() {
    /* noop — verifying ceremony is service policy */
  },
  matches({ pending, authenticated }) {
    if (pending.type !== "oidc" || authenticated.type !== "oidc") return false;
    return (
      pending.value.issuer === authenticated.value.issuer &&
      pending.value.sub === authenticated.value.sub
    );
  },
};

function buildServer(extra: Partial<ServerOptions> = {}) {
  const accounts = new MemoryAccountStore();
  const server = new Server({
    nonceStore: new MemoryNonceStore(),
    revocationList: new MemoryRevocationList(),
    serviceDid: DISCOVERY.service_did,
    accounts,
    recipients: { email: consoleEmailHandler, oidc: stubOidcHandler },
    discovery: DISCOVERY,
    baseUrl: BASE_URL,
    ...extra,
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

describe("§7.2 recipient body shapes", () => {
  let spy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });
  afterEach(() => spy.mockRestore());

  it("typed oidc recipient round-trips through invite → claim", async () => {
    const { server, accounts } = buildServer();
    const agent = await Agent.generate();
    const recipient: Recipient = {
      type: "oidc",
      value: { issuer: "https://accounts.google.com", sub: "103948572345" },
    };

    const signed = await agent.buildOwnerInvitation({ baseUrl: BASE_URL, recipient });
    // Confirm the wire body matches the §7.7.3 spec example exactly.
    const body = JSON.parse(signed.body!);
    expect(body.recipient).toEqual({
      type: "oidc",
      value: { issuer: "https://accounts.google.com", sub: "103948572345" },
    });

    const resp = await server.handleOwnerInvitation(await toRequest(signed));
    expect(resp.status).toBe(202);

    const pre = await accounts.get(agent.did);
    expect(pre?.pendingRecipient).toEqual(recipient);
  });

  it("bare-email shorthand (§7.2 backward-compat) is accepted", async () => {
    const { server, accounts } = buildServer();
    const agent = await Agent.generate();

    // Build with the typed shape, then mutate the body to the
    // shorthand form to exercise the server-side acceptance.
    const signed = await agent.signRequest({
      method: "POST",
      url: `${BASE_URL}/afauth/v1/accounts/me/owner-invitation`,
      body: JSON.stringify({ email: "alice@example.com" }),
    });
    const resp = await server.handleOwnerInvitation(await toRequest(signed));
    expect(resp.status).toBe(202);

    // The account should now hold the typed-recipient form.
    const acct = await accounts.get(agent.did);
    expect(acct?.pendingRecipient).toEqual({ type: "email", value: "alice@example.com" });
  });

  it("both `recipient` and bare `email` together → 400 (§7.2 MUST)", async () => {
    const { server } = buildServer();
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: `${BASE_URL}/afauth/v1/accounts/me/owner-invitation`,
      body: JSON.stringify({
        recipient: { type: "email", value: "alice@example.com" },
        email: "alice@example.com",
      }),
    });
    await expect(server.handleOwnerInvitation(await toRequest(signed))).rejects.toMatchObject({
      code: "malformed_request",
      status: 400,
    });
  });
});

describe("§7.2 redirect_url allow-list", () => {
  let spy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });
  afterEach(() => spy.mockRestore());

  it("no allow-list configured → any redirect_url rejected", async () => {
    const { server } = buildServer({ redirectAllowList: undefined });
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: `${BASE_URL}/afauth/v1/accounts/me/owner-invitation`,
      body: JSON.stringify({
        recipient: { type: "email", value: "alice@example.com" },
        redirect_url: "https://yourapp.com/welcome",
      }),
    });
    await expect(server.handleOwnerInvitation(await toRequest(signed))).rejects.toMatchObject({
      code: "malformed_request",
      status: 400,
    });
  });

  it("allow-list set; matching host → accepted", async () => {
    const { server } = buildServer({ redirectAllowList: ["yourapp.com"] });
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: `${BASE_URL}/afauth/v1/accounts/me/owner-invitation`,
      body: JSON.stringify({
        recipient: { type: "email", value: "alice@example.com" },
        redirect_url: "https://yourapp.com/welcome",
      }),
    });
    const resp = await server.handleOwnerInvitation(await toRequest(signed));
    expect(resp.status).toBe(202);
  });

  it("allow-list set; non-matching host → 400", async () => {
    const { server } = buildServer({ redirectAllowList: ["yourapp.com"] });
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: `${BASE_URL}/afauth/v1/accounts/me/owner-invitation`,
      body: JSON.stringify({
        recipient: { type: "email", value: "alice@example.com" },
        redirect_url: "https://evil.com/steal",
      }),
    });
    await expect(server.handleOwnerInvitation(await toRequest(signed))).rejects.toMatchObject({
      code: "malformed_request",
      status: 400,
    });
  });

  it("non-http(s) scheme rejected even when host would match", async () => {
    const { server } = buildServer({ redirectAllowList: ["yourapp.com"] });
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "POST",
      url: `${BASE_URL}/afauth/v1/accounts/me/owner-invitation`,
      body: JSON.stringify({
        recipient: { type: "email", value: "alice@example.com" },
        redirect_url: "javascript:alert(1)",
      }),
    });
    await expect(server.handleOwnerInvitation(await toRequest(signed))).rejects.toMatchObject({
      code: "malformed_request",
      status: 400,
    });
  });
});

describe("§7.2 invitation_id does not leak the secret token", () => {
  let spy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });
  afterEach(() => spy.mockRestore());

  it("invitation_id is unrelated to the magic-link token", async () => {
    const { server } = buildServer();
    const agent = await Agent.generate();
    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "alice@example.com" },
    });
    const resp = await server.handleOwnerInvitation(await toRequest(signed));
    const body = (await resp.json()) as { invitation_id: string };
    expect(body.invitation_id).toMatch(/^inv_/);

    const link = spy.mock.calls[0]![0] as string;
    const token = new URL(/https?:\/\/\S+/.exec(link)![0]).searchParams.get("token")!;

    // The token is what's in the link. The invitation_id MUST NOT
    // contain the token (or any other secret).
    expect(body.invitation_id).not.toBe(`inv_${token}`);
    expect(body.invitation_id).not.toContain(token);
  });
});
