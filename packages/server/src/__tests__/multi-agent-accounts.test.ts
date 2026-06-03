/**
 * §10.4.4 multi-agent accounts — one human, one account, many devices.
 *
 * A human links a PC agent and a phone agent to the same trust principal;
 * both `did:key`s carry the same `sub_h`. They must resolve to the SAME
 * service account (`account_id`), like logging into one account from two
 * devices — NOT two accounts, and NOT a rejected second device.
 *
 * Agents that carry no `sub_h` (attestation off/optional, runtime-only) get
 * distinct singleton accounts — there is no human to group on.
 */

import { Agent } from "@afauthhq/agent";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  HmacAttestor,
  MemoryAccountStore,
  MemoryNonceStore,
  defineService,
  type RecipientHandler,
} from "../index.js";

const SERVICE_DID = "did:web:api.example.com";
const BASE_URL = "https://api.example.com";

const SUB_H_ALICE = "8f3cZ_K9qWmA-LpQ7tVnRsxBcD2yE0HfJgIuYpXoNkM";
const SUB_H_BOB = "Qm2bX9wL4pR7nK0sT1vU8yA-cE3dF5gH6jI7kZ_oBpN";
const SECRET = new TextEncoder().encode("this-secret-is-at-least-32-bytes-long-enough-for-hs256");

const emailHandler: RecipientHandler = { async initiate() {}, matches() { return true; } };

async function makeToken(opts: { sub: string; aud?: string; iss?: string; subH?: string }): Promise<string> {
  const payload: Record<string, unknown> = {};
  if (opts.subH !== undefined) {
    payload.verification = "oauth";
    payload.sub_h = opts.subH;
  }
  const b = new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(opts.iss ?? "test-attestor")
    .setSubject(opts.sub)
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .setExpirationTime(Math.floor(Date.now() / 1000) + 60);
  if (opts.aud) b.setAudience(opts.aud);
  return b.sign(SECRET);
}

function newService(accounts = new MemoryAccountStore()) {
  return {
    accounts,
    server: defineService({
      baseUrl: BASE_URL,
      serviceDid: SERVICE_DID,
      accounts,
      recipients: { email: emailHandler },
      nonceStore: new MemoryNonceStore(),
      attestor: new HmacAttestor({ iss: "test-attestor", secret: SECRET }),
    }),
  };
}

/** Signed introspection with an attestation header; returns parsed body + status. */
async function signup(
  server: ReturnType<typeof newService>["server"],
  agent: Agent,
  jwt: string,
): Promise<{ status: number; account_id?: string; agent_did?: string; state?: string }> {
  const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
  const headers = new Headers(signed.headers);
  headers.set("afauth-attestation", jwt);
  const resp = await server
    .handleAccountIntrospection(new Request(signed.url, { method: signed.method, headers }))
    .catch((e) => (e as { toResponse: () => Response }).toResponse());
  const body = (await resp.json()) as Record<string, string>;
  return { status: resp.status, ...body };
}

describe("§10.4.4 multi-agent accounts (defineService)", () => {
  it("two agent DIDs sharing (iss, sub_h) resolve to the SAME account_id (PC + phone)", async () => {
    const { server } = newService();

    const pc = await Agent.generate();
    const phone = await Agent.generate();
    const r1 = await signup(server, pc, await makeToken({ sub: pc.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    const r2 = await signup(server, phone, await makeToken({ sub: phone.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));

    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    // Same human → one account, two devices.
    expect(r1.account_id).toBeDefined();
    expect(r2.account_id).toBe(r1.account_id);
    // Each response echoes the calling credential.
    expect(r1.agent_did).toBe(pc.did);
    expect(r2.agent_did).toBe(phone.did);
  });

  it("different principals (distinct sub_h) get different accounts", async () => {
    const { server } = newService();
    const alice = await Agent.generate();
    const bob = await Agent.generate();
    const ra = await signup(server, alice, await makeToken({ sub: alice.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    const rb = await signup(server, bob, await makeToken({ sub: bob.did, aud: SERVICE_DID, subH: SUB_H_BOB }));
    expect(ra.account_id).not.toBe(rb.account_id);
  });

  it("agents with no sub_h get distinct singleton accounts", async () => {
    const { server } = newService();
    const a1 = await Agent.generate();
    const a2 = await Agent.generate();
    const r1 = await signup(server, a1, await makeToken({ sub: a1.did, aud: SERVICE_DID }));
    const r2 = await signup(server, a2, await makeToken({ sub: a2.did, aud: SERVICE_DID }));
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(r1.account_id).not.toBe(r2.account_id);
  });

  it("re-signup of the same agent DID is idempotent (same account_id)", async () => {
    const { server } = newService();
    const a = await Agent.generate();
    const r1 = await signup(server, a, await makeToken({ sub: a.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    const r2 = await signup(server, a, await makeToken({ sub: a.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    expect(r2.account_id).toBe(r1.account_id);
  });
});

describe("MemoryAccountStore — multi-agent model (unit)", () => {
  const P = { iss: "afauth-trust", subH: SUB_H_ALICE };
  const A = "did:key:zPc";
  const B = "did:key:zPhone";
  const C = "did:key:zTablet";

  it("signupAgent groups a second principal device onto the first account", async () => {
    const s = new MemoryAccountStore();
    const first = await s.signupAgent({ did: A, principal: P });
    expect(first.attached).toBe(false);
    const second = await s.signupAgent({ did: B, principal: P });
    expect(second.attached).toBe(true);
    expect(second.account.accountId).toBe(first.account.accountId);
    expect(second.account.agents.map((x) => x.did).sort()).toEqual([A, B].sort());
    // Both credentials resolve to that one account.
    expect((await s.getByAgentDid(A))!.accountId).toBe(first.account.accountId);
    expect((await s.getByAgentDid(B))!.accountId).toBe(first.account.accountId);
  });

  it("findByPrincipal returns the grouped account; no-principal signups are singletons", async () => {
    const s = new MemoryAccountStore();
    const { account } = await s.signupAgent({ did: A, principal: P });
    expect((await s.findByPrincipal(P.iss, P.subH))!.accountId).toBe(account.accountId);
    const solo1 = await s.signupAgent({ did: B });
    const solo2 = await s.signupAgent({ did: C });
    expect(solo1.account.accountId).not.toBe(solo2.account.accountId);
  });

  it("rotateAgent swaps a credential and keeps account_id stable", async () => {
    const s = new MemoryAccountStore();
    const { account } = await s.signupAgent({ did: A, principal: P });
    const rotated = await s.rotateAgent(A, C, new Date().toISOString());
    expect(rotated.accountId).toBe(account.accountId); // stable
    expect(await s.getByAgentDid(A)).toBeNull(); // old credential gone
    expect((await s.getByAgentDid(C))!.accountId).toBe(account.accountId);
  });

  it("whole-account revoke flags the account; the credentials still resolve to it", async () => {
    const s = new MemoryAccountStore();
    const { account } = await s.signupAgent({ did: A, principal: P });
    await s.signupAgent({ did: B, principal: P });
    const revoked = await s.revoke(account.accountId, new Date().toISOString());
    expect(revoked.revoked).toBe(true);
    expect(revoked.agents.map((x) => x.did).sort()).toEqual([A, B].sort());
  });
});
