import { describe, it, expect } from "vitest";
import { Agent, signup } from "../index.js";
import type { TrustClient } from "../trust.js";

const BASE = "https://api.example.com";

function discoveryDoc(attestedOnly: boolean) {
  return {
    afauth_version: "0.1",
    service_did: "did:web:api.example.com",
    endpoints: {
      accounts: "/afauth/v1/accounts",
      owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
      claim_page: `${BASE}/claim`,
      claim_completion: "/afauth/v1/claim",
    },
    signature_algorithms: ["ed25519"],
    billing: attestedOnly
      ? { unclaimed_mode: "attested_only", accepted_attestors: ["afauth-trust"] }
      : { unclaimed_mode: "free" },
  };
}

interface Call {
  url: string;
  method: string;
  headers: unknown;
}

function makeFetch(opts: { attestedOnly: boolean; introStatus?: number; introBody?: unknown }) {
  const calls: Call[] = [];
  const fetch = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    calls.push({ url: u, method: init?.method ?? "GET", headers: init?.headers });
    if (u.endsWith("/.well-known/afauth")) {
      return new Response(JSON.stringify(discoveryDoc(opts.attestedOnly)), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify(opts.introBody ?? { ok: true }), {
      status: opts.introStatus ?? 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;
  return { fetch, calls };
}

const future = () => Math.floor(Date.now() / 1000) + 86_400;

describe("signup", () => {
  it("optional mode: sends a signed implicit-signup request, no trust link", async () => {
    const { fetch, calls } = makeFetch({ attestedOnly: false, introBody: { account_did: "x" } });
    const agent = await Agent.generate();
    let linked = false;

    const res = await signup({ agent, baseUrl: BASE, fetch, onLink: () => { linked = true; } });

    expect(linked).toBe(false);
    expect(res.status).toBe(200);
    expect(res.account).toEqual({ account_did: "x" });
    expect(res.trust).toBeUndefined();

    const intro = calls.find((c) => c.url.endsWith("/afauth/v1/accounts/me"));
    expect(intro).toBeTruthy();
    expect((intro!.headers as Record<string, string>)["signature-input"]).toBeTruthy();
  });

  it("attested_only with a reusable binding: skips the human link", async () => {
    const { fetch } = makeFetch({ attestedOnly: true, introBody: { account_did: "y" } });
    const agent = await Agent.generate();
    let linked = false;

    const res = await signup({
      agent,
      baseUrl: BASE,
      fetch,
      binding: { binding_id: "bnd_x", binding_token_expires_at: future() },
      onLink: () => { linked = true; },
    });

    expect(linked).toBe(false); // already linked → no human in the loop
    expect(res.status).toBe(200);
    expect(res.account).toEqual({ account_did: "y" });
    expect(res.trust).toBeTruthy();
    expect(res.binding?.binding_id).toBe("bnd_x");
  });

  it("attested_only unlinked: surfaces the link, polls, then signs up", async () => {
    const agent = await Agent.generate();
    const exp = future();
    let polls = 0;
    const stubTrust = {
      agentDid: agent.did,
      isLinked: () => false,
      getBinding: () => undefined,
      linkStart: async () => ({
        req_id: "req1",
        link_url: "https://trust.afauth.org/link?x",
        poll_url: "https://trust.afauth.org/poll",
        expires_in: 1800,
      }),
      linkPoll: async () => (++polls >= 2 ? { binding_id: "bnd_new", binding_token_expires_at: exp } : undefined),
    } as unknown as TrustClient;
    const { fetch } = makeFetch({ attestedOnly: true, introBody: { account_did: "z" } });
    const shown: string[] = [];

    const res = await signup({
      agent,
      baseUrl: BASE,
      fetch,
      trust: stubTrust,
      onLink: (url) => { shown.push(url); },
      pollIntervalMs: 1,
    });

    expect(shown).toEqual(["https://trust.afauth.org/link?x"]);
    expect(polls).toBeGreaterThanOrEqual(2);
    expect(res.binding).toEqual({ binding_id: "bnd_new", binding_token_expires_at: exp });
    expect(res.account).toEqual({ account_did: "z" });
  });

  it("throws on a non-2xx signup response", async () => {
    const { fetch } = makeFetch({ attestedOnly: false, introStatus: 403, introBody: { error: "nope" } });
    const agent = await Agent.generate();
    await expect(signup({ agent, baseUrl: BASE, fetch })).rejects.toThrow(/signup failed/);
  });

  it("throws when the human doesn't confirm before the link expires", async () => {
    const agent = await Agent.generate();
    const stubTrust = {
      agentDid: agent.did,
      isLinked: () => false,
      getBinding: () => undefined,
      linkStart: async () => ({ req_id: "r", link_url: "https://trust.afauth.org/link?x", poll_url: "p", expires_in: 1 }),
      linkPoll: async () => undefined, // never confirms
    } as unknown as TrustClient;
    const { fetch } = makeFetch({ attestedOnly: true });
    let n = 0;
    const now = () => (n++ === 0 ? 1000 : 999_999); // 1st call sets the deadline, 2nd is past it
    await expect(
      signup({ agent, baseUrl: BASE, fetch, trust: stubTrust, onLink: () => {}, pollIntervalMs: 1, now }),
    ).rejects.toThrow(/expired/);
  });
});
