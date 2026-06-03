/**
 * §11.3 rate_limit_exceeded enforcement tests.
 *
 * Exercises both the standalone MemoryRateLimiter (window resets,
 * over-limit decisions, retryAfter math) and end-to-end Server
 * integration (handleOwnerInvitation refusing the 11th call within
 * the window, the response carrying Retry-After and an §11.1
 * envelope).
 */

import { describe, expect, it } from "vitest";
import { Agent } from "@afauthhq/agent";
import {
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRateLimiter,
  Server,
  type DiscoveryDocument,
  type RecipientHandler,
} from "../index.js";

const SERVICE_DID = "did:web:api.example.com";
const BASE_URL = "https://api.example.com";

const discovery: DiscoveryDocument = {
  afauth_version: "0.1",
  service_did: SERVICE_DID,
  endpoints: {
    accounts: "/afauth/v1/accounts",
    owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
    claim_page: "https://claim.example.com",
    claim_completion: "/afauth/v1/claim",
  },
  signature_algorithms: ["ed25519"],
  recipient_types: ["email"],
};

const emailHandler: RecipientHandler = {
  async initiate() { /* noop */ },
  matches({ pending, authenticated }) {
    return authenticated.type === "email" && pending.type === "email"
      && pending.value.toLowerCase() === authenticated.value.toLowerCase();
  },
};

function newServer(opts: { limit: number; windowSeconds: number; now?: () => number }) {
  const accounts = new MemoryAccountStore();
  const limiter = new MemoryRateLimiter({ now: opts.now });
  return {
    accounts,
    limiter,
    server: new Server({
      nonceStore: new MemoryNonceStore(),
      revocationList: undefined,
      serviceDid: SERVICE_DID,
      accounts,
      recipients: { email: emailHandler },
      discovery,
      baseUrl: BASE_URL,
      rateLimiter: limiter,
      rateLimits: {
        owner_invitation: { limit: opts.limit, windowSeconds: opts.windowSeconds },
      },
    }),
  };
}

describe("MemoryRateLimiter", () => {
  it("accepts up to `limit` calls within a window, then refuses with retryAfter", async () => {
    let now = 1_000_000;
    const limiter = new MemoryRateLimiter({ now: () => now });
    const cfg = { limit: 3, windowSeconds: 60 };

    let d = await limiter.take("k", cfg);
    expect(d.ok).toBe(true);
    expect(d.remaining).toBe(2);

    d = await limiter.take("k", cfg);
    expect(d.ok).toBe(true);
    d = await limiter.take("k", cfg);
    expect(d.ok).toBe(true);
    expect(d.remaining).toBe(0);

    d = await limiter.take("k", cfg);
    expect(d.ok).toBe(false);
    expect(d.retryAfter).toBe(60);
    expect(d.resetAt).toBe(1_000_060);
  });

  it("resets when the window elapses", async () => {
    let now = 1_000_000;
    const limiter = new MemoryRateLimiter({ now: () => now });
    const cfg = { limit: 2, windowSeconds: 30 };
    await limiter.take("k", cfg);
    await limiter.take("k", cfg);
    expect((await limiter.take("k", cfg)).ok).toBe(false);

    now += 30;
    const after = await limiter.take("k", cfg);
    expect(after.ok).toBe(true);
    expect(after.remaining).toBe(1);
  });

  it("isolates keys", async () => {
    const limiter = new MemoryRateLimiter();
    const cfg = { limit: 1, windowSeconds: 60 };
    expect((await limiter.take("a", cfg)).ok).toBe(true);
    expect((await limiter.take("b", cfg)).ok).toBe(true);
    expect((await limiter.take("a", cfg)).ok).toBe(false);
    expect((await limiter.take("b", cfg)).ok).toBe(false);
  });
});

describe("Server.handleOwnerInvitation enforces rate limits", () => {
  it("returns 429 + Retry-After + §11.1 envelope when limit exceeded", async () => {
    // Freeze the clock: owner-invitation signing (async crypto) runs between
    // requests, so a real wall-clock second can tick by before the over-limit
    // request and make Retry-After 3599. The window itself is unchanged, so pin
    // `now` to assert the exact value deterministically (was a CI flake).
    const { server, accounts } = newServer({
      limit: 2,
      windowSeconds: 3600,
      now: () => 1_700_000_000,
    });
    const agent = await Agent.generate();
    await accounts.createUnclaimed(agent.did);

    async function sendInvite() {
      const signed = await agent.buildOwnerInvitation({
        baseUrl: BASE_URL,
        recipient: { type: "email", value: "alice@example.com" },
      });
      const req = new Request(signed.url, {
        method: signed.method,
        headers: new Headers(signed.headers),
        body: (signed.body ?? undefined) as BodyInit | undefined,
      });
      return server.handleOwnerInvitation(req);
    }

    const first = await sendInvite();
    expect(first.status).toBe(202);
    const second = await sendInvite();
    expect(second.status).toBe(202);

    // The third should be rate-limited.
    let third: Response | undefined;
    try {
      third = await sendInvite();
    } catch (e) {
      // Server.handle* throws AFAuthError; the worker layer would
      // call .toResponse(). Simulate that path here.
      const err = e as { toResponse?: () => Response };
      if (err.toResponse) third = err.toResponse();
    }
    expect(third).toBeDefined();
    expect(third!.status).toBe(429);
    expect(third!.headers.get("retry-after")).toBe("3600");
    const body = await third!.json() as { error: { code: string; details?: { retry_after: number } } };
    expect(body.error.code).toBe("rate_limit_exceeded");
    expect(body.error.details?.retry_after).toBe(3600);
  });

  it("each agent DID gets its own bucket", async () => {
    const { server, accounts } = newServer({ limit: 1, windowSeconds: 3600 });
    const alice = await Agent.generate();
    const bob = await Agent.generate();
    await accounts.createUnclaimed(alice.did);
    await accounts.createUnclaimed(bob.did);

    async function inviteAs(agent: Agent) {
      const signed = await agent.buildOwnerInvitation({
        baseUrl: BASE_URL,
        recipient: { type: "email", value: "x@example.com" },
      });
      return server.handleOwnerInvitation(new Request(signed.url, {
        method: signed.method,
        headers: new Headers(signed.headers),
        body: (signed.body ?? undefined) as BodyInit | undefined,
      }));
    }

    expect((await inviteAs(alice)).status).toBe(202);
    // Alice's second hit is rate-limited.
    let aliceSecond: Response;
    try {
      aliceSecond = await inviteAs(alice);
    } catch (e) {
      aliceSecond = (e as { toResponse: () => Response }).toResponse();
    }
    expect(aliceSecond!.status).toBe(429);

    // Bob still has his own budget.
    expect((await inviteAs(bob)).status).toBe(202);
  });

  it("no limiter configured → no rate limiting (default behaviour)", async () => {
    const accounts = new MemoryAccountStore();
    const server = new Server({
      nonceStore: new MemoryNonceStore(),
      serviceDid: SERVICE_DID,
      accounts,
      recipients: { email: emailHandler },
      discovery,
      baseUrl: BASE_URL,
      // no rateLimiter / rateLimits
    });
    const agent = await Agent.generate();
    await accounts.createUnclaimed(agent.did);
    for (let i = 0; i < 5; i++) {
      const signed = await agent.buildOwnerInvitation({
        baseUrl: BASE_URL,
        recipient: { type: "email", value: "x@example.com" },
      });
      const r = await server.handleOwnerInvitation(new Request(signed.url, {
        method: signed.method,
        headers: new Headers(signed.headers),
        body: (signed.body ?? undefined) as BodyInit | undefined,
      }));
      expect(r.status).toBe(202);
    }
  });

  it("limiter configured but no route entry → no rate limiting for that route", async () => {
    const accounts = new MemoryAccountStore();
    const server = new Server({
      nonceStore: new MemoryNonceStore(),
      serviceDid: SERVICE_DID,
      accounts,
      recipients: { email: emailHandler },
      discovery,
      baseUrl: BASE_URL,
      rateLimiter: new MemoryRateLimiter(),
      rateLimits: {
        // key_rotation configured; owner_invitation absent → no limit
        key_rotation: { limit: 1, windowSeconds: 3600 },
      },
    });
    const agent = await Agent.generate();
    await accounts.createUnclaimed(agent.did);
    for (let i = 0; i < 3; i++) {
      const signed = await agent.buildOwnerInvitation({
        baseUrl: BASE_URL,
        recipient: { type: "email", value: "x@example.com" },
      });
      const r = await server.handleOwnerInvitation(new Request(signed.url, {
        method: signed.method,
        headers: new Headers(signed.headers),
        body: (signed.body ?? undefined) as BodyInit | undefined,
      }));
      expect(r.status).toBe(202);
    }
  });
});
