/**
 * Integration tests for `createWorker`.
 *
 * Boots the handler with in-memory stores (MemoryAccountStore, etc.)
 * and dispatches real `Request` objects through it. This is the only
 * place the routing layer is exercised end-to-end — the per-store
 * tests (d1-account-store, durable-object-nonce-store) cover storage
 * but not how the worker glues those stores to the §4.3 endpoint
 * shape.
 *
 * Notes on choices:
 *   - Memory stores are used because the routing is the unit under
 *     test, and the spec-conformance tests in @afauthhq/server already
 *     prove these stores' behaviour. Routing is correct iff the
 *     handler dispatches to the right Server.handle* method.
 *   - The agent signs real requests through `@afauthhq/agent`, so the
 *     happy paths go through the same Verifier code paths real
 *     deployments use.
 */

import { describe, expect, it, vi } from "vitest";
import { Agent } from "@afauthhq/agent";
import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  type DiscoveryDocument,
  type OwnerSession,
} from "@afauthhq/server";

import { createWorker } from "../index.js";

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
  recipient_types: ["email"],
};

interface Harness {
  fetch: (req: Request) => Promise<Response>;
  accounts: MemoryAccountStore;
  revocation: MemoryRevocationList;
  setOwnerSession: (next: OwnerSession | null) => void;
}

function buildWorker(opts?: {
  discovery?: DiscoveryDocument | (() => Promise<DiscoveryDocument>);
  ownerSession?: OwnerSession | null;
}): Harness {
  const accounts = new MemoryAccountStore();
  const revocation = new MemoryRevocationList();
  let session: OwnerSession | null = opts?.ownerSession ?? null;
  const worker = createWorker({
    nonceStore: new MemoryNonceStore(),
    revocationList: revocation,
    serviceDid: DISCOVERY.service_did,
    accounts,
    recipients: { email: consoleEmailHandler },
    discovery: opts?.discovery ?? DISCOVERY,
    baseUrl: BASE_URL,
    extractOwnerSession: async () => session,
  });
  // The worker's fetch is typed against cloudflare's incoming-request
  // Request (`Request<unknown, IncomingRequestCfProperties>`), not the
  // DOM Request the test constructs. The runtime accepts either —
  // miniflare hands DOM Requests to user fetch handlers — but tsc
  // doesn't, so we cast at this boundary.
  const dispatch = worker.fetch! as (req: Request, env: unknown, ctx: unknown) => Promise<Response>;
  return {
    fetch: (req) => dispatch(req, {} as never, {} as never),
    accounts,
    revocation,
    setOwnerSession: (next) => {
      session = next;
    },
  };
}

async function toRequest(signed: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | Uint8Array | null;
}): Promise<Request> {
  // RequestInit.body accepts BufferSource at runtime (and the DOM lib
  // types reflect that), but workers-types narrows BodyInit in a way
  // that excludes Uint8Array. Cast at the boundary — see fetch dispatch
  // comment in buildWorker for the same workers-types/DOM tension.
  return new Request(signed.url, {
    method: signed.method,
    headers: signed.headers,
    body: (signed.body === null ? undefined : signed.body) as BodyInit | undefined,
  });
}

describe("createWorker — discovery", () => {
  it("serves /.well-known/afauth before any other route is resolved", async () => {
    const { fetch } = buildWorker();
    const res = await fetch(new Request(`${BASE_URL}/.well-known/afauth`));
    expect(res.status).toBe(200);
    const body = (await res.json()) as DiscoveryDocument;
    expect(body.afauth_version).toBe("0.1");
    expect(body.service_did).toBe(DISCOVERY.service_did);
  });

  it("memoises a function discovery across requests that need route resolution", async () => {
    let calls = 0;
    const { fetch } = buildWorker({
      discovery: async () => {
        calls++;
        return DISCOVERY;
      },
    });
    // Two non-well-known requests force route resolution. The worker's
    // private `resolve()` memoises after the first call.
    // Note: the well-known route bypasses the resolver (it asks the
    // Server directly), so this test deliberately avoids it.
    await fetch(new Request(`${BASE_URL}/afauth/v1/accounts/me`));
    await fetch(new Request(`${BASE_URL}/afauth/v1/accounts/me`));
    expect(calls).toBe(1);
  });
});

describe("createWorker — routing", () => {
  it("routes a signed GET /accounts/me to the introspection handler", async () => {
    const { fetch, accounts } = buildWorker();
    const agent = await Agent.generate();
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const res = await fetch(await toRequest(signed));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { account_id: string; agent_did: string; state: string };
    expect(body.agent_did).toBe(agent.did);
    expect(body.state).toBe("UNCLAIMED");
    // implicit signup created the row
    expect(await accounts.getByAgentDid(agent.did)).not.toBeNull();
  });

  it("routes a signed owner-invitation POST through the recipient handler", async () => {
    const { fetch, accounts } = buildWorker();
    const agent = await Agent.generate();
    // Introspect to materialise UNCLAIMED account.
    await fetch(await toRequest(await agent.buildAccountIntrospection({ baseUrl: BASE_URL })));
    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "alice@example.com" },
    });
    const res = await fetch(await toRequest(signed));
    expect(res.status).toBe(202);
    const body = (await res.json()) as { invitation_id: string; state: string };
    expect(body.invitation_id).toBeTruthy();
    expect(body.state).toBe("INVITED");
    const account = await accounts.getByAgentDid(agent.did);
    expect(account?.state).toBe("INVITED");
  });

  it("routes a key-rotation POST and updates the account DID", async () => {
    const { fetch, accounts } = buildWorker();
    const oldAgent = await Agent.generate();
    await fetch(await toRequest(await oldAgent.buildAccountIntrospection({ baseUrl: BASE_URL })));

    const newAgent = await Agent.generate();
    const signed = await oldAgent.buildKeyRotation({ baseUrl: BASE_URL, newDid: newAgent.did });
    const res = await fetch(await toRequest(signed));
    expect(res.status).toBe(200);

    expect(await accounts.getByAgentDid(oldAgent.did)).toBeNull();
    const moved = await accounts.getByAgentDid(newAgent.did);
    expect(moved?.state).toBe("UNCLAIMED");
  });

  it("returns 404 on unknown paths", async () => {
    const { fetch } = buildWorker();
    const res = await fetch(new Request(`${BASE_URL}/not/a/known/path`));
    expect(res.status).toBe(404);
  });

  it("returns 404 when method does not match (POST on a GET route)", async () => {
    const { fetch } = buildWorker();
    // /accounts/me is GET-only; a POST should miss every route and 404.
    const res = await fetch(new Request(`${BASE_URL}/afauth/v1/accounts/me`, { method: "POST" }));
    expect(res.status).toBe(404);
  });

  it("skips key-rotation routing when discovery omits the endpoint", async () => {
    const trimmed: DiscoveryDocument = {
      ...DISCOVERY,
      endpoints: { ...DISCOVERY.endpoints },
    };
    delete (trimmed.endpoints as Record<string, unknown>).key_rotation;
    const { fetch } = buildWorker({ discovery: trimmed });
    const agent = await Agent.generate();
    const signed = await agent.buildKeyRotation({
      baseUrl: BASE_URL,
      newDid: (await Agent.generate()).did,
    });
    const res = await fetch(await toRequest(signed));
    // Route not in the table → 404.
    expect(res.status).toBe(404);
  });
});

describe("createWorker — claim completion requires owner session", () => {
  it("rejects with 401 owner_authentication_required when the extractor returns null", async () => {
    const { fetch } = buildWorker();
    const res = await fetch(
      new Request(`${BASE_URL}/afauth/v1/claim/some-token`, { method: "POST" }),
    );
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("owner_authentication_required");
  });

  it("invokes the claim-completion handler when a session is available", async () => {
    // Full ceremony: introspect → invite → extract token from logs →
    // claim with the matching session.
    const consoleErrorSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    try {
      const harness = buildWorker();
      const agent = await Agent.generate();
      await harness.fetch(
        await toRequest(await agent.buildAccountIntrospection({ baseUrl: BASE_URL })),
      );
      await harness.fetch(
        await toRequest(
          await agent.buildOwnerInvitation({
            baseUrl: BASE_URL,
            recipient: { type: "email", value: "alice@example.com" },
          }),
        ),
      );

      // consoleEmailHandler logs the magic link. Extract the token.
      const logged = consoleErrorSpy.mock.calls
        .flat()
        .map((arg) => (typeof arg === "string" ? arg : ""))
        .join("\n");
      const m = logged.match(/token=([A-Za-z0-9_-]+)/);
      if (!m) throw new Error(`no token in logs:\n${logged}`);
      const token = m[1];

      harness.setOwnerSession({
        authenticated: { type: "email", value: "alice@example.com" },
        userId: "usr_alice",
      });
      const res = await harness.fetch(
        new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" }),
      );
      expect(res.status).toBe(200);
      const account = await harness.accounts.getByAgentDid(agent.did);
      expect(account?.state).toBe("CLAIMED");
    } finally {
      consoleErrorSpy.mockRestore();
    }
  });
});

describe("createWorker — error envelope passthrough", () => {
  it("AFAuth errors thrown inside handlers serialise via toResponse (401 envelope)", async () => {
    const { fetch } = buildWorker();
    // No Signature-Input header → Verifier throws AFAuthError; the
    // worker's catch should serialise it through err.toResponse.
    const res = await fetch(
      new Request(`${BASE_URL}/afauth/v1/accounts/me/owner-invitation`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ recipient: { type: "email", value: "alice@example.com" } }),
      }),
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/json");
    const body = (await res.json()) as { error: { code: string } };
    // The exact code varies by the missing-header branch; assert the
    // envelope shape is present.
    expect(body.error.code).toBeTruthy();
    expect(typeof body.error.code).toBe("string");
  });

  it("unexpected errors fall back to a 500 with a generic envelope", async () => {
    // Force resolve() to throw by passing a function discovery that
    // throws. The first non-well-known request triggers route resolution.
    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const worker = createWorker({
        nonceStore: new MemoryNonceStore(),
        revocationList: new MemoryRevocationList(),
        serviceDid: DISCOVERY.service_did,
        accounts: new MemoryAccountStore(),
        recipients: { email: consoleEmailHandler },
        discovery: async () => {
          throw new Error("synthetic discovery failure");
        },
        baseUrl: BASE_URL,
        extractOwnerSession: async () => null,
      });
      const dispatch = worker.fetch! as (
        req: Request,
        env: unknown,
        ctx: unknown,
      ) => Promise<Response>;
      const res = await dispatch(
        new Request(`${BASE_URL}/afauth/v1/accounts/me`),
        {} as never,
        {} as never,
      );
      expect(res.status).toBe(500);
      expect(consoleErrorSpy).toHaveBeenCalled();
    } finally {
      consoleErrorSpy.mockRestore();
    }
  });
});

describe("createWorker — owner-gated key endpoints (§8.2 re-key, §8.4 revoke)", () => {
  const REKEY_DISCOVERY: DiscoveryDocument = {
    ...DISCOVERY,
    endpoints: {
      ...DISCOVERY.endpoints,
      key_rekey: "/afauth/v1/accounts/me/keys/rekey",
      key_revocation: "/afauth/v1/accounts/me/keys/revoke",
    },
  };

  function freshSession(): OwnerSession {
    return {
      authenticated: { type: "email", value: "alice@example.com" },
      userId: "usr_alice",
      authenticatedAt: new Date().toISOString(),
    };
  }

  /** Walk an agent to CLAIMED through the worker, then return the harness. */
  async function claimedHarness() {
    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const harness = buildWorker({ discovery: REKEY_DISCOVERY });
    const agent = await Agent.generate();
    await harness.fetch(await toRequest(await agent.buildAccountIntrospection({ baseUrl: BASE_URL })));
    await harness.fetch(
      await toRequest(
        await agent.buildOwnerInvitation({
          baseUrl: BASE_URL,
          recipient: { type: "email", value: "alice@example.com" },
        }),
      ),
    );
    const token = consoleErrorSpy.mock.calls
      .flat()
      .map((a) => (typeof a === "string" ? a : ""))
      .join("\n")
      .match(/token=([A-Za-z0-9_-]+)/)![1];
    harness.setOwnerSession({
      authenticated: { type: "email", value: "alice@example.com" },
      userId: "usr_alice",
    });
    await harness.fetch(new Request(`${BASE_URL}/afauth/v1/claim/${token}`, { method: "POST" }));
    consoleErrorSpy.mockRestore();
    return { harness, agent };
  }

  it("routes a re-key POST to the handler (account moves to the new DID)", async () => {
    const { harness, agent } = await claimedHarness();
    harness.setOwnerSession(freshSession());
    const newAgent = await Agent.generate();
    const res = await harness.fetch(
      new Request(`${BASE_URL}/afauth/v1/accounts/me/keys/rekey`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ current_account_did: agent.did, new_account_did: newAgent.did }),
      }),
    );
    expect(res.status).toBe(200);
    expect(await harness.accounts.getByAgentDid(agent.did)).toBeNull();
    expect((await harness.accounts.getByAgentDid(newAgent.did))?.state).toBe("CLAIMED");
  });

  it("routes a revoke POST to the handler", async () => {
    const { harness, agent } = await claimedHarness();
    harness.setOwnerSession(freshSession());
    const res = await harness.fetch(
      new Request(`${BASE_URL}/afauth/v1/accounts/me/keys/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agent_did: agent.did }),
      }),
    );
    expect(res.status).toBe(200);
    expect((await harness.accounts.getByAgentDid(agent.did))?.revoked).toBe(true);
  });

  it("re-key / revoke with no owner session → 401 owner_authentication_required", async () => {
    const harness = buildWorker({ discovery: REKEY_DISCOVERY }); // session null by default
    for (const path of ["rekey", "revoke"]) {
      const res = await harness.fetch(
        new Request(`${BASE_URL}/afauth/v1/accounts/me/keys/${path}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        }),
      );
      expect(res.status).toBe(401);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
        "owner_authentication_required",
      );
    }
  });

  it("skips re-key / revoke routing when discovery omits the endpoints", async () => {
    const harness = buildWorker(); // base DISCOVERY has neither endpoint
    harness.setOwnerSession(freshSession());
    const res = await harness.fetch(
      new Request(`${BASE_URL}/afauth/v1/accounts/me/keys/rekey`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
    );
    expect(res.status).toBe(404);
  });
});
