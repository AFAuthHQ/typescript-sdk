/**
 * Regression: a default `@afauthhq/agent` must interoperate with a service
 * built from `defineService` defaults and routed by `@afauthhq/worker`.
 *
 * The bug this guards against: the agent's protocol-aware builders
 * construct canonical `/afauth/v1/...` request paths, while
 * `defineService`'s synthesized discovery historically advertised
 * divergent paths (`/accounts`, `/owner-invitations`). The worker routes
 * from the advertised discovery, so a default agent's request 404'd — yet
 * every other routed test hardcoded a canonical discovery override, so the
 * split was invisible to the suite. These tests feed `defineService`'s
 * *synthesized* discovery into the worker and drive a default agent
 * through it, end to end.
 */

import { describe, expect, it } from "vitest";
import { Agent } from "@afauthhq/agent";
import {
  consoleEmailHandler,
  defineService,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRevocationList,
  type DiscoveryDocument,
} from "@afauthhq/server";

import { createWorker } from "../index.js";

const BASE_URL = "https://api.example.com";
const SERVICE_DID = "did:web:api.example.com";

/**
 * The exact discovery document `defineService` synthesizes for a default
 * deployment. `attestation: "off"` isolates the routing question: the
 * synthesized endpoint *paths* are identical across attestation modes, and
 * leaving attestation out lets introspection return a clean 200 (implicit
 * signup) rather than a 401 attestation challenge.
 */
async function synthesizedDiscovery(): Promise<DiscoveryDocument> {
  const probe = defineService({
    baseUrl: BASE_URL,
    serviceDid: SERVICE_DID,
    accounts: new MemoryAccountStore(),
    recipients: { email: consoleEmailHandler },
    nonceStore: new MemoryNonceStore(),
    attestation: "off",
  });
  const res = await probe.handleDiscovery(new Request(`${BASE_URL}/.well-known/afauth`));
  return (await res.json()) as DiscoveryDocument;
}

function workerFrom(discovery: DiscoveryDocument) {
  const accounts = new MemoryAccountStore();
  const worker = createWorker({
    baseUrl: BASE_URL,
    serviceDid: SERVICE_DID,
    accounts,
    recipients: { email: consoleEmailHandler },
    nonceStore: new MemoryNonceStore(),
    revocationList: new MemoryRevocationList(),
    discovery,
    extractOwnerSession: async () => null,
  });
  const dispatch = worker.fetch! as (req: Request, env: unknown, ctx: unknown) => Promise<Response>;
  return {
    fetch: (req: Request) => dispatch(req, {} as never, {} as never),
    accounts,
  };
}

function toRequest(signed: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | Uint8Array | null;
}): Request {
  return new Request(signed.url, {
    method: signed.method,
    headers: signed.headers,
    body: (signed.body === null ? undefined : signed.body) as BodyInit | undefined,
  });
}

describe("agent ↔ defineService-default interop (worker routing)", () => {
  it("introspection from a baseUrl-only agent reaches the synthesized-discovery worker", async () => {
    const disc = await synthesizedDiscovery();
    const { fetch, accounts } = workerFrom(disc);
    const agent = await Agent.generate();
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    const res = await fetch(toRequest(signed));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { agent_did: string; state: string };
    expect(body.agent_did).toBe(agent.did);
    expect(await accounts.getByAgentDid(agent.did)).not.toBeNull();
  });

  it("owner-invitation from a baseUrl-only agent reaches the same worker", async () => {
    const disc = await synthesizedDiscovery();
    const { fetch } = workerFrom(disc);
    const agent = await Agent.generate();
    await fetch(toRequest(await agent.buildAccountIntrospection({ baseUrl: BASE_URL })));
    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "alice@example.com" },
    });
    const res = await fetch(toRequest(signed));
    expect(res.status).toBe(202);
    const body = (await res.json()) as { state: string };
    expect(body.state).toBe("INVITED");
  });
});

describe("agent honors advertised discovery endpoints (custom paths)", () => {
  // A service free to mount AFAuth wherever it likes (§4.3). A discovery-
  // aware agent must follow these, not assume the canonical layout.
  const CUSTOM: DiscoveryDocument = {
    afauth_version: "0.1",
    service_did: SERVICE_DID,
    endpoints: {
      accounts: "/api/v2/accounts",
      owner_invitation: "/api/v2/accounts/me/invite-owner",
      claim_page: "/claim",
      claim_completion: "/api/v2/claim",
      key_rotation: "/api/v2/accounts/me/keys/rotate",
    },
    signature_algorithms: ["ed25519"],
    recipient_types: ["email"],
  };

  it("introspection resolves to the advertised accounts path + /me", async () => {
    const { fetch, accounts } = workerFrom(CUSTOM);
    const agent = await Agent.generate();
    const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL, discovery: CUSTOM });
    expect(new URL(signed.url).pathname).toBe("/api/v2/accounts/me");
    const res = await fetch(toRequest(signed));
    expect(res.status).toBe(200);
    expect(await accounts.getByAgentDid(agent.did)).not.toBeNull();
  });

  it("owner-invitation resolves to the advertised owner_invitation path", async () => {
    const { fetch } = workerFrom(CUSTOM);
    const agent = await Agent.generate();
    await fetch(
      toRequest(await agent.buildAccountIntrospection({ baseUrl: BASE_URL, discovery: CUSTOM })),
    );
    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "alice@example.com" },
      discovery: CUSTOM,
    });
    expect(new URL(signed.url).pathname).toBe("/api/v2/accounts/me/invite-owner");
    const res = await fetch(toRequest(signed));
    expect(res.status).toBe(202);
  });

  it("falls back to the canonical §4.1 paths when no discovery is passed", async () => {
    const agent = await Agent.generate();
    const intro = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
    expect(new URL(intro.url).pathname).toBe("/afauth/v1/accounts/me");
    const inv = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "a@example.com" },
    });
    expect(new URL(inv.url).pathname).toBe("/afauth/v1/accounts/me/owner-invitation");
  });
});
