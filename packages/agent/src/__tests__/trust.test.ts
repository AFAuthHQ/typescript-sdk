import { describe, expect, it } from "vitest";
import { TrustClient, AFAUTH_TRUST_DEFAULT_BASE } from "../trust.js";

/**
 * Mock fetch that records calls and returns scripted responses.
 * Each script entry matches a single call in order.
 */
function mockFetch(
  script: Array<{ path: string; status?: number; body: unknown; assertBody?: (body: unknown) => void }>,
) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let idx = 0;
  const impl = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, init: init ?? {} });
    const step = script[idx++];
    if (!step) throw new Error(`unexpected fetch: ${url}`);
    if (!url.endsWith(step.path)) {
      throw new Error(`fetch ${idx}: want path ${step.path}, got ${url}`);
    }
    if (step.assertBody && init?.body) {
      step.assertBody(JSON.parse(init.body as string));
    }
    return new Response(JSON.stringify(step.body), {
      status: step.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  };
  return { impl: impl as typeof globalThis.fetch, calls };
}

describe("TrustClient", () => {
  it("defaults to trust.afauth.org base URL", () => {
    const c = new TrustClient();
    expect(c.baseUrl).toBe(AFAUTH_TRUST_DEFAULT_BASE);
  });

  it("auto-generates a did:key agent identity", () => {
    const c = new TrustClient();
    expect(c.agentDid).toMatch(/^did:key:z/);
    expect(c.agentPublicKey.length).toBe(32);
  });

  it("linkStart posts agent_did + agent_pubkey_b64 and surfaces the deep link", async () => {
    const { impl, calls } = mockFetch([
      {
        path: "/v1/link/start",
        body: {
          req_id: "req-1",
          link_url: "https://trust.afauth.org/link?req=eyJ…",
          poll_url: "https://trust.afauth.org/v1/link/poll",
          expires_in: 600,
        },
        assertBody: (b) => {
          expect((b as { agent_did: string }).agent_did).toMatch(/^did:key:z/);
          expect(typeof (b as { agent_pubkey_b64: string }).agent_pubkey_b64).toBe("string");
        },
      },
    ]);
    const c = new TrustClient({ fetch: impl });
    const start = await c.linkStart({ label: "test-agent" });
    expect(start.req_id).toBe("req-1");
    expect(start.link_url).toContain("/link?req=");
    expect(calls.length).toBe(1);
  });

  it("linkPoll signs req_id with the agent key and stores the binding on confirm", async () => {
    const { impl } = mockFetch([
      {
        path: "/v1/link/poll",
        body: {
          state: "confirmed",
          binding_id: "bind-1",
          binding_token_expires_at: Math.floor(Date.now() / 1000) + 86400,
        },
        assertBody: (b) => {
          const obj = b as { req_id: string; sig_b64: string };
          expect(obj.req_id).toBe("req-1");
          expect(obj.sig_b64.length).toBeGreaterThan(80); // 64-byte sig base64url ≈ 86 chars
        },
      },
    ]);
    const c = new TrustClient({ fetch: impl });
    const binding = await c.linkPoll("req-1");
    expect(binding?.binding_id).toBe("bind-1");
    expect(c.isLinked()).toBe(true);
    expect(c.getBinding()?.binding_token_expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("linkPoll returns undefined when state=pending", async () => {
    const { impl } = mockFetch([
      { path: "/v1/link/poll", body: { state: "pending" } },
    ]);
    const c = new TrustClient({ fetch: impl });
    const r = await c.linkPoll("req-1");
    expect(r).toBeUndefined();
    expect(c.isLinked()).toBe(false);
  });

  it("token() signs the mint request with the agent key (§3.1, no bearer token) and caches by audience", async () => {
    const expires = Math.floor(Date.now() / 1000) + 900;
    const { impl, calls } = mockFetch([
      {
        path: "/v1/token",
        body: { jwt: "jwt-1", expires_at: expires, verification: "email" },
        assertBody: (b) => expect((b as { aud: string }).aud).toBe("did:web:svc.example"),
      },
    ]);
    const c = new TrustClient({
      fetch: impl,
      binding: {
        binding_id: "bind-1",
        binding_token_expires_at: expires,
      },
    });
    const t1 = await c.token("did:web:svc.example");
    expect(t1.jwt).toBe("jwt-1");
    expect(t1.verification).toBe("email");

    // §3.1: the mint call is §5-signed with the agent key, NOT bearer.
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers.authorization).toBeUndefined();
    expect(headers["signature-input"]).toContain(`keyid="${c.agentDid}"`);
    expect(headers["signature-input"]).toContain('"@method" "@target-uri" "content-digest"');
    expect(headers["signature"]).toMatch(/^sig1=:.+:$/);
    expect(headers["content-digest"]).toMatch(/^sha-256=:.+:$/);

    // Second call for the same audience hits cache (no second fetch).
    const t2 = await c.token("did:web:svc.example");
    expect(t2.jwt).toBe("jwt-1");
    expect(calls.length).toBe(1);
  });

  it("token() refuses when the agent has not linked", async () => {
    const c = new TrustClient();
    await expect(c.token("did:web:svc.example")).rejects.toThrow(/not linked/);
  });
});
