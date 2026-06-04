/**
 * §10.7 agent refresh-on-challenge loop (AttestedFetcher).
 *
 * Covers:
 *   - reactive: a 401 attestation_required triggers a mint + a single
 *     retry that carries the attestation; the retry is re-signed (fresh
 *     nonce) so the §5.6 replay set accepts it.
 *   - proactive: the attestation rides the first attempt (no 401).
 *   - a 401 with a different code is returned to the caller, no retry.
 *   - a clean 200 passes through with no mint.
 *   - a revoked binding surfaces as a terminal TrustHttpError, not a loop.
 *   - the constructor rejects an agent/trust key mismatch.
 */

import { describe, expect, it } from "vitest";
import { Agent } from "../index.js";
import { AttestedFetcher } from "../attested-fetch.js";
import { TrustClient, TrustHttpError, AttestorNotAcceptedError } from "../trust.js";

const SERVICE_DID = "did:web:svc.example";
const SERVICE_URL = "https://svc.example/api/thing";

/** A trust-attestor fetch that mints unique tokens for POST /v1/token (or scripts a failure). */
function trustFetch(opts: { fail?: { status: number; code: string } } = {}) {
  let mints = 0;
  const impl = (async (url: string | URL | Request) => {
    if (String(url).endsWith("/v1/token")) {
      if (opts.fail) {
        return new Response(JSON.stringify({ error: { code: opts.fail.code } }), {
          status: opts.fail.status,
          headers: { "content-type": "application/json" },
        });
      }
      mints += 1;
      return new Response(
        JSON.stringify({ jwt: `att-${mints}`, expires_at: Math.floor(Date.now() / 1000) + 900, verification: "oauth" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`unexpected trust path: ${String(url)}`);
  }) as unknown as typeof globalThis.fetch;
  return { impl, mints: () => mints };
}

/** A service fetch that records each call's attestation header + signature nonce. */
function serviceFetch(handler: (call: { attestation: string | null; n: number }) => Response) {
  const calls: { attestation: string | null; nonce: string | undefined }[] = [];
  const impl = (async (url: string | URL | Request, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const sigInput = headers.get("signature-input") ?? "";
    calls.push({
      attestation: headers.get("afauth-attestation"),
      nonce: sigInput.match(/nonce="([^"]+)"/)?.[1],
    });
    return handler({ attestation: headers.get("afauth-attestation"), n: calls.length });
  }) as unknown as typeof globalThis.fetch;
  return { impl, calls };
}

async function setup(trustOpts: { fail?: { status: number; code: string } } = {}) {
  const agent = await Agent.generate();
  const tf = trustFetch(trustOpts);
  const trust = new TrustClient({
    agentDid: agent.did,
    agentPublicKey: agent.publicKey,
    agentPrivateKey: agent.exportPrivateKey(),
    binding: {
      binding_id: "bind-1",
      binding_token_expires_at: Math.floor(Date.now() / 1000) + 100_000,
    },
    fetch: tf.impl,
  });
  return { agent, trust, mints: tf.mints };
}

/** A syntactically valid JWT carrying `iss` (signature is a placeholder). */
function jwtWithIss(iss: string): string {
  const b64url = (o: unknown) =>
    btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${b64url({ alg: "EdDSA", typ: "JWT" })}.${b64url({ iss, aud: SERVICE_DID, exp: 9_999_999_999 })}.sig`;
}

/** A trust-attestor fetch that mints a token whose JWT carries `iss`. */
function trustFetchIss(iss: string) {
  return (async (url: string | URL | Request) => {
    if (String(url).endsWith("/v1/token")) {
      return new Response(
        JSON.stringify({ jwt: jwtWithIss(iss), expires_at: Math.floor(Date.now() / 1000) + 900, verification: "oauth" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`unexpected trust path: ${String(url)}`);
  }) as unknown as typeof globalThis.fetch;
}

async function setupIss(iss: string) {
  const agent = await Agent.generate();
  const trust = new TrustClient({
    agentDid: agent.did,
    agentPublicKey: agent.publicKey,
    agentPrivateKey: agent.exportPrivateKey(),
    binding: { binding_id: "bind-1", binding_token_expires_at: Math.floor(Date.now() / 1000) + 100_000 },
    fetch: trustFetchIss(iss),
  });
  return { agent, trust };
}

const challenge401 = () =>
  new Response(JSON.stringify({ error: { code: "attestation_required" } }), {
    status: 401,
    headers: { "content-type": "application/json" },
  });

describe("AttestedFetcher (§10.7 refresh-on-challenge)", () => {
  it("reactive: challenge → mint → retry once with a fresh attestation and a fresh signature", async () => {
    const { agent, trust, mints } = await setup();
    const svc = serviceFetch(({ attestation }) =>
      attestation ? new Response("ok", { status: 200 }) : challenge401(),
    );
    const fetcher = new AttestedFetcher({ agent, trust, serviceDid: SERVICE_DID, fetch: svc.impl });

    const res = await fetcher.fetch({ method: "GET", url: SERVICE_URL });

    expect(res.status).toBe(200);
    expect(svc.calls).toHaveLength(2);
    expect(svc.calls[0]!.attestation).toBeNull(); // reactive: no attestation on the first try
    expect(svc.calls[1]!.attestation).toBe("att-1"); // freshly minted, attached on retry
    expect(mints()).toBe(1);
    // Re-signed: the retry carries a different nonce, so it isn't a replay.
    expect(svc.calls[0]!.nonce).toBeTruthy();
    expect(svc.calls[1]!.nonce).toBeTruthy();
    expect(svc.calls[0]!.nonce).not.toBe(svc.calls[1]!.nonce);
  });

  it("proactive: the attestation rides the first attempt, so there is no challenge", async () => {
    const { agent, trust, mints } = await setup();
    const svc = serviceFetch(({ attestation }) =>
      attestation ? new Response("ok", { status: 200 }) : challenge401(),
    );
    const fetcher = new AttestedFetcher({ agent, trust, serviceDid: SERVICE_DID, fetch: svc.impl, proactive: true });

    const res = await fetcher.fetch({ method: "GET", url: SERVICE_URL });

    expect(res.status).toBe(200);
    expect(svc.calls).toHaveLength(1);
    expect(svc.calls[0]!.attestation).toBe("att-1");
    expect(mints()).toBe(1);
  });

  it("a 401 with a different error code is returned unchanged (no mint, no retry)", async () => {
    const { agent, trust, mints } = await setup();
    const svc = serviceFetch(() =>
      new Response(JSON.stringify({ error: { code: "revoked_key" } }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    );
    const fetcher = new AttestedFetcher({ agent, trust, serviceDid: SERVICE_DID, fetch: svc.impl });

    const res = await fetcher.fetch({ method: "GET", url: SERVICE_URL });

    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("revoked_key");
    expect(svc.calls).toHaveLength(1);
    expect(mints()).toBe(0);
  });

  it("a clean 200 passes through with no attestation and no mint", async () => {
    const { agent, trust, mints } = await setup();
    const svc = serviceFetch(() => new Response("ok", { status: 200 }));
    const fetcher = new AttestedFetcher({ agent, trust, serviceDid: SERVICE_DID, fetch: svc.impl });

    const res = await fetcher.fetch({ method: "GET", url: SERVICE_URL });

    expect(res.status).toBe(200);
    expect(svc.calls).toHaveLength(1);
    expect(svc.calls[0]!.attestation).toBeNull();
    expect(mints()).toBe(0);
  });

  it("a revoked binding surfaces as a terminal TrustHttpError, not an unbounded retry", async () => {
    const { agent, trust } = await setup({ fail: { status: 403, code: "binding_revoked" } });
    const svc = serviceFetch(() => challenge401());
    const fetcher = new AttestedFetcher({ agent, trust, serviceDid: SERVICE_DID, fetch: svc.impl });

    await expect(fetcher.fetch({ method: "GET", url: SERVICE_URL })).rejects.toBeInstanceOf(TrustHttpError);
    try {
      await fetcher.fetch({ method: "GET", url: SERVICE_URL });
    } catch (e) {
      expect(e).toBeInstanceOf(TrustHttpError);
      expect((e as TrustHttpError).isBindingRevoked()).toBe(true);
    }
    // The service was challenged but never retried-with-attestation (mint failed).
    expect(svc.calls.every((c) => c.attestation === null)).toBe(true);
  });

  it("constructor rejects an agent/trust key mismatch", async () => {
    const { trust } = await setup();
    const otherAgent = await Agent.generate();
    expect(
      () => new AttestedFetcher({ agent: otherAgent, trust, serviceDid: SERVICE_DID, fetch: trustFetch().impl }),
    ).toThrow(/same key/);
  });
});

describe("AttestedFetcher attestor reconciliation (§4.4 accepted_attestors)", () => {
  it("proactive: an accepted attestor is sent normally", async () => {
    const { agent, trust } = await setupIss("afauth-trust");
    const svc = serviceFetch(({ attestation }) => (attestation ? new Response("ok", { status: 200 }) : challenge401()));
    const fetcher = new AttestedFetcher({
      agent,
      trust,
      serviceDid: SERVICE_DID,
      fetch: svc.impl,
      proactive: true,
      acceptedAttestors: ["afauth-trust", "acme-trust"],
    });

    const res = await fetcher.fetch({ method: "GET", url: SERVICE_URL });

    expect(res.status).toBe(200);
    expect(svc.calls).toHaveLength(1);
    expect(svc.calls[0]!.attestation).toBe(jwtWithIss("afauth-trust"));
  });

  it("proactive: an unaccepted attestor throws AttestorNotAcceptedError BEFORE any request is sent", async () => {
    const { agent, trust } = await setupIss("afauth-trust");
    const svc = serviceFetch(() => new Response("ok", { status: 200 }));
    const fetcher = new AttestedFetcher({
      agent,
      trust,
      serviceDid: SERVICE_DID,
      fetch: svc.impl,
      proactive: true,
      acceptedAttestors: ["acme-trust"],
    });

    await expect(fetcher.fetch({ method: "GET", url: SERVICE_URL })).rejects.toBeInstanceOf(AttestorNotAcceptedError);
    expect(svc.calls).toHaveLength(0); // never sent
  });

  it("reactive: an unaccepted attestor throws on the §10.7 retry; the doomed attested request is never sent", async () => {
    const { agent, trust } = await setupIss("afauth-trust");
    const svc = serviceFetch(({ attestation }) => (attestation ? new Response("ok", { status: 200 }) : challenge401()));
    const fetcher = new AttestedFetcher({
      agent,
      trust,
      serviceDid: SERVICE_DID,
      fetch: svc.impl,
      acceptedAttestors: ["acme-trust"],
    });

    await expect(fetcher.fetch({ method: "GET", url: SERVICE_URL })).rejects.toBeInstanceOf(AttestorNotAcceptedError);
    // Only the initial unattested probe went out; the attested retry was withheld.
    expect(svc.calls).toHaveLength(1);
    expect(svc.calls.every((c) => c.attestation === null)).toBe(true);
  });

  it("without acceptedAttestors the minted token is sent regardless of issuer (unchanged behavior)", async () => {
    const { agent, trust } = await setupIss("some-random-attestor");
    const svc = serviceFetch(({ attestation }) => (attestation ? new Response("ok", { status: 200 }) : challenge401()));
    const fetcher = new AttestedFetcher({ agent, trust, serviceDid: SERVICE_DID, fetch: svc.impl, proactive: true });

    const res = await fetcher.fetch({ method: "GET", url: SERVICE_URL });

    expect(res.status).toBe(200);
    expect(svc.calls[0]!.attestation).toBe(jwtWithIss("some-random-attestor"));
  });
});
