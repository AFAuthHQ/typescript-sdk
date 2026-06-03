/**
 * §10.4.4 per-principal uniqueness — "same human, same bucket".
 *
 * `attested_only` (§9.2) only guarantees a signup carries a VALID
 * attestation; on its own it does not stop one human from minting many
 * agent keypairs and opening many free accounts. Every trust attestation
 * for the same human at the same service carries the SAME `sub_h` (§10.4),
 * so a service closes the Sybil hole by keying a uniqueness slot on
 * `(iss, sub_h)` and refusing a second account for a slot already held.
 *
 * `defineService` wires that slot ON by default in `required` mode, so the
 * one-call recipe actually delivers the guarantee its docs advertise.
 *
 * These are the bug-capturing tests: before the SubHUniquenessStore wiring
 * the second signup returned 200 (Sybil hole open). They assert it now
 * returns `409 principal_already_registered`.
 */

import { Agent } from "@afauthhq/agent";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  HmacAttestor,
  MemoryAccountStore,
  MemoryNonceStore,
  MemorySubHUniquenessStore,
  defineService,
  sweepExpiredAccounts,
  type RecipientHandler,
} from "../index.js";

const SERVICE_DID = "did:web:api.example.com";
const BASE_URL = "https://api.example.com";

// Two distinct, well-formed 43-char base64url pseudonyms.
const SUB_H_ALICE = "8f3cZ_K9qWmA-LpQ7tVnRsxBcD2yE0HfJgIuYpXoNkM";
const SUB_H_BOB = "Qm2bX9wL4pR7nK0sT1vU8yA-cE3dF5gH6jI7kZ_oBpN";

const SECRET = new TextEncoder().encode(
  "this-secret-is-at-least-32-bytes-long-enough-for-hs256",
);

const emailHandler: RecipientHandler = {
  async initiate() {
    /* noop */
  },
  matches() {
    return true;
  },
};

/** Mint an HS256 attestation, optionally carrying verification + sub_h. */
async function makeToken(opts: {
  sub: string;
  aud?: string;
  iss?: string;
  subH?: string;
}): Promise<string> {
  const payload: Record<string, unknown> = {};
  if (opts.subH !== undefined) {
    payload.verification = "oauth";
    payload.sub_h = opts.subH;
  }
  const builder = new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(opts.iss ?? "test-attestor")
    .setSubject(opts.sub)
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .setExpirationTime(Math.floor(Date.now() / 1000) + 60);
  if (opts.aud) builder.setAudience(opts.aud);
  return builder.sign(SECRET);
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
      // Override the default trustAttestor() so tests don't hit the network.
      attestor: new HmacAttestor({ iss: "test-attestor", secret: SECRET }),
    }),
  };
}

/** Signed introspection with an attestation header attached. */
async function signupWith(server: ReturnType<typeof newService>["server"], agent: Agent, jwt: string) {
  const signed = await agent.buildAccountIntrospection({ baseUrl: BASE_URL });
  const headers = new Headers(signed.headers);
  headers.set("afauth-attestation", jwt);
  return server
    .handleAccountIntrospection(new Request(signed.url, { method: signed.method, headers }))
    .catch((e) => (e as { toResponse: () => Response }).toResponse());
}

describe("§10.4.4 per-principal uniqueness via defineService (default-on)", () => {
  it("rejects a SECOND agent DID carrying the same (iss, sub_h) with 409 principal_already_registered", async () => {
    const { server } = newService();

    const alice1 = await Agent.generate();
    const r1 = await signupWith(server, alice1, await makeToken({ sub: alice1.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    expect(r1.status).toBe(200);

    // Same human (same sub_h), a brand-new throwaway agent keypair.
    const alice2 = await Agent.generate();
    const r2 = await signupWith(server, alice2, await makeToken({ sub: alice2.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    expect(r2.status).toBe(409);
    const body = (await r2.json()) as { error: { code: string } };
    expect(body.error.code).toBe("principal_already_registered");
  });

  it("allows two DIFFERENT principals (distinct sub_h) to each sign up", async () => {
    const { server } = newService();

    const alice = await Agent.generate();
    const bob = await Agent.generate();
    const ra = await signupWith(server, alice, await makeToken({ sub: alice.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    const rb = await signupWith(server, bob, await makeToken({ sub: bob.did, aud: SERVICE_DID, subH: SUB_H_BOB }));
    expect(ra.status).toBe(200);
    expect(rb.status).toBe(200);
  });

  it("does NOT dedupe runtime-only attestations (no sub_h, no principal asserted)", async () => {
    const { server } = newService();

    const a1 = await Agent.generate();
    const a2 = await Agent.generate();
    // No subH → runtime-only; nothing to key "same human" on.
    const r1 = await signupWith(server, a1, await makeToken({ sub: a1.did, aud: SERVICE_DID }));
    const r2 = await signupWith(server, a2, await makeToken({ sub: a2.did, aud: SERVICE_DID }));
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
  });

  it("is idempotent for the SAME agent DID re-presenting its attestation", async () => {
    const { server } = newService();
    const alice = await Agent.generate();
    const r1 = await signupWith(server, alice, await makeToken({ sub: alice.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    const r2 = await signupWith(server, alice, await makeToken({ sub: alice.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
  });
});

describe("§10.4.4 bypass closed — owner-invitation is gated too", () => {
  // Build a signed owner-invitation Request with an attestation header.
  async function inviteWith(server: ReturnType<typeof newService>["server"], agent: Agent, jwt: string) {
    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "owner@example.com" },
    });
    const headers = new Headers(signed.headers);
    headers.set("afauth-attestation", jwt);
    return server
      .handleOwnerInvitation(new Request(signed.url, { method: signed.method, headers, body: signed.body as BodyInit }))
      .catch((e) => (e as { toResponse: () => Response }).toResponse());
  }

  it("a second principal cannot create an account by inviting first (regression: owner-invitation used to skip the gate)", async () => {
    const { server } = newService();

    // First principal takes the slot via introspection.
    const alice1 = await Agent.generate();
    const r1 = await signupWith(server, alice1, await makeToken({ sub: alice1.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    expect(r1.status).toBe(200);

    // Same human, new keypair, comes in through owner-invitation instead.
    const alice2 = await Agent.generate();
    const r2 = await inviteWith(server, alice2, await makeToken({ sub: alice2.did, aud: SERVICE_DID, subH: SUB_H_ALICE }));
    expect(r2.status).toBe(409);
    const body = (await r2.json()) as { error: { code: string } };
    expect(body.error.code).toBe("principal_already_registered");
  });

  it("owner-invitation against attested_only with NO attestation → 401 attestation_required (was previously allowed)", async () => {
    const { server } = newService();
    const agent = await Agent.generate();
    const signed = await agent.buildOwnerInvitation({
      baseUrl: BASE_URL,
      recipient: { type: "email", value: "owner@example.com" },
    });
    const resp = await server
      .handleOwnerInvitation(new Request(signed.url, { method: signed.method, headers: new Headers(signed.headers), body: signed.body as BodyInit }))
      .catch((e) => (e as { toResponse: () => Response }).toResponse());
    expect(resp.status).toBe(401);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe("attestation_required");
  });
});

describe("§10.4.4 slot lifecycle — release on expire, follow on rotation", () => {
  async function rotate(server: ReturnType<typeof newService>["server"], from: Agent, to: Agent) {
    const signed = await from.buildKeyRotation({ baseUrl: BASE_URL, newDid: to.did });
    return server.handleKeyRotation(
      new Request(signed.url, { method: signed.method, headers: new Headers(signed.headers), body: signed.body as BodyInit }),
    );
  }

  it("frees the slot when the unclaimed account expires, letting the human sign up again", async () => {
    const accounts = new MemoryAccountStore();
    const { server } = newService(accounts);

    const alice1 = await Agent.generate();
    expect((await signupWith(server, alice1, await makeToken({ sub: alice1.did, aud: SERVICE_DID, subH: SUB_H_ALICE }))).status).toBe(200);

    // Sweep the now-expired account, passing the server's uniqueness store
    // so the slot is released alongside the EXPIRED transition.
    const future = () => new Date(Date.now() + 10_000);
    const result = await sweepExpiredAccounts(accounts, {
      unclaimedTtlSeconds: 1,
      now: future,
      subHUniqueness: server.subHUniquenessStore,
    });
    expect(result.expired).toContain(alice1.did);

    // Same human, fresh keypair — slot is free again.
    const alice2 = await Agent.generate();
    expect((await signupWith(server, alice2, await makeToken({ sub: alice2.did, aud: SERVICE_DID, subH: SUB_H_ALICE }))).status).toBe(200);
  });

  it("follows a key rotation: the slot moves to the new DID (still blocks duplicates, releases under the new DID)", async () => {
    const accounts = new MemoryAccountStore();
    const { server } = newService(accounts);

    // alice signs up, then rotates her (pre-claim) key.
    const aliceOld = await Agent.generate();
    expect((await signupWith(server, aliceOld, await makeToken({ sub: aliceOld.did, aud: SERVICE_DID, subH: SUB_H_ALICE }))).status).toBe(200);
    const aliceNew = await Agent.generate();
    expect((await rotate(server, aliceOld, aliceNew)).status).toBe(200);

    // A third keypair for the same human is still blocked — slot held (now by aliceNew).
    const aliceThird = await Agent.generate();
    expect((await signupWith(server, aliceThird, await makeToken({ sub: aliceThird.did, aud: SERVICE_DID, subH: SUB_H_ALICE }))).status).toBe(409);

    // Expiring the ROTATED account releases the slot — only works if rekey
    // moved the slot from aliceOld to aliceNew.
    const future = () => new Date(Date.now() + 10_000);
    await sweepExpiredAccounts(accounts, { unclaimedTtlSeconds: 1, now: future, subHUniqueness: server.subHUniquenessStore });

    const aliceFourth = await Agent.generate();
    expect((await signupWith(server, aliceFourth, await makeToken({ sub: aliceFourth.did, aud: SERVICE_DID, subH: SUB_H_ALICE }))).status).toBe(200);
  });
});

describe("MemorySubHUniquenessStore (unit)", () => {
  const A = "did:key:zAlice";
  const B = "did:key:zBob";
  const C = "did:key:zCarol";

  it("claim: first wins, different DID conflicts, same DID idempotent", async () => {
    const s = new MemorySubHUniquenessStore();
    expect(await s.claim("iss", "subH", A)).toEqual({ ok: true });
    expect(await s.claim("iss", "subH", A)).toEqual({ ok: true }); // idempotent
    expect(await s.claim("iss", "subH", B)).toEqual({ ok: false, existingDid: A });
  });

  it("claim is scoped by (iss, sub_h): same sub_h under a different iss is a different slot", async () => {
    const s = new MemorySubHUniquenessStore();
    expect(await s.claim("iss-1", "subH", A)).toEqual({ ok: true });
    expect(await s.claim("iss-2", "subH", B)).toEqual({ ok: true });
  });

  it("rekey moves the slot to the new DID", async () => {
    const s = new MemorySubHUniquenessStore();
    await s.claim("iss", "subH", A);
    await s.rekey(A, B);
    expect(await s.claim("iss", "subH", C)).toEqual({ ok: false, existingDid: B }); // held by B now
    expect(await s.claim("iss", "subH", B)).toEqual({ ok: true }); // B owns it
  });

  it("releaseByDid frees the slot; a concurrent re-claim by another DID is not clobbered", async () => {
    const s = new MemorySubHUniquenessStore();
    await s.claim("iss", "subH", A);
    await s.releaseByDid(A);
    expect(await s.claim("iss", "subH", B)).toEqual({ ok: true }); // free again
    // A releasing again is a no-op and must not evict B's fresh claim.
    await s.releaseByDid(A);
    expect(await s.claim("iss", "subH", C)).toEqual({ ok: false, existingDid: B });
  });
});
