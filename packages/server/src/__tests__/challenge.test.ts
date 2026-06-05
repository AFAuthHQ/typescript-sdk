/**
 * Server.challengeFor (§5.7) — builds the WWW-Authenticate: AFAuth challenge
 * for a thrown error. Verified by round-tripping through parseChallenge.
 */
import { describe, expect, it } from "vitest";
import { AFAuthError } from "@afauthhq/core";
import {
  AFAUTH_TRUST_ISS,
  MemoryAccountStore,
  MemoryNonceStore,
  afauthAttempted,
  defineService,
  parseChallenge,
  type RecipientHandler,
} from "../index.js";

const SERVICE_DID = "did:web:api.example.com";
const BASE_URL = "https://api.example.com";
const emailHandler: RecipientHandler = {
  async initiate() {
    /* noop */
  },
  matches() {
    return true;
  },
};

// Default `attestation: 'required'` ⇒ attested_only + accepted_attestors: ['afauth-trust'].
function buildServer() {
  return defineService({
    baseUrl: BASE_URL,
    serviceDid: SERVICE_DID,
    accounts: new MemoryAccountStore(),
    recipients: { email: emailHandler },
    nonceStore: new MemoryNonceStore(),
  });
}

describe("Server.challengeFor (§5.7)", () => {
  it("returns undefined for a non-401 AFAuthError", async () => {
    expect(
      await buildServer().challengeFor(new AFAuthError("malformed_request", 400, "x")),
    ).toBeUndefined();
  });

  it("returns undefined for a non-AFAuthError", async () => {
    expect(await buildServer().challengeFor(new Error("boom"))).toBeUndefined();
  });

  it("emits discovery + error for a signature failure, without attestors", async () => {
    const header = await buildServer().challengeFor(
      new AFAuthError("invalid_signature", 401, "bad sig"),
    );
    const c = parseChallenge(header!);
    expect(c?.discovery).toBe(`${BASE_URL}/.well-known/afauth`);
    expect(c?.error).toBe("invalid_signature");
    expect(c?.attestors).toBeUndefined();
  });

  it("adds accepted attestors for attestation_required", async () => {
    const header = await buildServer().challengeFor(
      new AFAuthError("attestation_required", 401, "need attestation"),
    );
    const c = parseChallenge(header!);
    expect(c?.error).toBe("attestation_required");
    expect(c?.attestors).toEqual([AFAUTH_TRUST_ISS]);
  });

  it("adds accepted attestors for invalid_attestation", async () => {
    const header = await buildServer().challengeFor(
      new AFAuthError("invalid_attestation", 401, "bad attestation"),
    );
    expect(parseChallenge(header!)?.attestors).toEqual([AFAUTH_TRUST_ISS]);
  });

  it("adds owner_login for owner_authentication_required", async () => {
    const header = await buildServer().challengeFor(
      new AFAuthError("owner_authentication_required", 401, "need owner"),
    );
    const c = parseChallenge(header!);
    expect(c?.error).toBe("owner_authentication_required");
    expect(c?.ownerLogin).toBeTruthy();
  });

  it("omits error (bare advertisement) for invalid_signature when the request didn't attempt AFAuth", async () => {
    const req = new Request("https://api.example.com/afauth/v1/accounts/me"); // no AFAuth headers
    const header = await buildServer().challengeFor(
      new AFAuthError("invalid_signature", 401, "no sig"),
      req,
    );
    const c = parseChallenge(header!);
    expect(c?.discovery).toBe(`${BASE_URL}/.well-known/afauth`);
    expect(c?.error).toBeUndefined();
  });

  it("sets error=invalid_signature when the request carried a Signature-Input", async () => {
    const req = new Request("https://api.example.com/x", {
      headers: { "signature-input": "garbage" },
    });
    const header = await buildServer().challengeFor(
      new AFAuthError("invalid_signature", 401, "bad sig"),
      req,
    );
    expect(parseChallenge(header!)?.error).toBe("invalid_signature");
  });

  it("keeps error for non-signature codes even without an AFAuth attempt", async () => {
    const req = new Request("https://api.example.com/x"); // no AFAuth headers
    const header = await buildServer().challengeFor(
      new AFAuthError("attestation_required", 401, "need attestation"),
      req,
    );
    const c = parseChallenge(header!);
    expect(c?.error).toBe("attestation_required");
    expect(c?.attestors).toEqual([AFAUTH_TRUST_ISS]);
  });
});

describe("afauthAttempted", () => {
  it("is false without AFAuth headers", () => {
    expect(afauthAttempted(new Request("https://x/"))).toBe(false);
  });
  it("is true with a Signature-Input header", () => {
    expect(
      afauthAttempted(new Request("https://x/", { headers: { "signature-input": "sig1=()" } })),
    ).toBe(true);
  });
  it("is true with an AFAuth-Attestation header", () => {
    expect(
      afauthAttempted(new Request("https://x/", { headers: { "afauth-attestation": "jwt" } })),
    ).toBe(true);
  });
});
