import { describe, expect, it } from "vitest";
import {
  AFAuthError,
  formatChallenge,
  parseChallenge,
  type AFAuthChallenge,
} from "../index";

const DISCOVERY = "https://api.example.com/.well-known/afauth";

describe("formatChallenge (§5.7)", () => {
  it("emits the AFAuth scheme with quoted URL and unquoted token error", () => {
    const h = formatChallenge({ discovery: DISCOVERY, error: "invalid_signature" });
    expect(h).toBe(
      `AFAuth discovery="${DISCOVERY}", error=invalid_signature`,
    );
  });

  it("space-joins and quotes a multi-attestor list", () => {
    const h = formatChallenge({
      discovery: DISCOVERY,
      error: "attestation_required",
      attestors: ["afauth-trust", "microsoft-entra-agent-id"],
    });
    expect(h).toBe(
      `AFAuth discovery="${DISCOVERY}", error=attestation_required, attestors="afauth-trust microsoft-entra-agent-id"`,
    );
  });

  it("quotes a realm that is a service_did (contains ':')", () => {
    const h = formatChallenge({ realm: "did:web:example.com", discovery: DISCOVERY });
    expect(h).toContain(`realm="did:web:example.com"`);
  });

  it("omits attestors when the list is empty", () => {
    const h = formatChallenge({ discovery: DISCOVERY, attestors: [] });
    expect(h).not.toContain("attestors");
  });

  it("emits a bare scheme advertisement when no params are set", () => {
    expect(formatChallenge({})).toBe("AFAuth");
  });
});

describe("parseChallenge (§5.7)", () => {
  it("round-trips a full challenge", () => {
    const c: AFAuthChallenge = {
      discovery: DISCOVERY,
      error: "attestation_required",
      attestors: ["afauth-trust", "microsoft-entra-agent-id"],
      ownerLogin: "https://api.example.com/login",
      realm: "did:web:example.com",
    };
    expect(parseChallenge(formatChallenge(c))).toEqual(c);
  });

  it("returns null when no AFAuth challenge is present", () => {
    expect(parseChallenge('Bearer realm="x", error="invalid_token"')).toBeNull();
    expect(parseChallenge("")).toBeNull();
  });

  it("extracts the AFAuth challenge when it coexists with another scheme", () => {
    const c = parseChallenge(
      `Bearer realm="x", AFAuth discovery="${DISCOVERY}", error=revoked_key`,
    );
    expect(c).toEqual({ discovery: DISCOVERY, error: "revoked_key" });
  });

  it("splits a space-delimited attestors list", () => {
    const c = parseChallenge(
      `AFAuth attestors="afauth-trust google-cloud-agent-identity"`,
    );
    expect(c?.attestors).toEqual(["afauth-trust", "google-cloud-agent-identity"]);
  });

  it("ignores unknown auth-params", () => {
    const c = parseChallenge(`AFAuth discovery="${DISCOVERY}", future_param=xyz`);
    expect(c).toEqual({ discovery: DISCOVERY });
  });

  it("handles escaped characters in quoted values", () => {
    const c = parseChallenge(`AFAuth error="weird \\"quoted\\" value"`);
    expect(c?.error).toBe('weird "quoted" value');
  });

  it("treats a bare AFAuth advertisement as an empty challenge", () => {
    expect(parseChallenge("AFAuth")).toEqual({});
  });
});

describe("AFAuthError.toResponse(extraHeaders)", () => {
  it("merges the WWW-Authenticate challenge onto the 401 envelope", async () => {
    const err = new AFAuthError("attestation_required", 401, "need attestation");
    const challenge = formatChallenge({
      discovery: DISCOVERY,
      error: err.code,
      attestors: ["afauth-trust"],
    });
    const res = err.toResponse({ "WWW-Authenticate": challenge });
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(challenge);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("attestation_required");
  });

  it("still works with no extra headers (back-compat)", () => {
    const res = new AFAuthError("invalid_signature", 401, "bad").toResponse();
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBeNull();
  });
});
