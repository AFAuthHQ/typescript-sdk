/**
 * §4.3 / §4.5 discovery-document validation.
 *
 * fetchDiscovery and assertDiscoveryDocument should:
 *   - require afauth_version === "0.1"
 *   - require service_did, endpoints (with the four mandatory paths),
 *     and signature_algorithms array
 *   - reject documents that don't advertise ed25519 (§4.5)
 *   - preserve unknown fields (§4.2 forward-compat)
 */

import { describe, expect, it } from "vitest";
import { assertDiscoveryDocument } from "../index.js";

const VALID: unknown = {
  afauth_version: "0.1",
  service_did: "did:web:api.example.com",
  endpoints: {
    accounts: "/afauth/v1/accounts",
    owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
    claim_page: "/claim",
    claim_completion: "/afauth/v1/claim",
  },
  signature_algorithms: ["ed25519"],
};

describe("assertDiscoveryDocument", () => {
  it("accepts a minimal valid document", () => {
    expect(() => assertDiscoveryDocument(VALID)).not.toThrow();
  });

  it("rejects null / non-object", () => {
    expect(() => assertDiscoveryDocument(null)).toThrow(/not an object/);
    expect(() => assertDiscoveryDocument("hello")).toThrow(/not an object/);
  });

  it("rejects wrong afauth_version", () => {
    expect(() => assertDiscoveryDocument({ ...(VALID as object), afauth_version: "0.2" })).toThrow(
      /afauth_version/,
    );
  });

  it("rejects missing service_did", () => {
    const { service_did: _omit, ...without } = VALID as Record<string, unknown>;
    expect(() => assertDiscoveryDocument(without)).toThrow(/service_did/);
  });

  it.each([
    "accounts",
    "owner_invitation",
    "claim_page",
    "claim_completion",
  ])("rejects missing endpoints.%s", (k) => {
    const eps = { ...(VALID as { endpoints: Record<string, string> }).endpoints };
    delete eps[k];
    expect(() => assertDiscoveryDocument({ ...(VALID as object), endpoints: eps })).toThrow(
      new RegExp(`endpoints\\.${k}`),
    );
  });

  it("rejects signature_algorithms that does not advertise ed25519 (§4.5)", () => {
    expect(() =>
      assertDiscoveryDocument({ ...(VALID as object), signature_algorithms: ["rsa-sha256"] }),
    ).toThrow(/ed25519/);
  });

  it("preserves unknown forward-compat fields (§4.2)", () => {
    const doc = assertDiscoveryDocument({ ...(VALID as object), future_field: { x: 1 } });
    expect((doc as unknown as { future_field: { x: number } }).future_field).toEqual({ x: 1 });
  });
});
