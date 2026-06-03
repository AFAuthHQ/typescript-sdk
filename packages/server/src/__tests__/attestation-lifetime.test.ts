/**
 * §10.3.1 — attestors that bound their token lifetime (afauth-trust pins
 * `exp - iat ≤ 900s`) must reject any token that exceeds the cap, and
 * must require `iat` to be present. A long-lived token from a
 * compromised or misconfigured attestor key would otherwise outlive the
 * §10.7 attested-session revocation window.
 *
 * The cap is per-attestor: the generic HmacAttestor/JwksAttestor leave
 * it unset (§10.2 imposes no generic ceiling), and `trustAttestor()`
 * defaults it to 900s.
 */

import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { HmacAttestor } from "../index.js";

const SECRET = new TextEncoder().encode("this-secret-is-at-least-32-bytes-long-enough-for-hs256");
const AGENT_DID = "did:key:z6MkAgentLifetime";

async function token(opts: { iat?: number; exp: number; omitIat?: boolean }): Promise<string> {
  const b = new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("test-attestor")
    .setSubject(AGENT_DID)
    .setExpirationTime(opts.exp);
  if (!opts.omitIat) b.setIssuedAt(opts.iat ?? Math.floor(Date.now() / 1000));
  return b.sign(SECRET);
}

describe("Attestation lifetime cap (§10.3.1)", () => {
  it("rejects a token whose exp - iat exceeds maxLifetimeSeconds", async () => {
    const now = Math.floor(Date.now() / 1000);
    const att = new HmacAttestor({ iss: "test-attestor", secret: SECRET, maxLifetimeSeconds: 900 });
    const jwt = await token({ iat: now, exp: now + 100_000 }); // ~28h ≫ 900s, but still in the future
    await expect(att.verify(jwt, AGENT_DID)).rejects.toMatchObject({ code: "invalid_attestation" });
  });

  it("rejects a capped attestor's token that omits iat", async () => {
    const now = Math.floor(Date.now() / 1000);
    const att = new HmacAttestor({ iss: "test-attestor", secret: SECRET, maxLifetimeSeconds: 900 });
    const jwt = await token({ exp: now + 300, omitIat: true });
    await expect(att.verify(jwt, AGENT_DID)).rejects.toMatchObject({ code: "invalid_attestation" });
  });

  it("accepts a token within the cap", async () => {
    const now = Math.floor(Date.now() / 1000);
    const att = new HmacAttestor({ iss: "test-attestor", secret: SECRET, maxLifetimeSeconds: 900 });
    const jwt = await token({ iat: now, exp: now + 300 });
    const claims = await att.verify(jwt, AGENT_DID);
    expect(claims.sub).toBe(AGENT_DID);
  });

  it("uncapped attestor (no maxLifetimeSeconds) accepts a long-lived token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const att = new HmacAttestor({ iss: "test-attestor", secret: SECRET });
    const jwt = await token({ iat: now, exp: now + 100_000 });
    const claims = await att.verify(jwt, AGENT_DID);
    expect(claims.sub).toBe(AGENT_DID);
  });
});
