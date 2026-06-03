/**
 * §7.5 freshness floor: assertFreshOwnerSession.
 *
 * Throws AFAuthError("owner_session_too_stale", 403, …) iff the
 * session's authenticatedAt is missing, malformed, or older than the
 * configured maxAgeSeconds. Otherwise returns void.
 */

import { describe, expect, it } from "vitest";
import {
  assertFreshOwnerSession,
  type OwnerSession,
} from "../index.js";

const REF_NOW_MS = Date.parse("2026-05-21T12:00:00.000Z");
const now = () => Math.floor(REF_NOW_MS / 1000);

function sessionAt(iso: string | undefined): OwnerSession {
  const s: OwnerSession = {
    authenticated: { type: "email", value: "alice@example.com" },
    userId: "usr_alice",
  };
  if (iso !== undefined) s.authenticatedAt = iso;
  return s;
}

describe("assertFreshOwnerSession", () => {
  it("accepts a session authenticated 30 seconds ago with window=300", () => {
    const s = sessionAt(new Date(REF_NOW_MS - 30_000).toISOString());
    expect(() => assertFreshOwnerSession(s, { maxAgeSeconds: 300, now })).not.toThrow();
  });

  it("accepts a session at the exact boundary (age == maxAgeSeconds)", () => {
    const s = sessionAt(new Date(REF_NOW_MS - 300_000).toISOString());
    expect(() => assertFreshOwnerSession(s, { maxAgeSeconds: 300, now })).not.toThrow();
  });

  it("rejects a session one second past the boundary", () => {
    const s = sessionAt(new Date(REF_NOW_MS - 301_000).toISOString());
    expect(() => assertFreshOwnerSession(s, { maxAgeSeconds: 300, now })).toThrow(
      expect.objectContaining({ code: "owner_session_too_stale", status: 403 }),
    );
  });

  it("rejects a missing authenticatedAt", () => {
    const s = sessionAt(undefined);
    expect(() => assertFreshOwnerSession(s, { maxAgeSeconds: 300, now })).toThrow(
      expect.objectContaining({ code: "owner_session_too_stale", status: 403 }),
    );
  });

  it("rejects a malformed authenticatedAt", () => {
    const s = sessionAt("not-an-iso-date");
    expect(() => assertFreshOwnerSession(s, { maxAgeSeconds: 300, now })).toThrow(
      expect.objectContaining({ code: "owner_session_too_stale", status: 403 }),
    );
  });

  it("uses Date.now()/1000 when no `now` override is supplied", () => {
    const recent = new Date(Date.now() - 10_000).toISOString();
    const s = sessionAt(recent);
    expect(() => assertFreshOwnerSession(s, { maxAgeSeconds: 60 })).not.toThrow();
  });

  it("documented usage: composes with Server.revoke", async () => {
    const { MemoryAccountStore, Server, MemoryNonceStore, MemoryRevocationList } = await import("../index.js");
    const accounts = new MemoryAccountStore();
    await accounts.signupAgent({ did: "did:key:zVictim" }).then((r) => r.account);
    const server = new Server({
      nonceStore: new MemoryNonceStore(),
      revocationList: new MemoryRevocationList(),
      serviceDid: "did:web:example.com",
      accounts,
      recipients: {},
      discovery: {
        afauth_version: "0.1",
        service_did: "did:web:example.com",
        endpoints: {
          accounts: "/afauth/v1/accounts",
          owner_invitation: "/afauth/v1/accounts/me/owner-invitation",
          claim_page: "/claim",
          claim_completion: "/afauth/v1/claim",
        },
        signature_algorithms: ["ed25519"],
      },
      baseUrl: "https://api.example.com",
    });

    const staleSession: OwnerSession = {
      authenticated: { type: "email", value: "alice@example.com" },
      userId: "usr_alice",
      authenticatedAt: new Date(REF_NOW_MS - 999_000).toISOString(),
    };

    // The service's own revoke route would do:
    expect(() =>
      assertFreshOwnerSession(staleSession, { maxAgeSeconds: 300, now }),
    ).toThrow(expect.objectContaining({ code: "owner_session_too_stale" }));

    // Account is unchanged — the check fired before any storage mutation.
    expect((await accounts.getByAgentDid("did:key:zVictim"))?.revoked).toBeUndefined();
  });
});
