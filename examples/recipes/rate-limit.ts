/**
 * Recipe: per-route rate limiting (§11.3 `rate_limit_exceeded`).
 *
 * The protocol reserves the `rate_limit_exceeded` (429) code but
 * takes no position on policy. `ServerOptions` accepts an optional
 * `rateLimiter` plus per-route `rateLimits`. Each route's key is the
 * agent DID extracted from `keyid` (except `claim_completion`, which
 * keys by token).
 *
 * `MemoryRateLimiter` is a single-process fixed-window counter
 * suitable for tests and small deployments; for horizontally-scaled
 * deployments use a shared backend like `KvRateLimiter`
 * (in `@afauthhq/worker`).
 *
 * Over-limit calls return `429` with `Retry-After` set to the seconds
 * remaining in the current window.
 */

import {
  consoleEmailHandler,
  MemoryAccountStore,
  MemoryNonceStore,
  MemoryRateLimiter,
  MemoryRevocationList,
  Server,
  type ServerRateLimits,
} from "@afauthhq/server";

const rateLimits: ServerRateLimits = {
  // §6.4/§6.5: cap signup-adjacent writes per agent.
  accounts: { limit: 5, windowSeconds: 60 },
  account_introspection: { limit: 60, windowSeconds: 60 },
  // §7.2: keep an agent from flooding humans with invitation emails.
  owner_invitation: { limit: 3, windowSeconds: 3600 },
  // §7.4: one-shot per token in practice; still gate it to defend
  // against scripted claim probes.
  claim_completion: { limit: 5, windowSeconds: 60 },
  // §8.1/§8.2: rotation is expensive; tight cap is fine.
  key_rotation: { limit: 5, windowSeconds: 3600 },
};

const server = new Server({
  nonceStore: new MemoryNonceStore(),
  revocationList: new MemoryRevocationList(),
  serviceDid: "did:web:api.example.com",
  accounts: new MemoryAccountStore(),
  recipients: { email: consoleEmailHandler },
  baseUrl: "https://api.example.com",
  discovery: {
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
  },
  rateLimiter: new MemoryRateLimiter(),
  rateLimits,
});

export { server };
