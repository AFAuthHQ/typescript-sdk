# AFAuth SDK Recipes

Seven focused examples for surfaces that aren't covered by the full
[`examples/worker`](../worker) reference Worker. Each file is a
self-contained snippet you can lift into your own code, type-checked
against the live SDK.

| File | What it shows |
|---|---|
| [`define-service.ts`](./define-service.ts) | `defineService` — spam-resistant defaults (attestation required, `sub_h`-keyed) and how to opt out |
| [`verify.ts`](./verify.ts) | Standalone `Verifier` — edge-plugin pattern per Appendix E |
| [`optional-auth.ts`](./optional-auth.ts) | Anonymous-allowed endpoint via `Verifier.verifyOptional` (§5.8) — verify only if attempted; §5.7 challenge only on a failed attempt. Runnable: see `optional-auth.test.ts` |
| [`rotate.ts`](./rotate.ts) | Pre-claim key rotation via `agent.buildKeyRotation` (§8.1) |
| [`revoke.ts`](./revoke.ts) | Owner-driven revocation via `server.revoke(did)` (§8.4) |
| [`rate-limit.ts`](./rate-limit.ts) | `MemoryRateLimiter` + per-route `ServerRateLimits` (§11.3) |
| [`attestor.ts`](./attestor.ts) | `HmacAttestor` / `JwksAttestor` / `MultiAttestor` (§10) |

All compile under `tsc --noEmit`. Most are illustrative, not runnable
end-to-end (each would need a real service, key, or attestor secret to
exercise live) — except [`optional-auth.ts`](./optional-auth.ts), which ships
with a co-located test that drives all three outcomes through the live SDK.

```bash
pnpm --filter @afauthhq/example-recipes typecheck
pnpm --filter @afauthhq/example-recipes test   # runs optional-auth.test.ts
```
