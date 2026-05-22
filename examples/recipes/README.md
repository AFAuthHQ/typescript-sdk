# AFAuth SDK Recipes

Five focused examples for surfaces that aren't covered by the full
[`examples/worker`](../worker) reference Worker. Each file is a
self-contained snippet you can lift into your own code, type-checked
against the live SDK.

| File | What it shows |
|---|---|
| [`verify.ts`](./verify.ts) | Standalone `Verifier` — edge-plugin pattern per Appendix E |
| [`rotate.ts`](./rotate.ts) | Pre-claim key rotation via `agent.buildKeyRotation` (§8.1) |
| [`revoke.ts`](./revoke.ts) | Owner-driven revocation via `server.revoke(did)` (§8.4) |
| [`rate-limit.ts`](./rate-limit.ts) | `MemoryRateLimiter` + per-route `ServerRateLimits` (§11.3) |
| [`attestor.ts`](./attestor.ts) | `HmacAttestor` / `JwksAttestor` / `MultiAttestor` (§10) |

These compile under `tsc --noEmit`; they are illustrative, not runnable
end-to-end (each would need a real service, key, or attestor secret to
exercise live).

```bash
pnpm --filter @afauthhq/example-recipes typecheck
```
