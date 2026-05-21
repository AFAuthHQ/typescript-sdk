# AFAuth example Worker

Reference Cloudflare Worker composing `@afauth/server` and `@afauth/worker`.

## What it does today (M0)

- Boots on Cloudflare Workers.
- Returns the `/.well-known/afauth` discovery document with status 200.
- Constructs a `Server` instance to verify type-compatibility with the
  ServerOptions surface defined in `@afauth/server`.
- All five protocol endpoints return 404 (handler wiring lands in M1).

## What it will do next (M1+)

- M1: route the five endpoints through `createWorker(opts)`; the
  `Verifier` accepts the harness's test vectors end-to-end.
- M2: owner-invitation + claim completion; the email
  `RecipientHandler` logs the magic link to `console`.
- M3: pre-claim key rotation, owner-initiated revocation backed by
  a KV revocation list.

## Running locally

```bash
pnpm install
pnpm --filter @afauth/example-worker dev
```

Then `curl http://localhost:8787/.well-known/afauth`.

## Deploying

```bash
pnpm --filter @afauth/example-worker deploy
```

Provision a KV namespace and uncomment the `kv_namespaces` block in
`wrangler.toml` for the production nonce store.
