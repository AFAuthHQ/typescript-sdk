# example-cli

A minimal **service-distributed CLI** built on [`@afauthhq/agent`](../../packages/agent) —
the shape a vendor ships so a user's coding agent can sign the user up
*agent-natively* (no email/OTP/browser-OAuth, no bearer secret on the wire),
then optionally hand ownership to a human later.

It's the runnable companion to the [**Ship AFAuth in your CLI**](https://docs.afauth.org/ship-afauth-in-your-cli)
guide.

## Run it

```bash
pnpm --filter @afauthhq/example-cli build

node dist/cli.js whoami                                   # this machine's agent did:key
node dist/cli.js signup https://api.example.com           # provision (self-links if attested_only)
node dist/cli.js claim  https://api.example.com you@example.com   # deferred human ownership
```

## What to copy

- **Shared identity.** `loadOrCreateAgent()` and `loadBinding()` (from
  `@afauthhq/agent/node`) read the shared `~/.afauth/` home, so this CLI reuses
  an identity and human link the user may already have from `afauth init` — the
  human links **once, ever**, across every AFAuth service. Pass an explicit
  path to scope the key to your own tool instead.
- **One-call signup.** `signup()` runs discover → link-if-`attested_only`-and-
  unlinked → attested implicit signup. The only human step is the `onLink`
  callback (and only the first time on an unlinked machine); persist the
  returned `binding` with `saveBinding()` so it's never prompted again.
- **Your data plane stays yours.** This example signs up and stops; a real
  service either keeps making signed requests, or mints its own native key on
  the back of the verified signup. AFAuth gates identity / signup / claim, not
  your API auth.

The on-disk formats are the spec's
[agent-home storage contract](https://github.com/AFAuthHQ/spec/blob/main/spec/storage.md),
so what this CLI writes is exactly what the `afauth` CLI reads, and vice versa.
