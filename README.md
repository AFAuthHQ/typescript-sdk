# AFAuth — TypeScript

> Reference TypeScript SDK for the [AFAuth Protocol](https://github.com/AFAuthHQ/spec).

This monorepo contains the official TypeScript packages that implement AFAuth:

| Package | What it does |
|---|---|
| [`@afauth/agent`](packages/agent) | Keypair generation, did:key derivation, signed `fetch` — for agents that talk to AFAuth-enabled services |
| [`@afauth/server`](packages/server) | Express/Hono/etc. middleware that verifies signatures, manages account state, drives the claim flow |

## Status

**v0.0.1 — Pre-alpha.** Scaffolding only; not yet functional.

## Install

```bash
npm install @afauth/server      # for service developers
npm install @afauth/agent       # for agent developers
```

## Quickstart — service

```ts
import { AFAuth } from "@afauth/server";

const afauth = new AFAuth({ apiKey: process.env.AFAUTH_KEY });
app.use(afauth.middleware());

app.get("/api/whatever", (req, res) => {
  // req.account.id        → "did:key:z6Mk…"
  // req.account.isClaimed
  // req.account.owner
});
```

## Quickstart — agent

```ts
import { AgentIdentity } from "@afauth/agent";

const me = AgentIdentity.load("./key.json") ?? AgentIdentity.generate();
me.save("./key.json");

const res = await me.fetch("https://api.example.com/things");
```

## Develop

```bash
pnpm install
pnpm build
pnpm test
```

## License

[MIT](LICENSE)
