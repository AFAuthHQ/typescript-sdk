# AFAuth example Worker

Reference Cloudflare Worker composing `@afauthhq/server` and
`@afauthhq/worker` into a deployable AFAuth-protected service.

## What it does

- Serves the `/.well-known/afauth` discovery document (§4).
- Verifies agent-signed requests on the four signed endpoints
  (§5.5 + §5.6), including replay protection and revocation
  lookups.
- Runs the owner-invitation ceremony (§7.2): logs the magic link to
  the Worker's console (visible in `wrangler tail`) via the
  reference `consoleEmailHandler`.
- Accepts claim completions at `POST /afauth/v1/claim/<token>` after
  validating the §7.7 match relation against the supplied owner
  session.
- Implements pre-claim key rotation (§8.1) and §8.4 revocation.
- Returns the agent's account record on
  `GET /afauth/v1/accounts/me`, omitting `pendingRecipient`.

## Configuration knobs (env)

| Var | Required | Default |
|---|---|---|
| `SERVICE_DID` | no | `did:web:example.com` |
| `BASE_URL` | no | `https://example.com` |
| `AFAUTH_NONCES` (KV namespace) | no — falls back to `MemoryNonceStore` | — |
| `AFAUTH_REVOCATIONS` (KV namespace) | no — falls back to `MemoryRevocationList` | — |

> **SECURITY: DEMO ONLY.** The example uses an `X-Owner-Session`
> header to carry the claim-page session, which is trivially
> forgeable by anyone who can reach the Worker. A real deployment
> MUST replace `extractOwnerSession` with one that verifies a
> proper authenticated session (signed cookie, IdP-issued JWT,
> etc.). The header form exists only to make the ceremony
> demonstrable locally.

## Running locally

```bash
pnpm install
pnpm --filter @afauthhq/example-worker dev
```

Then exercise the discovery endpoint:

```bash
curl http://localhost:8787/.well-known/afauth
```

To drive a full invitation → claim ceremony locally, use the
`@afauthhq/agent` package to sign the requests; the email handler
will log the magic link to the Worker's stderr (`wrangler tail`).

## Deploying

```bash
# Provision durable storage:
wrangler kv namespace create AFAUTH_NONCES
wrangler kv namespace create AFAUTH_REVOCATIONS

# Paste the returned namespace IDs into wrangler.toml, then:
pnpm --filter @afauthhq/example-worker deploy
```

The default `MemoryAccountStore` is process-local and is suitable
only for development; production deployments should substitute a
durable `AccountStore` implementation (e.g. backed by D1 or
Durable Objects) that upholds the §7.3 atomic-supersession contract.
