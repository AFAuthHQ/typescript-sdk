/**
 * Recipe: an anonymous-allowed endpoint (optional auth / progressive
 * enhancement). The endpoint serves everyone, but an AFAuth-authenticated
 * agent gets more.
 *
 * Use `Verifier.verifyOptional` (§5.8): it verifies only when the request
 * actually presents AFAuth credentials. Anonymous callers are served (200, and
 * — because the request was not rejected — no `WWW-Authenticate` challenge);
 * only a *failed* AFAuth attempt is rejected, with a §5.7 challenge.
 *
 * Calling `Verifier.verify` directly would 401 every anonymous caller — the bug
 * this recipe avoids. AFAuth is a secondary/optional scheme here: it never
 * speaks on the anonymous happy path, only when an agent actually tried it.
 *
 * Unlike the other recipes, this one ships with a runnable test
 * (`optional-auth.test.ts`) that exercises all three outcomes end-to-end.
 */

import { AFAuthError } from "@afauthhq/core";
import {
  MemoryNonceStore,
  MemoryRevocationList,
  Verifier,
  formatChallenge,
} from "@afauthhq/server";

const DISCOVERY_URL = "https://api.example.com/.well-known/afauth";

const verifier = new Verifier({
  nonceStore: new MemoryNonceStore(),
  serviceDid: "did:web:api.example.com",
  revocationList: new MemoryRevocationList(),
});

/**
 * `GET /api/data` — anonymous-allowed. Anonymous callers get the public
 * payload; an authenticated agent gets the elevated one.
 */
export async function handleOptionalAuth(req: Request): Promise<Response> {
  let auth: Awaited<ReturnType<typeof verifier.verifyOptional>>;
  try {
    auth = await verifier.verifyOptional({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body ? await req.text() : null,
    });
  } catch (err) {
    // Credentials were presented and FAILED. Reject and tell the agent why via
    // a §5.7 error challenge — don't silently downgrade to anonymous.
    return rejected(err);
  }

  if (auth.authenticated) {
    return json(200, { tier: "authenticated", agent: auth.request.agentDid, items: 1000 });
  }
  // Anonymous: serve the public response. No 401, no challenge.
  return json(200, { tier: "anonymous", items: 10 });
}

/** A failed AFAuth attempt → 401 with a §5.7 error challenge. */
function rejected(err: unknown): Response {
  if (err instanceof AFAuthError) {
    // verifyOptional only throws when AFAuth was attempted, so naming the
    // failure in `error` is correct — this isn't an other-scheme/cold request.
    const challenge = formatChallenge({ discovery: DISCOVERY_URL, error: err.code });
    return json(
      err.status,
      { error: { code: err.code, message: err.message } },
      { "WWW-Authenticate": challenge },
    );
  }
  return json(500, { error: { code: "internal_error", message: "internal error" } });
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}
