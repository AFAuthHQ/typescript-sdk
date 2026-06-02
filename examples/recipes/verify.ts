/**
 * Recipe: standalone request verification.
 *
 * `Verifier` performs §5.5 + §5.6 (signature parsing, key resolution,
 * Ed25519 verify, timestamp + nonce checks). Use it directly when you
 * only need "did this agent really sign this request?" — typically at
 * an edge proxy or service-mesh sidecar that fronts a service backend
 * (Appendix E). The `Server` class wraps a `Verifier` to add endpoint
 * handlers; if you don't need those, `Verifier` is enough.
 *
 * Agent account identifiers are `did:key`, so the Verifier resolves the
 * signing key straight from the DID — no network, no registry, no I/O.
 */

import {
  MemoryNonceStore,
  MemoryRevocationList,
  Verifier,
} from "@afauthhq/server";

const verifier = new Verifier({
  nonceStore: new MemoryNonceStore(),
  serviceDid: "did:web:api.example.com",
  // §8.3: services MUST maintain a revocation list. The `Verifier`
  // defaults to an in-memory list with a one-time warning if omitted;
  // production deployments MUST supply a durable one.
  revocationList: new MemoryRevocationList(),
  // No `didResolver` needed: agent identifiers are did:key, so the
  // default resolver decodes the key straight from the DID.
});

/**
 * Verify a Fetch-style Request and return either the verified identity
 * or a §11.1-shaped error envelope.
 */
export async function handleSignedRequest(req: Request): Promise<Response> {
  try {
    const body = req.body ? await req.text() : null;
    const verified = await verifier.verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body,
    });

    // verified.agentDid is the signed identity. Authorise per your own
    // policy, then forward to the backend.
    return new Response(
      JSON.stringify({ ok: true, agent: verified.agentDid }),
      { headers: { "content-type": "application/json" } },
    );
  } catch (err) {
    return errorResponse(err);
  }
}

/** Render an AFAuthError (or any other error) as a §11.1 envelope. */
function errorResponse(err: unknown): Response {
  if (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    "status" in err &&
    "message" in err
  ) {
    const e = err as { code: string; status: number; message: string };
    return new Response(
      JSON.stringify({ error: { code: e.code, message: e.message } }),
      {
        status: e.status,
        headers: { "content-type": "application/json" },
      },
    );
  }
  return new Response(
    JSON.stringify({ error: { code: "internal_error", message: "internal error" } }),
    { status: 500, headers: { "content-type": "application/json" } },
  );
}
