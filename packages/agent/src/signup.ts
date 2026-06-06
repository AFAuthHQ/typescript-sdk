/**
 * High-level signup orchestration — the runtime-agnostic core of what the
 * `afauth signup` CLI command does, in one call.
 *
 * Fetches discovery, and when the service is `attested_only` (§9.2) links to a
 * human if not already linked (surfacing the link URL via `onLink` and polling
 * to completion) before sending the implicit-signup signed request with an
 * auto-minted attestation. Returns the binding it used so a Node caller can
 * persist it (see `@afauthhq/agent/node`'s `saveBinding`).
 *
 * No `node:*` imports — usable on any Web-standard runtime. Persistence and
 * the shared agent home live in the `/node` entry.
 */

import { TrustClient, type TrustBinding, type TrustLinkStart } from "./trust.js";
import { AttestedFetcher } from "./attested-fetch.js";
import { fetchDiscovery, type Agent, type DiscoveryDocument } from "./index.js";

export interface SignupOptions {
  /** The agent whose key signs the signup request. */
  agent: Agent;
  /** The service base URL (its `/.well-known/afauth` is fetched from here). */
  baseUrl: string;
  /**
   * Called when a human must approve a trust link (the one human-in-the-loop
   * step). Receives the link URL to show/open; signup then polls until the
   * human confirms. Keep it UI-agnostic — a CLI prints, a GUI opens a browser.
   * Not called when the agent is already linked or the service isn't
   * `attested_only`.
   */
  onLink?: (linkUrl: string, info: TrustLinkStart) => void | Promise<void>;
  /** A persisted binding from a previous run (e.g. from `loadBinding`). */
  binding?: TrustBinding;
  /** Bring your own TrustClient (e.g. pointed at a self-hosted attestor). */
  trust?: TrustClient;
  /** Override the trust attestor base URL (when not passing `trust`). */
  trustBaseUrl?: string;
  /** The service's `billing.accepted_attestors`; defaults to the discovery value. */
  acceptedAttestors?: readonly string[];
  /** `fetch` override (tests / custom transports). */
  fetch?: typeof globalThis.fetch;
  /** Poll interval while waiting for the human to confirm the link (default 2000ms). */
  pollIntervalMs?: number;
  /** Human-readable label for the link (shown on the attestor's confirm page). */
  label?: string;
  /** Clock override (tests). */
  now?: () => number;
}

export interface SignupResult {
  /** The validated discovery document. */
  discovery: DiscoveryDocument;
  /** The service's account-introspection response body (parsed JSON, or null). */
  account: unknown;
  /** The HTTP status of the signup request. */
  status: number;
  /** The TrustClient used, when the service was `attested_only`. */
  trust?: TrustClient;
  /** The binding used or established — persist it so the human links only once. */
  binding?: TrustBinding;
}

function billingOf(disc: DiscoveryDocument): {
  unclaimed_mode?: string;
  accepted_attestors?: string[];
} {
  return (
    ((disc as unknown as Record<string, unknown>)["billing"] as
      | { unclaimed_mode?: string; accepted_attestors?: string[] }
      | undefined) ?? {}
  );
}

async function readJson(res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

export async function signup(opts: SignupOptions): Promise<SignupResult> {
  const fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const now = opts.now ?? (() => Date.now());
  const disc = await fetchDiscovery(opts.baseUrl, opts.fetch ? { fetch: opts.fetch } : {});
  const billing = billingOf(disc);
  const attestedOnly = billing.unclaimed_mode === "attested_only";

  // The implicit-signup request: a signed GET of `<accounts>/me` (§6.5). The
  // first such request from an unknown DID provisions the account service-side.
  const probe = await opts.agent.buildAccountIntrospection({ baseUrl: opts.baseUrl, discovery: disc });

  if (!attestedOnly) {
    const res = await fetchImpl(probe.url, { method: probe.method, headers: probe.headers });
    const account = await readJson(res);
    if (!res.ok) throw new Error(`signup failed: HTTP ${res.status}`);
    return { discovery: disc, account, status: res.status, trust: opts.trust, binding: opts.binding };
  }

  const trust =
    opts.trust ??
    new TrustClient({
      agentDid: opts.agent.did,
      agentPublicKey: opts.agent.publicKey,
      agentPrivateKey: opts.agent.exportPrivateKey(),
      ...(opts.trustBaseUrl ? { baseUrl: opts.trustBaseUrl } : {}),
      ...(opts.binding ? { binding: opts.binding } : {}),
      ...(opts.fetch ? { fetch: opts.fetch } : {}),
    });

  let binding = opts.binding ?? trust.getBinding();
  if (!trust.isLinked()) {
    const link = await trust.linkStart(opts.label ? { label: opts.label } : {});
    if (opts.onLink) await opts.onLink(link.link_url, link);
    const intervalMs = opts.pollIntervalMs ?? 2000;
    const deadline = now() + link.expires_in * 1000;
    for (;;) {
      const polled = await trust.linkPoll(link.req_id);
      if (polled) {
        binding = polled;
        break;
      }
      if (now() >= deadline) throw new Error("trust link not confirmed before it expired");
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }

  const acceptedAttestors = opts.acceptedAttestors ?? billing.accepted_attestors;
  const af = new AttestedFetcher({
    agent: opts.agent,
    trust,
    serviceDid: disc.service_did,
    ...(acceptedAttestors ? { acceptedAttestors } : {}),
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  const res = await af.fetch({ method: probe.method, url: probe.url });
  const account = await readJson(res);
  if (!res.ok) throw new Error(`signup failed after attestation: HTTP ${res.status}`);
  return { discovery: disc, account, status: res.status, trust, binding };
}
