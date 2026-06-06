#!/usr/bin/env node
/**
 * example-cli — a minimal reference for a SERVICE-DISTRIBUTED CLI built on
 * `@afauthhq/agent`. This is the shape a vendor (say, "acme") ships as `acme`
 * so a user's coding agent can sign the user up agent-natively, with no
 * email/OTP/browser-OAuth and no bearer secret on the wire.
 *
 * The lean surface — three verbs, AFAuth stays invisible plumbing:
 *
 *   example-cli whoami                          # this machine's agent identity
 *   example-cli signup https://api.acme.dev     # provision (self-links if attested_only)
 *   example-cli claim  https://api.acme.dev you@example.com   # deferred human ownership
 *
 * Two ideas worth copying:
 *  1. It uses `loadOrCreateAgent()` / `loadBinding()` from `@afauthhq/agent/node`,
 *     which read the SHARED `~/.afauth/` home. So if the user already ran
 *     `afauth init` (or any other AFAuth-aware tool), this CLI reuses that one
 *     identity and that one human link — the human links ONCE, ever, across
 *     every service. Pass an explicit path to those helpers instead if you'd
 *     rather scope the key to your own tool.
 *  2. `signup()` does the whole discover → link-if-needed → attested-signup
 *     dance; the only human-in-the-loop step is the `onLink` callback, and only
 *     the first time on an unlinked machine.
 */

import { signup } from "@afauthhq/agent";
import { loadOrCreateAgent, loadBinding, saveBinding } from "@afauthhq/agent/node";

async function whoami(): Promise<void> {
  const { agent, created } = await loadOrCreateAgent();
  console.log(`${agent.did}${created ? "  (created)" : ""}`);
}

async function doSignup(baseUrl: string): Promise<void> {
  const { agent } = await loadOrCreateAgent();
  // Reuse a human link already on this machine (from `afauth trust link` or a
  // prior run) so we don't prompt again.
  const existing = (await loadBinding({ agentDid: agent.did })) ?? undefined;

  const result = await signup({
    agent,
    baseUrl,
    label: "example-cli",
    ...(existing ? { binding: existing } : {}),
    onLink: (url) => {
      console.error("Approve this agent once — a real person, in a browser:");
      console.error(`  ${url}`);
      console.error("Waiting for confirmation…");
    },
  });

  // Persist a freshly-established link so the human never re-links — and so
  // every other AFAuth client on the machine inherits it too.
  if (result.binding && result.binding !== existing) {
    await saveBinding({ agentDid: agent.did, binding: result.binding });
  }

  console.log(JSON.stringify({ did: agent.did, account: result.account }, null, 2));
}

async function claim(baseUrl: string, email: string): Promise<void> {
  const { agent } = await loadOrCreateAgent();
  const signed = await agent.buildOwnerInvitation({
    baseUrl,
    recipient: { type: "email", value: email },
  });
  const res = await fetch(signed.url, {
    method: signed.method,
    headers: signed.headers,
    ...(signed.body != null ? { body: signed.body as BodyInit } : {}),
  });
  console.error(
    res.ok ? `Invitation sent — check ${email} to finish claiming.` : `claim failed: HTTP ${res.status}`,
  );
}

async function main(): Promise<void> {
  const [cmd, a, b] = process.argv.slice(2);
  if (cmd === "whoami") return whoami();
  if (cmd === "signup" && a) return doSignup(a);
  if (cmd === "claim" && a && b) return claim(a, b);
  console.error("usage:");
  console.error("  example-cli whoami");
  console.error("  example-cli signup <service-url>");
  console.error("  example-cli claim  <service-url> <email>");
  process.exit(2);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
