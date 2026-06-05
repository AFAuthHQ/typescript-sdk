/**
 * Runnable end-to-end test for the optional-auth recipe. Exercises all three
 * outcomes: anonymous → 200 (no challenge), signed → elevated, failed attempt →
 * 401 + §5.7 challenge.
 *
 *   pnpm --filter @afauthhq/example-recipes test
 */
import { describe, expect, it } from "vitest";
import { Agent } from "@afauthhq/agent";
import { parseChallenge } from "@afauthhq/server";
import { handleOptionalAuth } from "./optional-auth.js";

function headersFrom(h: Record<string, string>): Headers {
  const headers = new Headers();
  for (const [k, v] of Object.entries(h)) headers.set(k, v);
  return headers;
}

describe("optional-auth recipe (anonymous-allowed endpoint)", () => {
  it("serves anonymous callers with the public payload (200, no challenge)", async () => {
    const res = await handleOptionalAuth(new Request("https://api.example.com/api/data"));
    expect(res.status).toBe(200);
    expect(res.headers.get("WWW-Authenticate")).toBeNull();
    expect(((await res.json()) as { tier: string }).tier).toBe("anonymous");
  });

  it("elevates an authenticated agent", async () => {
    const agent = await Agent.generate();
    const signed = await agent.signRequest({
      method: "GET",
      url: "https://api.example.com/api/data",
    });
    const res = await handleOptionalAuth(
      new Request(signed.url, { method: signed.method, headers: headersFrom(signed.headers) }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { tier: string; agent: string };
    expect(body.tier).toBe("authenticated");
    expect(body.agent).toBe(agent.did);
  });

  it("rejects a failed AFAuth attempt with a §5.7 challenge", async () => {
    const res = await handleOptionalAuth(
      new Request("https://api.example.com/api/data", {
        headers: { "signature-input": "garbage" },
      }),
    );
    expect(res.status).toBe(401);
    expect(parseChallenge(res.headers.get("WWW-Authenticate")!)?.error).toBe("invalid_signature");
  });
});
