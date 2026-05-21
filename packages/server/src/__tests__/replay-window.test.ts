/**
 * C.6 conformance: replay-window vectors.
 *
 * For each vendored fixture, build a Verifier whose `now` is forced
 * to `verifier_now_unix_seconds`, materialise an HTTP request from
 * the signed-request shape, and assert the verify result matches
 * `expected_outcome`. For accept-with-replay vectors, also verify the
 * replay invariant (second verification rejects `replayed_nonce`).
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CoveredComponent, SignatureParams } from "@afauth/core";
import { MemoryNonceStore, Verifier } from "../index.js";

const REPLAY_DIR = join(__dirname, "..", "..", "..", "..", "vendor", "spec-vectors", "replay-window");

interface ReplayVector {
  name: string;
  request: { method: string; target_uri: string; body: string | null };
  content_digest: string | null;
  covered_components: readonly CoveredComponent[];
  signature_params: SignatureParams;
  canonical_signature_input: string;
  signature_hex: string;
  public_key_did: string;
  verifier_now_unix_seconds: number;
  expected_outcome:
    | { type: "accept" }
    | { type: "reject"; code: string; status: number };
  replay_behaviour?: string;
  extra_setup?: { kind: string; other_keyid?: string };
}

function loadReplayVectors(): ReplayVector[] {
  return readdirSync(REPLAY_DIR)
    .filter((f) => f.endsWith(".json") && !f.startsWith("_"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(REPLAY_DIR, f), "utf8")) as ReplayVector);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function buildHeaders(v: ReplayVector): Headers {
  const headers = new Headers();
  const p = v.signature_params;
  const componentList = v.covered_components.map((c) => `"${c}"`).join(" ");
  const sigInput =
    `sig1=(${componentList});` +
    `created=${p.created};expires=${p.expires};` +
    `nonce="${p.nonce}";keyid="${p.keyid}";alg="${p.alg}"`;
  headers.set("signature-input", sigInput);
  headers.set("signature", `sig1=:${bytesToBase64(hexToBytes(v.signature_hex))}:`);
  if (v.content_digest) headers.set("content-digest", v.content_digest);
  return headers;
}

function makeVerifier(v: ReplayVector, nonceStore: MemoryNonceStore): Verifier {
  return new Verifier({
    nonceStore,
    serviceDid: "did:web:example.com",
    now: () => v.verifier_now_unix_seconds,
  });
}

describe("§C.6 replay-window vectors", () => {
  const vectors = loadReplayVectors();

  it("vendors all four expected fixtures", () => {
    const names = vectors.map((v) => v.name).sort();
    expect(names).toEqual([
      "cross-keyid-nonce-reuse",
      "expired-signature",
      "fresh-signature-accepted",
      "future-dated-signature",
    ]);
  });

  for (const v of vectors) {
    if (v.expected_outcome.type === "reject") {
      // Hoist the narrowed values so they survive into the it() closure
      // (TS doesn't propagate discriminated-union narrowing across closures).
      const { code: expectedCode, status: expectedStatus } = v.expected_outcome;
      it(`${v.name}: rejects with ${expectedCode} (${expectedStatus})`, async () => {
        const nonceStore = new MemoryNonceStore();
        const verifier = makeVerifier(v, nonceStore);
        await expect(
          verifier.verify({
            method: v.request.method,
            url: v.request.target_uri,
            headers: buildHeaders(v),
            body: v.request.body,
          }),
        ).rejects.toMatchObject({ code: expectedCode, status: expectedStatus });
      });
    } else {
      it(`${v.name}: accepts`, async () => {
        const nonceStore = new MemoryNonceStore();
        if (v.extra_setup?.kind === "prime_nonce_under_other_keyid" && v.extra_setup.other_keyid) {
          await nonceStore.seen(v.extra_setup.other_keyid, v.signature_params.nonce, 60);
        }
        const verifier = makeVerifier(v, nonceStore);
        const result = await verifier.verify({
          method: v.request.method,
          url: v.request.target_uri,
          headers: buildHeaders(v),
          body: v.request.body,
        });
        expect(result.agentDid).toBe(v.public_key_did);

        if (v.replay_behaviour) {
          // Replay invariant: same vector against the same store rejects.
          await expect(
            verifier.verify({
              method: v.request.method,
              url: v.request.target_uri,
              headers: buildHeaders(v),
              body: v.request.body,
            }),
          ).rejects.toMatchObject({ code: "replayed_nonce", status: 401 });
        }
      });
    }
  }
});
