import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildCanonicalInput,
  sha256ContentDigest,
  type CanonicalRequest,
  type CoveredComponent,
  type SignatureParams,
} from "../index.js";

const SIGS_DIR = join(__dirname, "..", "..", "..", "..", "vendor", "spec-vectors", "signatures");

interface Vector {
  name: string;
  request: { method: string; target_uri: string; body: string | null };
  content_digest: string | null;
  covered_components: readonly CoveredComponent[];
  signature_params: SignatureParams;
  canonical_signature_input: string;
}

function loadVectors(): Vector[] {
  return readdirSync(SIGS_DIR)
    .filter((f) => f.endsWith(".json") && !f.startsWith("_"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(SIGS_DIR, f), "utf8")) as Vector);
}

describe("canonical input + content-digest against vendored vectors", () => {
  for (const v of loadVectors()) {
    it(`${v.name}: canonical input rebuilds byte-equal`, () => {
      const canonReq: CanonicalRequest = {
        method: v.request.method,
        targetUri: v.request.target_uri,
        ...(v.content_digest ? { contentDigest: v.content_digest } : {}),
      };
      const rebuilt = buildCanonicalInput(canonReq, v.signature_params, v.covered_components);
      expect(rebuilt).toBe(v.canonical_signature_input);
    });

    if (v.request.body !== null) {
      it(`${v.name}: sha256ContentDigest matches committed value`, () => {
        expect(sha256ContentDigest(v.request.body!)).toBe(v.content_digest);
      });
    }
  }
});
