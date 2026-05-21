/**
 * §C.4 recipient-normalisation conformance.
 *
 * Loads every vector under vendor/spec-vectors/recipients/ and runs
 * normaliseRecipient against it; asserts accept/reject and (on
 * accept) byte-equal canonical output.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { normaliseRecipient, type Recipient } from "../index.js";

const DIR = join(__dirname, "..", "..", "..", "..", "vendor", "spec-vectors", "recipients");

interface RecipientVector {
  name: string;
  recipient_type: "email" | "phone" | "oidc" | "did";
  input: Recipient;
  expected: { type: "accept"; canonical: Recipient } | { type: "reject"; reason?: string };
}

function loadVectors(): RecipientVector[] {
  return readdirSync(DIR)
    .filter((f) => f.endsWith(".json") && !f.startsWith("_"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(DIR, f), "utf8")) as RecipientVector);
}

describe("§C.4 recipient-normalisation vectors", () => {
  const vectors = loadVectors();

  it("vendors the full §C.4 corpus", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(19);
  });

  for (const v of vectors) {
    if (v.expected.type === "accept") {
      // Hoist the narrowed expected for the closure.
      const expectedCanonical = v.expected.canonical;
      it(`${v.name}: accepts and canonicalises`, () => {
        const out = normaliseRecipient(v.input);
        expect(out).toEqual(expectedCanonical);
      });
    } else {
      it(`${v.name}: rejects (${v.expected.reason ?? "n/a"})`, () => {
        expect(() => normaliseRecipient(v.input)).toThrow();
      });
    }
  }

  it("normaliseRecipient is idempotent for accept-vectors", () => {
    for (const v of vectors) {
      if (v.expected.type !== "accept") continue;
      const first = normaliseRecipient(v.input);
      const second = normaliseRecipient(first);
      expect(second).toEqual(first);
    }
  });
});
