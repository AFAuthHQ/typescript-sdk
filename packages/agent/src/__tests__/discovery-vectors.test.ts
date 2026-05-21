/**
 * §C.3 discovery-document conformance.
 *
 * Loads every vector under vendor/spec-vectors/discovery/ and runs
 * the document through assertDiscoveryDocument; asserts the
 * accept/reject outcome matches the fixture's `expected.type`.
 *
 * `reason` strings on reject fixtures are informational —
 * implementations may produce different error messages.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { assertDiscoveryDocument } from "../index.js";

const DIR = join(__dirname, "..", "..", "..", "..", "vendor", "spec-vectors", "discovery");

interface DiscoveryVector {
  name: string;
  document: unknown;
  expected: { type: "accept" } | { type: "reject"; reason?: string };
}

function loadVectors(): DiscoveryVector[] {
  return readdirSync(DIR)
    .filter((f) => f.endsWith(".json") && !f.startsWith("_"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(DIR, f), "utf8")) as DiscoveryVector);
}

describe("§C.3 discovery-document vectors", () => {
  const vectors = loadVectors();

  it("vendors the full §C.3 corpus", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(18);
  });

  for (const v of vectors) {
    if (v.expected.type === "accept") {
      it(`${v.name}: accepts`, () => {
        expect(() => assertDiscoveryDocument(v.document)).not.toThrow();
      });
    } else {
      it(`${v.name}: rejects (${v.expected.reason ?? "n/a"})`, () => {
        expect(() => assertDiscoveryDocument(v.document)).toThrow();
      });
    }
  }
});
