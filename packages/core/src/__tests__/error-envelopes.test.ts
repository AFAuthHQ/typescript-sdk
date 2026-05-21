/**
 * C.5 conformance: AFAuthError.toResponse() must match the canonical
 * envelope shape and HTTP status documented in vendor/spec-vectors/errors/
 * for every reserved §11.3 code.
 *
 * The vectors are normative for envelope structure and status; the
 * `message` field is informational (§11.1) and the test does not
 * assert exact wording.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AFAuthError, type AFAuthErrorCode } from "../index.js";

const ERRORS_DIR = join(__dirname, "..", "..", "..", "..", "vendor", "spec-vectors", "errors");

interface ErrorVector {
  name: string;
  code: AFAuthErrorCode;
  http_status: number;
  envelope: {
    error: {
      code: AFAuthErrorCode;
      message: string;
      details?: unknown;
    };
  };
}

function loadErrorVectors(): ErrorVector[] {
  return readdirSync(ERRORS_DIR)
    .filter((f) => f.endsWith(".json") && !f.startsWith("_"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(ERRORS_DIR, f), "utf8")) as ErrorVector);
}

describe("§C.5 error-envelope vectors", () => {
  const vectors = loadErrorVectors();

  it("covers all 17 §11.3 reserved codes", () => {
    expect(vectors.length).toBe(17);
  });

  for (const v of vectors) {
    it(`${v.code}: AFAuthError.toResponse() matches envelope + status`, async () => {
      const err = new AFAuthError(v.code, v.http_status, v.envelope.error.message);
      const resp = err.toResponse();

      expect(resp.status).toBe(v.http_status);
      expect(resp.headers.get("content-type")).toBe("application/json");

      const body = (await resp.json()) as ErrorVector["envelope"];
      // error.code matches vector exactly.
      expect(body.error.code).toBe(v.code);
      // message is a string (content is informational; we use the
      // vector's message in this test to keep output deterministic).
      expect(typeof body.error.message).toBe("string");
      // No unknown keys on error (allowed: code, message, details).
      const keys = Object.keys(body.error).sort();
      expect(keys.every((k) => ["code", "message", "details"].includes(k))).toBe(true);
    });
  }

  it("preserves optional details field through serialisation", async () => {
    const err = new AFAuthError(
      "malformed_request",
      400,
      "request body invalid",
      { field: "recipient", reason: "missing" },
    );
    const body = (await err.toResponse().json()) as ErrorVector["envelope"];
    expect(body.error.details).toEqual({ field: "recipient", reason: "missing" });
  });

  it("omits details when undefined", async () => {
    const err = new AFAuthError("invalid_signature", 401, "bad");
    const body = (await err.toResponse().json()) as ErrorVector["envelope"];
    expect("details" in body.error).toBe(false);
  });
});
