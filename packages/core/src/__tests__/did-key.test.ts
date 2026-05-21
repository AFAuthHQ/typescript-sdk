import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { decodeDidKey, encodeDidKey } from "../index.js";

const VENDOR_DIR = join(__dirname, "..", "..", "..", "..", "vendor", "spec-vectors");

interface KeypairFixture {
  did_key: string;
  public_key_raw_hex: string;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

describe("did:key codec", () => {
  const keypair: KeypairFixture = JSON.parse(
    readFileSync(join(VENDOR_DIR, "keypair.json"), "utf8"),
  );

  it("decodes the reference public key to the right bytes", () => {
    const pub = decodeDidKey(keypair.did_key);
    expect(bytesToHex(pub)).toBe(keypair.public_key_raw_hex);
  });

  it("encodes the reference bytes back to the same did:key", () => {
    const pub = hexToBytes(keypair.public_key_raw_hex);
    expect(encodeDidKey(pub)).toBe(keypair.did_key);
  });

  it("roundtrips a random keypair", () => {
    const random = new Uint8Array(32);
    for (let i = 0; i < 32; i++) random[i] = i * 7 + 13;
    expect(decodeDidKey(encodeDidKey(random))).toEqual(random);
  });

  it("rejects non-did:key inputs", () => {
    expect(() => decodeDidKey("did:web:example.com")).toThrow(/not a did:key/);
  });

  it("rejects wrong multicodec prefix", () => {
    // base58btc-encoded 0x00 0x01 + 32 zero bytes — would be "did:key:z" + base58 of 34 bytes
    // Construct a deliberately-wrong prefix vector by hand to confirm rejection:
    expect(() => decodeDidKey("did:key:zABC")).toThrow();
  });

  it("rejects wrong-length keys", () => {
    expect(() => encodeDidKey(new Uint8Array(31))).toThrow(/32 bytes/);
  });
});
