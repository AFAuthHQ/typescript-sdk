import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "../index.js";
import { saveAgent, loadAgent } from "../node.js";

// RFC 8032 Ed25519 vector 1 — same fixed seed/did the store test uses.
const RFC_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC_DID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

describe("seed zeroization", () => {
  it("destroy() zeros the in-memory seed and blocks further signing", async () => {
    const a = await Agent.generate();
    expect(Buffer.from(a.exportPrivateKey()).toString("hex")).not.toMatch(/^0+$/);

    a.destroy();

    expect(Buffer.from(a.exportPrivateKey()).toString("hex")).toBe("0".repeat(64));
    await expect(a.signRequest({ method: "GET", url: "https://svc.example/" })).rejects.toThrow(
      /destroyed/,
    );
  });

  it("fromPrivateKey copies the seed, so a caller can wipe its buffer safely", async () => {
    const seed = new Uint8Array(Buffer.from(RFC_SEED, "hex"));
    const agent = await Agent.fromPrivateKey(seed);

    // Simulate the caller (e.g. loadAgent) zeroizing its transient buffer.
    seed.fill(0);

    expect(agent.did).toBe(RFC_DID);
    expect(Buffer.from(agent.exportPrivateKey()).toString("hex")).toBe(RFC_SEED);
  });
});

describe("saveAgent overwrite backup (Go-parity, no silent destroy)", () => {
  let dir: string;
  let keyPath: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "afauth-seed-"));
    keyPath = join(dir, "key.json");
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("a fresh save creates no backup", async () => {
    await saveAgent(await Agent.generate(), keyPath);
    await expect(stat(`${keyPath}.bak`)).rejects.toThrow();
  });

  it("overwrite preserves the prior key as a rolling .bak", async () => {
    const a = await Agent.generate();
    await saveAgent(a, keyPath);

    const b = await Agent.generate();
    await saveAgent(b, keyPath, { overwrite: true });

    // Old key is recoverable, not destroyed; new key is active.
    expect((await loadAgent(`${keyPath}.bak`))!.did).toBe(a.did);
    expect((await loadAgent(keyPath))!.did).toBe(b.did);
    expect((await stat(`${keyPath}.bak`)).mode & 0o777).toBe(0o600);

    // A second rotation rolls the backup forward to the now-prior key (b),
    // so at most one backup ever exists — no unbounded pile of live keys.
    const c = await Agent.generate();
    await saveAgent(c, keyPath, { overwrite: true });
    expect((await loadAgent(`${keyPath}.bak`))!.did).toBe(b.did);
    expect((await loadAgent(keyPath))!.did).toBe(c.did);
  });
});
