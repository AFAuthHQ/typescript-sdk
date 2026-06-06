import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, stat, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "../index.js";
import {
  loadAgent,
  saveAgent,
  loadOrCreateAgent,
  readSharedAgent,
  loadBinding,
  saveBinding,
  defaultKeyPath,
  defaultTrustPath,
  agentHome,
} from "../node.js";

// RFC 8032 Ed25519 test vector 1 — a fixed seed whose public key and did:key
// are well-known, so this doubles as a cross-implementation conformance check:
// any correct AFAuth client (the Go CLI included) must derive the same did:key.
const RFC_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
// did:key of RFC_PUB, computed independently via multicodec 0xed01 || pubkey
// + base58btc — the oracle this test checks the SDK's derivation against.
const RFC_DID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

let dir: string;
let keyPath: string;
let trustPath: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "afauth-store-"));
  keyPath = join(dir, "key.json");
  trustPath = join(dir, "trust.json");
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("key store", () => {
  it("returns null when no key file exists", async () => {
    expect(await loadAgent(keyPath)).toBeNull();
  });

  it("creates, persists the Go key.json shape (mode 0600), and re-loads identically", async () => {
    const { agent, created } = await loadOrCreateAgent(keyPath);
    expect(created).toBe(true);

    const raw = JSON.parse(await readFile(keyPath, "utf8"));
    expect(raw).toMatchObject({ version: 1, algorithm: "ed25519", did_key: agent.did });
    expect(raw.public_key_hex).toMatch(/^[0-9a-f]{64}$/);
    expect(raw.private_key_seed_hex).toMatch(/^[0-9a-f]{64}$/);
    expect(raw.did_key).toMatch(/^did:key:z/);
    expect((await stat(keyPath)).mode & 0o777).toBe(0o600);

    const second = await loadOrCreateAgent(keyPath);
    expect(second.created).toBe(false);
    expect(second.agent.did).toBe(agent.did);
    expect(Buffer.from(second.agent.exportPrivateKey()).toString("hex")).toBe(
      Buffer.from(agent.exportPrivateKey()).toString("hex"),
    );
  });

  it("refuses to clobber an existing key unless overwrite is set", async () => {
    const a = await Agent.generate();
    await saveAgent(a, keyPath);
    const b = await Agent.generate();
    await expect(saveAgent(b, keyPath)).rejects.toThrow(/already exists/);
    await saveAgent(b, keyPath, { overwrite: true });
    const loaded = await loadAgent(keyPath);
    expect(loaded!.did).toBe(b.did);
  });

  it("loads the canonical RFC 8032 vector to the well-known did:key (cross-impl parity)", async () => {
    await writeFile(
      keyPath,
      JSON.stringify({
        version: 1,
        algorithm: "ed25519",
        did_key: RFC_DID,
        public_key_hex: RFC_PUB,
        private_key_seed_hex: RFC_SEED,
      }),
    );
    const agent = await loadAgent(keyPath);
    expect(agent).not.toBeNull();
    expect(agent!.did).toBe(RFC_DID);
    expect(agent!.publicKeyHex()).toBe(RFC_PUB);
  });

  it("rejects a tampered public_key_hex", async () => {
    await writeFile(
      keyPath,
      JSON.stringify({
        version: 1,
        algorithm: "ed25519",
        did_key: RFC_DID,
        public_key_hex: "00".repeat(32),
        private_key_seed_hex: RFC_SEED,
      }),
    );
    await expect(loadAgent(keyPath)).rejects.toThrow(/public_key_hex/);
  });

  it("rejects an unsupported version", async () => {
    await writeFile(keyPath, JSON.stringify({ version: 99, algorithm: "ed25519", did_key: RFC_DID, public_key_hex: RFC_PUB, private_key_seed_hex: RFC_SEED }));
    await expect(loadAgent(keyPath)).rejects.toThrow(/version/);
  });
});

describe("trust store", () => {
  const did = RFC_DID;
  const base = "https://trust.afauth.org";
  const future = Math.floor(Date.now() / 1000) + 86_400;

  it("round-trips a binding (mode 0600) and matches the schema shape", async () => {
    await saveBinding({
      agentDid: did,
      baseUrl: base,
      binding: { binding_id: "bnd_1", binding_token_expires_at: future },
      iss: "afauth-trust",
      verification: "email",
      path: trustPath,
    });
    expect((await stat(trustPath)).mode & 0o777).toBe(0o600);

    const onDisk = JSON.parse(await readFile(trustPath, "utf8"));
    expect(onDisk.version).toBe(2);
    expect(onDisk.bindings).toHaveLength(1);
    expect(onDisk.bindings[0]).toMatchObject({
      base_url: base,
      iss: "afauth-trust",
      agent_did: did,
      binding_id: "bnd_1",
      binding_token_expires_at: future,
      verification: "email",
    });

    const loaded = await loadBinding({ agentDid: did, baseUrl: base, path: trustPath });
    expect(loaded).toEqual({ binding_id: "bnd_1", binding_token_expires_at: future });
  });

  it("preserves sibling attestor bindings on upsert", async () => {
    await saveBinding({ agentDid: did, baseUrl: base, binding: { binding_id: "bnd_pub", binding_token_expires_at: future }, iss: "afauth-trust", path: trustPath });
    await saveBinding({ agentDid: did, baseUrl: "https://acme-trust.example", binding: { binding_id: "bnd_ent", binding_token_expires_at: future }, iss: "acme", path: trustPath });

    const onDisk = JSON.parse(await readFile(trustPath, "utf8"));
    expect(onDisk.bindings).toHaveLength(2);
    expect(await loadBinding({ agentDid: did, baseUrl: base, path: trustPath })).toMatchObject({ binding_id: "bnd_pub" });
    expect(await loadBinding({ agentDid: did, baseUrl: "https://acme-trust.example", path: trustPath })).toMatchObject({ binding_id: "bnd_ent" });

    // Re-link same base_url → replace in place, keep the learned iss.
    await saveBinding({ agentDid: did, baseUrl: base, binding: { binding_id: "bnd_pub2", binding_token_expires_at: future }, path: trustPath });
    const after = JSON.parse(await readFile(trustPath, "utf8"));
    expect(after.bindings).toHaveLength(2);
    const pub = after.bindings.find((b: { base_url: string }) => b.base_url === base);
    expect(pub).toMatchObject({ binding_id: "bnd_pub2", iss: "afauth-trust" });
  });

  it("returns null for an orphaned binding (different agent_did)", async () => {
    await saveBinding({ agentDid: did, baseUrl: base, binding: { binding_id: "bnd_1", binding_token_expires_at: future }, path: trustPath });
    const other = await Agent.generate();
    expect(await loadBinding({ agentDid: other.did, baseUrl: base, path: trustPath })).toBeNull();
  });

  it("returns null for an expired binding", async () => {
    const past = Math.floor(Date.now() / 1000) - 10;
    await saveBinding({ agentDid: did, baseUrl: base, binding: { binding_id: "bnd_1", binding_token_expires_at: past }, path: trustPath });
    expect(await loadBinding({ agentDid: did, baseUrl: base, path: trustPath })).toBeNull();
  });

  it("returns null when no binding for the base url exists", async () => {
    expect(await loadBinding({ agentDid: did, baseUrl: base, path: trustPath })).toBeNull();
  });

  it("migrates a legacy v1 inline binding on read", async () => {
    await writeFile(
      trustPath,
      JSON.stringify({ version: 1, base_url: base, iss: "afauth-trust", agent_did: did, binding_id: "bnd_legacy", binding_token_expires_at: future }),
    );
    const loaded = await loadBinding({ agentDid: did, baseUrl: base, path: trustPath });
    expect(loaded).toMatchObject({ binding_id: "bnd_legacy" });
  });
});

describe("default paths", () => {
  it("honour AFAUTH_HOME", () => {
    const prev = process.env.AFAUTH_HOME;
    try {
      process.env.AFAUTH_HOME = "/tmp/some-home";
      expect(agentHome()).toBe("/tmp/some-home");
      expect(defaultKeyPath()).toBe("/tmp/some-home/key.json");
      expect(defaultTrustPath()).toBe("/tmp/some-home/trust.json");
    } finally {
      if (prev === undefined) delete process.env.AFAUTH_HOME;
      else process.env.AFAUTH_HOME = prev;
    }
  });
});

describe("key store — validation", () => {
  it("rejects an unsupported algorithm", async () => {
    await writeFile(keyPath, JSON.stringify({ version: 1, algorithm: "rsa", did_key: RFC_DID, public_key_hex: RFC_PUB, private_key_seed_hex: RFC_SEED }));
    await expect(loadAgent(keyPath)).rejects.toThrow(/algorithm/);
  });

  it("rejects a did_key that doesn't match the public key", async () => {
    const other = await Agent.generate();
    await writeFile(keyPath, JSON.stringify({ version: 1, algorithm: "ed25519", did_key: other.did, public_key_hex: RFC_PUB, private_key_seed_hex: RFC_SEED }));
    await expect(loadAgent(keyPath)).rejects.toThrow(/did_key/);
  });

  it("rejects a malformed seed", async () => {
    await writeFile(keyPath, JSON.stringify({ version: 1, algorithm: "ed25519", did_key: RFC_DID, public_key_hex: RFC_PUB, private_key_seed_hex: "nothex" }));
    await expect(loadAgent(keyPath)).rejects.toThrow(/seed/);
  });

  it("saveAgent overwrite leaves a 0600 file", async () => {
    const a = await Agent.generate();
    await saveAgent(a, keyPath);
    const b = await Agent.generate();
    await saveAgent(b, keyPath, { overwrite: true });
    expect((await stat(keyPath)).mode & 0o777).toBe(0o600);
    expect((await loadAgent(keyPath))!.did).toBe(b.did);
  });

  it("readSharedAgent reads the shared home — null, then the created identity", async () => {
    const prev = process.env.AFAUTH_HOME;
    try {
      process.env.AFAUTH_HOME = dir; // empty temp home
      expect(await readSharedAgent()).toBeNull();
      const { agent } = await loadOrCreateAgent();
      expect((await readSharedAgent())?.did).toBe(agent.did);
    } finally {
      if (prev === undefined) delete process.env.AFAUTH_HOME;
      else process.env.AFAUTH_HOME = prev;
    }
  });
});

describe("trust store — matching", () => {
  const did = RFC_DID;
  const future = Math.floor(Date.now() / 1000) + 86_400;

  it("finds a binding by iss as well as base_url", async () => {
    await saveBinding({ agentDid: did, baseUrl: "https://trust.afauth.org", binding: { binding_id: "bnd_1", binding_token_expires_at: future }, iss: "afauth-trust", path: trustPath });
    expect(await loadBinding({ agentDid: did, baseUrl: "afauth-trust", path: trustPath })).toMatchObject({ binding_id: "bnd_1" });
  });

  it("preserves a prior verification when re-saved without one", async () => {
    await saveBinding({ agentDid: did, baseUrl: "https://trust.afauth.org", binding: { binding_id: "bnd_1", binding_token_expires_at: future }, iss: "afauth-trust", verification: "email", path: trustPath });
    await saveBinding({ agentDid: did, baseUrl: "https://trust.afauth.org", binding: { binding_id: "bnd_2", binding_token_expires_at: future }, path: trustPath });
    const onDisk = JSON.parse(await readFile(trustPath, "utf8"));
    expect(onDisk.bindings[0]).toMatchObject({ binding_id: "bnd_2", iss: "afauth-trust", verification: "email" });
  });
});

describe("invalid files", () => {
  it("rejects an invalid JSON key file", async () => {
    await writeFile(keyPath, "{ not json");
    await expect(loadAgent(keyPath)).rejects.toThrow(/invalid JSON/);
  });

  it("rejects an invalid JSON trust file (surfaced on save)", async () => {
    await writeFile(trustPath, "{ not json");
    await expect(
      saveBinding({
        agentDid: RFC_DID,
        binding: { binding_id: "b", binding_token_expires_at: Math.floor(Date.now() / 1000) + 1000 },
        path: trustPath,
      }),
    ).rejects.toThrow(/invalid JSON/);
  });

  it("rethrows a non-ENOENT read error (e.g. path is a directory)", async () => {
    await expect(loadAgent(dir)).rejects.toThrow();
  });
});

describe("trust store — injected clock", () => {
  const did = RFC_DID;

  it("honours opts.now for save + expiry", async () => {
    const t = 1_000_000;
    await saveBinding({ agentDid: did, baseUrl: "https://trust.afauth.org", binding: { binding_id: "b", binding_token_expires_at: t + 100 }, path: trustPath, now: () => t });
    expect(await loadBinding({ agentDid: did, baseUrl: "https://trust.afauth.org", path: trustPath, now: () => t + 50 })).toMatchObject({ binding_id: "b" });
    expect(await loadBinding({ agentDid: did, baseUrl: "https://trust.afauth.org", path: trustPath, now: () => t + 200 })).toBeNull();
  });
});
