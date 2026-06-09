/**
 * `@afauthhq/agent/node` — Node-only persistence for the AFAuth agent home.
 *
 * Reads and writes the same `$AFAUTH_HOME/{key.json,trust.json}` files the
 * reference `afauth` CLI uses (formats pinned by the spec's
 * `schemas/key-store.json` and `schemas/trust-store.json`; see
 * `spec/storage.md`). Sharing those files is what lets a human link an agent
 * once and have *every* AFAuth client on the machine — this SDK, the Go CLI,
 * a service-distributed CLI — reuse the same identity and the same human link.
 *
 * This entry imports `node:fs`/`node:os`/`node:path`, so it is deliberately
 * kept off the runtime-agnostic main entry (`@afauthhq/agent`), which still
 * runs on Workers/Deno/Bun. Import from `@afauthhq/agent/node` only in Node.
 */

import { readFile, writeFile, mkdir, rename, chmod, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { Agent, AFAUTH_TRUST_DEFAULT_BASE, type TrustBinding } from "./index.js";

// ---------- paths (§ spec/storage.md) ----------

/** The agent home: `$AFAUTH_HOME` when set and non-empty, else `~/.afauth`. */
export function agentHome(): string {
  const env = process.env.AFAUTH_HOME;
  return env && env.length > 0 ? env : join(homedir(), ".afauth");
}

/** Canonical keypair path: `$AFAUTH_HOME/key.json` (default `~/.afauth/key.json`). */
export function defaultKeyPath(): string {
  return join(agentHome(), "key.json");
}

/** Canonical trust-binding path: `$AFAUTH_HOME/trust.json`. */
export function defaultTrustPath(): string {
  return join(agentHome(), "trust.json");
}

// ---------- key.json (schemas/key-store.json) ----------

interface KeyFile {
  version: number;
  algorithm: string;
  did_key: string;
  public_key_hex: string;
  private_key_seed_hex: string;
}

const KEY_VERSION = 1;

function isENOENT(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === "ENOENT";
}

/**
 * Load the agent keypair from `path` (default the shared `key.json`).
 *
 * Returns `null` when the file does not exist — so callers can create one.
 * Throws on a malformed file, an unsupported version/algorithm, or a
 * consistency-check failure: the public key derived from the seed MUST match
 * `public_key_hex`, and the derived `did:key` MUST match `did_key` (the same
 * tamper/truncation checks the Go loader performs).
 */
export async function loadAgent(path: string = defaultKeyPath()): Promise<Agent | null> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if (isENOENT(err)) return null;
    throw err;
  }
  let raw: KeyFile;
  try {
    raw = JSON.parse(text) as KeyFile;
  } catch (err) {
    throw new Error(`key store ${path}: invalid JSON: ${(err as Error).message}`);
  }
  if (raw.version !== KEY_VERSION) {
    throw new Error(`key store ${path}: unsupported version ${raw.version} (this build understands ${KEY_VERSION})`);
  }
  if (raw.algorithm !== "ed25519") {
    throw new Error(`key store ${path}: unsupported algorithm ${JSON.stringify(raw.algorithm)} (v0.1: ed25519 only)`);
  }
  if (typeof raw.private_key_seed_hex !== "string" || !/^[0-9a-f]{64}$/.test(raw.private_key_seed_hex)) {
    throw new Error(`key store ${path}: private_key_seed_hex must be 64 lowercase hex chars`);
  }
  const seed = new Uint8Array(Buffer.from(raw.private_key_seed_hex, "hex"));
  const agent = await Agent.fromPrivateKey(seed);
  // fromPrivateKey copied the seed into the agent; drop our decode buffer so
  // the only live copy is the one a caller can later agent.destroy(). The
  // immutable `raw.private_key_seed_hex` string remains beyond our reach.
  seed.fill(0);
  if (agent.publicKeyHex() !== raw.public_key_hex) {
    throw new Error(`key store ${path}: persisted public_key_hex does not match the key derived from the seed`);
  }
  if (agent.did !== raw.did_key) {
    throw new Error(`key store ${path}: persisted did_key ${JSON.stringify(raw.did_key)} does not match derived ${JSON.stringify(agent.did)}`);
  }
  return agent;
}

/**
 * Persist `agent` to `path` in the shared `key.json` format (mode 0600, parent
 * dir 0700). Refuses to clobber an existing key unless `opts.overwrite` is set
 * (replacing a key is a footgun — rotation is an explicit operation). With
 * `overwrite`, the write is atomic (temp file + rename).
 */
export async function saveAgent(
  agent: Agent,
  path: string = defaultKeyPath(),
  opts: { overwrite?: boolean } = {},
): Promise<void> {
  const file: KeyFile = {
    version: KEY_VERSION,
    algorithm: "ed25519",
    did_key: agent.did,
    public_key_hex: agent.publicKeyHex(),
    private_key_seed_hex: Buffer.from(agent.exportPrivateKey()).toString("hex"),
  };
  const data = JSON.stringify(file, null, 2) + "\n";
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  if (opts.overwrite) {
    const tmp = `${path}.tmp`;
    await writeFile(tmp, data, { mode: 0o600 });
    // Preserve the prior key as a sibling `.bak` before installing the new
    // one, so a rotation the service later disputes is recoverable. (The Go
    // CLI's Replace does the same.) Unlike the CLI's timestamped backups
    // this is a single rolling backup — all the "revert the last rotation"
    // case needs, and it avoids the unbounded pile of live private keys that
    // accumulating backups create. `afauth keys forget-backup` can shred it.
    try {
      await stat(path);
      await rename(path, `${path}.bak`);
    } catch (err) {
      if (!isENOENT(err)) throw err;
    }
    await rename(tmp, path);
    await chmod(path, 0o600);
    return;
  }
  try {
    // "wx" === O_CREAT | O_EXCL | O_WRONLY — fails if the file exists.
    await writeFile(path, data, { flag: "wx", mode: 0o600 });
  } catch (err) {
    if ((err as { code?: string }).code === "EEXIST") {
      throw new Error(`key already exists at ${path} (pass { overwrite: true } to replace it)`);
    }
    throw err;
  }
}

/**
 * Load the keypair at `path`, or generate + persist a fresh one if absent.
 *
 * The headline helper for a CLI's first run: by default it targets the shared
 * agent home, so it reuses an identity the user already created with `afauth
 * init` (and the human link that came with it) instead of minting a new one.
 * A malformed existing file throws rather than being overwritten.
 */
export async function loadOrCreateAgent(
  path: string = defaultKeyPath(),
): Promise<{ agent: Agent; created: boolean }> {
  const existing = await loadAgent(path);
  if (existing) return { agent: existing, created: false };
  const agent = await Agent.generate();
  await saveAgent(agent, path);
  return { agent, created: true };
}

/**
 * The machine's shared AFAuth identity, or `null` if none exists yet.
 * Sugar for `loadAgent(defaultKeyPath())` — use it to detect "is this machine
 * already equipped?" before deciding whether to create a service-scoped key.
 */
export function readSharedAgent(): Promise<Agent | null> {
  return loadAgent(defaultKeyPath());
}

// ---------- trust.json (schemas/trust-store.json) ----------

interface StoredBinding {
  base_url: string;
  iss?: string;
  agent_did: string;
  binding_id: string;
  binding_token_expires_at: number;
  verification?: "email" | "oauth" | "payment";
  verification_seen_at?: number;
}

interface TrustStore {
  version: number;
  bindings: StoredBinding[];
}

const TRUST_VERSION = 2;

function trimSlash(s: string): string {
  return s.replace(/\/+$/, "");
}

/**
 * Read `trust.json`, migrating a legacy v1 file (single binding inlined at the
 * top level) to the v2 `bindings` array — mirrors the Go loader. A missing
 * file yields an empty store so the save path can create one.
 */
async function readTrustStore(path: string): Promise<TrustStore> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if (isENOENT(err)) return { version: TRUST_VERSION, bindings: [] };
    throw err;
  }
  let raw: Partial<TrustStore> & Partial<StoredBinding>;
  try {
    raw = JSON.parse(text) as Partial<TrustStore> & Partial<StoredBinding>;
  } catch (err) {
    throw new Error(`trust store ${path}: invalid JSON: ${(err as Error).message}`);
  }
  let bindings = Array.isArray(raw.bindings) ? (raw.bindings as StoredBinding[]) : [];
  // v1 inline single binding → fold into the v2 array.
  if (bindings.length === 0 && (raw.base_url || raw.binding_id)) {
    bindings = [
      {
        base_url: raw.base_url ?? "",
        ...(raw.iss ? { iss: raw.iss } : {}),
        agent_did: raw.agent_did ?? "",
        binding_id: raw.binding_id ?? "",
        binding_token_expires_at: raw.binding_token_expires_at ?? 0,
        ...(raw.verification ? { verification: raw.verification } : {}),
        ...(raw.verification_seen_at ? { verification_seen_at: raw.verification_seen_at } : {}),
      },
    ];
  }
  return { version: TRUST_VERSION, bindings };
}

async function writeTrustStore(path: string, store: TrustStore): Promise<void> {
  store.version = TRUST_VERSION;
  if (!store.bindings) store.bindings = [];
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const data = JSON.stringify(store, null, 2);
  const tmp = `${path}.tmp`;
  await writeFile(tmp, data, { mode: 0o600 });
  await rename(tmp, path);
  await chmod(path, 0o600);
}

/**
 * The currently-usable binding for `baseUrl` (default the canonical
 * `afauth-trust` attestor), or `null`. Returns `null` when the binding is
 * absent, ORPHANED (its `agent_did` differs from `agentDid` — left by a key
 * rotation), or expired — i.e. exactly the cases where it can't mint. The
 * returned shape feeds straight into `new TrustClient({ binding })`.
 */
export async function loadBinding(opts: {
  agentDid?: string;
  baseUrl?: string;
  path?: string;
  now?: () => number;
}): Promise<TrustBinding | null> {
  const baseUrl = opts.baseUrl ?? AFAUTH_TRUST_DEFAULT_BASE;
  const store = await readTrustStore(opts.path ?? defaultTrustPath());
  const sel = trimSlash(baseUrl);
  const b = store.bindings.find(
    (x) => trimSlash(x.base_url) === sel || (x.iss !== undefined && x.iss === baseUrl),
  );
  if (!b) return null;
  if (opts.agentDid && b.agent_did && b.agent_did !== opts.agentDid) return null; // orphaned
  const now = opts.now ? opts.now() : Math.floor(Date.now() / 1000);
  if (b.binding_token_expires_at > 0 && now >= b.binding_token_expires_at) return null; // expired
  return { binding_id: b.binding_id, binding_token_expires_at: b.binding_token_expires_at };
}

/**
 * Upsert a binding for `baseUrl` into `trust.json`, preserving every other
 * attestor's binding (and a previously-learned `iss` if `iss` is omitted) —
 * the same merge the Go CLI performs, so the SDK and CLI can share the file.
 */
export async function saveBinding(opts: {
  agentDid: string;
  binding: TrustBinding;
  baseUrl?: string;
  iss?: string;
  verification?: "email" | "oauth" | "payment";
  path?: string;
  now?: () => number;
}): Promise<void> {
  const path = opts.path ?? defaultTrustPath();
  const baseUrl = opts.baseUrl ?? AFAUTH_TRUST_DEFAULT_BASE;
  const store = await readTrustStore(path);
  const key = trimSlash(baseUrl);
  const now = opts.now ? opts.now() : Math.floor(Date.now() / 1000);
  const existing = store.bindings.find((x) => trimSlash(x.base_url) === key);
  const next: StoredBinding = {
    base_url: baseUrl,
    agent_did: opts.agentDid,
    binding_id: opts.binding.binding_id,
    binding_token_expires_at: opts.binding.binding_token_expires_at,
    ...(opts.iss ?? existing?.iss ? { iss: opts.iss ?? existing?.iss } : {}),
    ...(opts.verification
      ? { verification: opts.verification, verification_seen_at: now }
      : existing?.verification
        ? { verification: existing.verification, verification_seen_at: existing.verification_seen_at }
        : {}),
  };
  const idx = store.bindings.findIndex((x) => trimSlash(x.base_url) === key);
  if (idx >= 0) store.bindings[idx] = next;
  else store.bindings.push(next);
  await writeTrustStore(path, store);
}
