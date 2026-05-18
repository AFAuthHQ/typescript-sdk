/**
 * @afauth/agent — Agent SDK for the AFAuth Protocol.
 *
 * Generates Ed25519 keypairs, derives `did:key` identifiers, and signs HTTP
 * requests per RFC 9421 with AFAuth-specific signed components.
 *
 * TODO: implement key generation, did:key encoding (multibase multicodec
 * prefix 0xed01), keypair serialisation, and signed-fetch.
 */

/**
 * An agent's cryptographic identity.
 *
 * The public key encoded as `did:key:...` is the agent's account ID on every
 * AFAuth-enabled service.
 */
export class AgentIdentity {
  /** The `did:key:...` identifier derived from the public key. */
  readonly did: string;

  private readonly publicKey: Uint8Array;
  private readonly privateKey: Uint8Array;

  private constructor(publicKey: Uint8Array, privateKey: Uint8Array, did: string) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.did = did;
  }

  /** Generate a fresh Ed25519 keypair. */
  static generate(): AgentIdentity {
    throw new Error("TODO: not yet implemented");
  }

  /** Load a previously-saved keypair from disk. Returns null if no file at the given path. */
  static load(_path: string): AgentIdentity | null {
    throw new Error("TODO: not yet implemented");
  }

  /** Persist this keypair to disk with file mode 0600. */
  save(_path: string): void {
    throw new Error("TODO: not yet implemented");
  }

  /** Signed fetch — sends an HTTP request with RFC 9421 signature headers. */
  async fetch(_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> {
    throw new Error("TODO: not yet implemented");
  }
}
