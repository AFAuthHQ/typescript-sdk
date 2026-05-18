/**
 * @afauth/server — Server SDK for the AFAuth Protocol.
 *
 * Verifies signed requests, manages account state (UNCLAIMED / INVITED /
 * CLAIMED / EXPIRED), and drives the owner-invitation / claim flow.
 *
 * TODO: implement signature verification per RFC 9421, account state store
 * adapters (in-memory, Postgres, AFAuth Cloud), email delivery adapters,
 * claim-page hosting, and webhook delivery.
 */

export interface AFAuthOptions {
  /** API key for AFAuth Cloud / Network. Omit to run fully self-hosted. */
  apiKey?: string;

  /** Persistent storage for account state. Required in self-hosted mode. */
  storage?: StorageAdapter;

  /** Email provider for magic-link delivery. Required in self-hosted mode. */
  email?: EmailAdapter;

  /** URL of the hosted claim page (yours or AFAuth Cloud's). */
  claimPageUrl?: string;
}

/** Persistence layer for account state. */
export interface StorageAdapter {
  // TODO: account CRUD, invitation CRUD, key-rotation log
}

/** Email delivery for magic-link messages. */
export interface EmailAdapter {
  // TODO: sendMagicLink(email, token, accountSummary)
}

/** The verified account context attached to every signed request. */
export interface AccountContext {
  id: string;
  isClaimed: boolean;
  owner: { email: string; userId: string; claimedAt: string } | null;
  createdAt: string;
}

/**
 * Entry point for the server SDK.
 */
export class AFAuth {
  constructor(_options: AFAuthOptions) {
    // TODO
  }

  /** Express/Hono-compatible middleware that verifies the request signature and populates req.account. */
  middleware(): unknown {
    throw new Error("TODO: not yet implemented");
  }

  /** Initiate the two-step owner-invitation flow. */
  async inviteOwner(_accountId: string, _options: { email: string }): Promise<void> {
    throw new Error("TODO: not yet implemented");
  }

  /** Subscribe to lifecycle events: account.created, account.invited, account.claimed, account.expired. */
  on(_event: string, _handler: (...args: unknown[]) => void): void {
    throw new Error("TODO: not yet implemented");
  }
}
