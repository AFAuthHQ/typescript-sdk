-- AFAuth v0.1 schema (migration 0001) — multi-agent accounts.
--
-- Apply with `wrangler d1 migrations apply <db-name>`. Portable to standard
-- Postgres / MySQL with minor syntactic changes (CHECK constraints + JSON
-- columns are SQLite-native).
--
-- An account is keyed on an opaque `account_id` (NOT a DID) and groups every
-- agent credential (device) of one human (§10.4.4). Three tables:
--   afauth_accounts        — one row per account
--   afauth_account_agents  — one row per attached agent DID (device)
--   afauth_invitations     — one row per pending owner invitation

CREATE TABLE IF NOT EXISTS afauth_accounts (
  account_id   TEXT PRIMARY KEY,
  -- Per-service human pseudonym this account is grouped under (§10.4). Both
  -- NULL for singleton accounts (no-sub_h / attestation off|optional). The
  -- UNIQUE constraint enforces at most one account per (iss, sub_h); SQLite
  -- treats NULLs as distinct, so singletons never collide.
  iss          TEXT,
  sub_h        TEXT,
  state        TEXT NOT NULL CHECK (state IN ('UNCLAIMED', 'INVITED', 'CLAIMED', 'EXPIRED', 'ARCHIVED')),
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  -- JSON of Account.owner ({ identity, userId, claimedAt }). NULL until CLAIMED.
  owner_json   TEXT,
  -- 0/1 whole-account revoke (§8.4).
  revoked      INTEGER NOT NULL DEFAULT 0,
  UNIQUE (iss, sub_h)
);

CREATE TABLE IF NOT EXISTS afauth_account_agents (
  -- The agent credential (device) DID. Globally unique: one DID binds to at
  -- most one account (§10.5 is per-agent-DID).
  agent_did    TEXT PRIMARY KEY,
  account_id   TEXT NOT NULL,
  added_at     TEXT NOT NULL,
  -- 0/1 per-credential revoke (§8.4); the account survives if others remain.
  revoked      INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (account_id) REFERENCES afauth_accounts (account_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_afauth_account_agents_account
  ON afauth_account_agents (account_id);

CREATE TABLE IF NOT EXISTS afauth_invitations (
  token           TEXT PRIMARY KEY,
  account_id      TEXT NOT NULL,
  recipient_json  TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  -- §7.3 atomicity: at most one pending invitation per account.
  UNIQUE (account_id),
  FOREIGN KEY (account_id) REFERENCES afauth_accounts (account_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_afauth_invitations_account
  ON afauth_invitations (account_id);
