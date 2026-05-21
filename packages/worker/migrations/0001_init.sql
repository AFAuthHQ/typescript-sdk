-- AFAuth v0.1 schema (migration 0001).
--
-- Apply with `wrangler d1 migrations apply <db-name>` after copying
-- this file into your Worker project's migrations directory. The
-- schema is portable to standard Postgres / MySQL with minor syntactic
-- changes (CHECK constraints + JSON columns are SQLite-native).
--
-- Two tables:
--   afauth_accounts        — one row per account, keyed by current DID
--   afauth_invitations     — one row per pending invitation; UNIQUE
--                            on account_did enforces §7.3 atomicity
--                            (at most one pending invitation per account)

CREATE TABLE IF NOT EXISTS afauth_accounts (
  did          TEXT PRIMARY KEY,
  state        TEXT NOT NULL CHECK (state IN ('UNCLAIMED', 'INVITED', 'CLAIMED', 'EXPIRED', 'ARCHIVED')),
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  -- JSON of Account.owner ({ identity, userId, claimedAt }). NULL
  -- until the account transitions to CLAIMED.
  owner_json   TEXT,
  -- 0/1 boolean. Set by §8.4 owner-initiated revocation.
  revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS afauth_invitations (
  token           TEXT PRIMARY KEY,
  account_did     TEXT NOT NULL,
  recipient_json  TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  -- §7.3 atomicity: at most one pending invitation per account.
  -- A new invitation must DELETE any prior row before INSERT.
  UNIQUE (account_did),
  FOREIGN KEY (account_did) REFERENCES afauth_accounts (did) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_afauth_invitations_account
  ON afauth_invitations (account_did);
