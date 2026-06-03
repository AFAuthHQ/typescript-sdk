-- AFAuth per-principal uniqueness (migration 0002).
--
-- Backs `D1SubHUniquenessStore` — the §10.4.4 "same human, same bucket"
-- slot. One row per occupied `(iss, sub_h)` slot; the composite PRIMARY
-- KEY makes `claim()` atomic (INSERT ... ON CONFLICT DO NOTHING decides a
-- single winner under concurrent claims), closing the free-tier Sybil hole
-- that `attested_only` alone leaves open.
--
-- Apply after 0001_init.sql with `wrangler d1 migrations apply <db-name>`.
-- Portable to standard Postgres / MySQL with minor syntactic changes.

CREATE TABLE IF NOT EXISTS afauth_subh_uniqueness (
  -- Attestor identifier (JWT `iss`). Part of the key: different attestors
  -- derive independent pseudonym spaces for the same human (§10.4.4), so a
  -- given human may legitimately hold one slot per attestor.
  iss         TEXT NOT NULL,
  -- The pairwise human pseudonym `sub_h` (§10.4). Opaque base64url.
  sub_h       TEXT NOT NULL,
  -- The account DID currently holding the slot. Tracks the live key across
  -- rotations (§8.1 / §8.2) via UPDATE in rekey().
  did         TEXT NOT NULL,
  claimed_at  TEXT NOT NULL,
  PRIMARY KEY (iss, sub_h)
);

-- Reverse lookup for rekey()/releaseByDid(), which operate from a DID alone.
CREATE INDEX IF NOT EXISTS idx_afauth_subh_did
  ON afauth_subh_uniqueness (did);
