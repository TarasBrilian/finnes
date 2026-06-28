/**
 * Database schema (FIN-029, docs/INDEXER_IMPLEMENTATION.md §4). Embedded as a SQL
 * string (not a .sql file) so it ships in `dist/` without a build-time copy step.
 * All `CREATE … IF NOT EXISTS`, so `migrate()` is idempotent. Field-element columns
 * are `BYTEA` (raw 32 bytes); hex is an API-boundary concern only.
 *
 * Idempotency: every table has a NATURAL unique key so re-ingesting an event
 * (restart, page overlap, mild reorg) is a no-op via `ON CONFLICT DO NOTHING`.
 * `seq`/`id` are `BIGSERIAL` only to give a stable newest-first ordering.
 */

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS sync_state (
  contract_id  TEXT PRIMARY KEY,
  start_ledger BIGINT      NOT NULL,
  last_cursor  TEXT,
  last_ledger  BIGINT      NOT NULL DEFAULT 0,
  backfilled   BOOLEAN     NOT NULL DEFAULT FALSE,
  head_root    BYTEA,
  head_count   BIGINT      NOT NULL DEFAULT 0,
  halted       BOOLEAN     NOT NULL DEFAULT FALSE,
  halt_reason  TEXT,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS leaves (
  tree        SMALLINT    NOT NULL,
  leaf_index  BIGINT      NOT NULL,
  commitment  BYTEA       NOT NULL,
  tx_hash     TEXT        NOT NULL,
  ledger      BIGINT      NOT NULL,
  topic       TEXT        NOT NULL,
  output_pos  SMALLINT    NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tree, leaf_index),
  UNIQUE (commitment)
);

CREATE TABLE IF NOT EXISTS roots (
  seq        BIGSERIAL PRIMARY KEY,
  tree       SMALLINT NOT NULL,
  root       BYTEA    NOT NULL,
  leaf_count BIGINT   NOT NULL,
  tx_hash    TEXT     NOT NULL,
  ledger     BIGINT   NOT NULL,
  UNIQUE (tree, tx_hash)
);
CREATE INDEX IF NOT EXISTS roots_recent_idx ON roots (tree, seq DESC);
CREATE INDEX IF NOT EXISTS roots_value_idx  ON roots (tree, root);

CREATE TABLE IF NOT EXISTS nullifiers (
  nullifier  BYTEA       PRIMARY KEY,
  tx_hash    TEXT        NOT NULL,
  ledger     BIGINT      NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ciphertexts (
  id           BIGSERIAL,
  tx_hash      TEXT     NOT NULL,
  output_index SMALLINT NOT NULL,
  commitment   BYTEA    NOT NULL,
  circuit      TEXT     NOT NULL,
  ledger       BIGINT   NOT NULL,
  c_auditor    BYTEA[]  NOT NULL,
  c_recipient  BYTEA[]  NOT NULL,
  PRIMARY KEY (tx_hash, output_index)
);
CREATE INDEX IF NOT EXISTS ciphertexts_commitment_idx ON ciphertexts (commitment);
CREATE INDEX IF NOT EXISTS ciphertexts_id_idx         ON ciphertexts (id);

CREATE TABLE IF NOT EXISTS transactions (
  tx_hash          TEXT        PRIMARY KEY,
  seq              BIGSERIAL   UNIQUE,
  circuit          TEXT        NOT NULL,
  ledger           BIGINT      NOT NULL,
  closed_at        TIMESTAMPTZ NOT NULL,
  nullifiers       BYTEA[]     NOT NULL DEFAULT '{}',
  reveal_asset_id  BYTEA,
  reveal_amount    BYTEA,
  reveal_recipient BYTEA
);
CREATE INDEX IF NOT EXISTS transactions_seq_idx ON transactions (seq DESC);

CREATE TABLE IF NOT EXISTS frozen (
  commitment  BYTEA     PRIMARY KEY,
  frozen_root BYTEA     NOT NULL,
  tx_hash     TEXT      NOT NULL,
  ledger      BIGINT    NOT NULL,
  seq         BIGSERIAL UNIQUE
);

CREATE TABLE IF NOT EXISTS compliance_roots (
  id      BIGSERIAL PRIMARY KEY,
  kind    TEXT   NOT NULL,
  root    BYTEA  NOT NULL,
  tx_hash TEXT   NOT NULL,
  ledger  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS compliance_roots_kind_idx ON compliance_roots (kind, id DESC);

CREATE TABLE IF NOT EXISTS asset_registry (
  asset_id BYTEA PRIMARY KEY,
  sac      TEXT  NOT NULL
);

CREATE TABLE IF NOT EXISTS transparent_registry (
  recipient BYTEA PRIMARY KEY,
  addr      TEXT  NOT NULL
);
`;
