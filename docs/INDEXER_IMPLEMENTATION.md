# FIN-029 — Stateful indexer: implementation spec (DB schema + API contract)

Detailed build spec for the stateful, always-on indexer service that FIN-029
introduces. The **ticket** (motivation, the `UnknownAnchorRoot` #10 root cause, the
multi-party argument, priority) lives in [`TASK.md` → FIN-029](./TASK.md); this
document is the **how**: the data model, the ingestion worker, and the HTTP API
contract the frontend consumes. Read `ARCHITECTURE.md` → "Backend" for the tier's
place in the system and `docs/PUBLIC_IO.md` for field-layout context.

> Scope: replace the demo's stateless RPC-replay indexer (`frontend/lib/indexer.ts`)
> with a service that persists the full commitment tree from genesis, so any client —
> on any device, at any time — can fetch a correct inclusion path + an in-window
> anchor root. **Non-goals:** the relayer (stays FIN-019), and cross-party
> recipient-ciphertext key agreement (FIN-027 "Known gap" — the indexer serves the
> ciphertexts but cannot recover the `c_recipient` key).

---

## 1. Design principles (read first)

1. **The indexer is UNTRUSTED.** It serves Merkle paths and roots, but the only
   integrity guarantee is the on-chain Groth16 proof. A wrong/malicious path produces
   an *invalid proof* the contract rejects — never a loss of funds. This is why the
   service can be a plain public read cache with no auth on reads.
2. **Public data only (invariant #8).** The indexer ingests and serves commitments,
   nullifiers, roots, and field-packed ciphertexts — all already public on-chain. It
   never sees or stores `owner_sk` / `k_view` / note plaintext. Centralizing it does
   not weaken confidentiality.
3. **Off-chain hashing, on-chain none (invariant #11).** The contract stores only the
   frontier + root and does no hashing. The indexer *does* hash (to build Merkle
   paths) using the **same Poseidon-BLS** as the circuit and SDK (`@finnes/sdk`,
   parity is a CI gate). It must reuse the SDK, never reimplement Poseidon.
4. **Per-effect self-check.** Every leaf-bearing contract event carries `new_root`
   (see §3). After applying each effect the worker asserts
   `computed_tree_root == event.new_root`; a mismatch halts ingestion and alarms
   (it means leaf ordering drifted). This makes the indexer's tree provably equal to
   the contract's, not "best effort".
5. **Anchor to `latest`.** The contract accepts any anchor root within its
   recent-roots window (`recent_roots_capacity()` = 64). The client should always
   anchor a spend to the indexer's *latest* root (always in-window) and fetch the
   path + anchor atomically right before proving.

---

## 2. Architecture

```
            Soroban Testnet (contract CD3AO6XD… ; redeploy fresh for genesis)
                       │  getEvents (RPC)            │  current_root / leaf_count (cross-check)
                       ▼                              ▼
   ┌─────────────────────────────────────────────────────────┐
   │  INDEXER SERVICE (Railway; no VPS)                        │
   │   ┌───────────────┐      ┌──────────────────────────┐    │
   │   │ ingest worker │ ───▶ │ Postgres (durable state) │    │
   │   │  backfill+tail│      │ leaves/roots/nf/ct/tx/…   │    │
   │   └───────────────┘      └──────────────────────────┘    │
   │   ┌───────────────┐              ▲                        │
   │   │  HTTP API     │ ─────────────┘ (reads)                │
   │   └───────────────┘                                       │
   └───────────────────────────────────────────────────────────┘
                       │  /path /roots /transactions /frozen … (CORS, public)
                       ▼
                 Frontend (many clients / devices)
```

Two logical components, deployable as **one Node process** (Express server + a
`setInterval` worker) for the demo, or split into a `web` + `worker` service later;
both share the one Postgres. Reuse the existing decode/tree logic from
`frontend/lib/indexer.ts` (move server-side, make it stateful) and the SDK
(`IncrementalMerkleTree`, `commitNote`, `K_A`, `K_R`, `TREE_DEPTH`).

### Repository layout

The indexer is a new **top-level workspace `indexer/`** — a sibling of `sdk/` /
`prover/` / `frontend/`, registered in the root `package.json` `workspaces`. It depends
on `@finnes/sdk` (Poseidon/Merkle parity) and deploys independently (Railway), so it
follows the same package convention as the others (ESM, `tsc -b` → `dist/`, a project
reference to `../sdk`).

```
indexer/
  package.json          @finnes/indexer (deps: @finnes/sdk, @stellar/stellar-sdk, express, pg)
  tsconfig.json         extends ../tsconfig.base.json; references ../sdk
  src/
    config.ts encoding.ts stellar.ts
    db/{schema,client,migrate,repo}.ts
    ingest/{decode,tree,worker}.ts
    api/server.ts
    index.ts
  README.md
```

Root scripts: `npm run indexer:dev | indexer:start | indexer:build | indexer:migrate`
(the pre-existing `indexer:verify:live` is a separate one-shot live-check script,
unrelated to this service).

---

## 3. Contract event catalog (the ingestion source of truth)

Topics are single short symbols (`events.rs`). All 32-byte values are `BytesN<32>`;
ciphertexts are `Vec<BytesN<32>>` of length `K_A`/`K_R` (= 5). Leaf-bearing effects
into the **main** tree advance `leaf_count`; `escrowdep` feeds the **escrow** tree.

| Topic (symbol) | Source fn | Payload fields | Leaves (tree) | Ciphertexts |
|---|---|---|---|---|
| `shield` | `shield` | `asset_id, amount, cm_out, new_root, c_auditor[5], c_recipient[5]` | +1 `cm_out` (main) | 1 note |
| `transfer` | `confidential_transfer` | `nf_in_0, nf_in_1, cm_out_0, cm_out_1, new_root, c_auditor[10], c_recipient[10]` | +2 (main) | 2 notes (slice `K_A`-wide) |
| `unshield` | `unshield` | `nf_in_0, asset_id, amount, recipient, cm_change_0, new_root, c_auditor[5], c_recipient[5]` | +1 if `cm_change_0≠0` else +0 (main) | 1 note iff change |
| `recovery` | `mint_recovery`/`clawback` | `cm_out, new_root` | +1 (main) | none |
| `freeze` | `freeze` | `cm_target, new_frozen_root` | — | — |
| `rootupd` | admin root update | `kind: Symbol, new_root` | — | — |
| `regasset` | `register_asset` | `asset_id, sac: Address` | — | — |
| `regtrans` | `register_transparent` | `recipient, addr: Address` | — | — |
| `dvp` | `settle_dvp` (demo) | `nf_leg_x_0, nf_leg_y_0, cm_out_x, cm_out_y, new_root` | +2 (main) | **none** (disclosure gap, see §11) |
| `intent` | `create_intent` | tuple `(intent_id, deadline)` | — | — |
| `escrowdep` | `escrow_deposit` | tuple `(intent_id, nf_in_0, cm_out, new_root, c_auditor[5], c_recipient[5])` | +1 (**escrow**) | 1 note |
| `settled` | `settle_intent` | tuple `(intent_id, nf_x, nf_y, cm_out_x, cm_out_y, new_root)` | +2 (main) | none |
| `refunded` | `escrow_refund` | tuple `(intent_id, nf_in_0, cm_out, new_root, c_auditor[5], c_recipient[5])` | +1 (main) | 1 note |

Decoding: `scValToNative` (Stellar SDK) yields named objects for `#[contracttype]`
structs and positional arrays for the escrow tuples. The current frontend only
handles `shield`/`transfer`/`unshield`/`recovery`/`freeze`; the service must handle
all leaf-bearing topics (shield/transfer/unshield/recovery/dvp/settled/refunded →
main, escrowdep → escrow) to stay correct once DvP/escrow go live.

**Read views for cross-check** (`lib.rs`): `current_root() → Option<BytesN<32>>`,
`current_frontier() → Option<Vec<BytesN<32>>>` (length `TREE_DEPTH`=20),
`leaf_count() → u64`, `recent_roots_capacity() → u32` (=64),
`is_nullifier_used(nf) → bool`. The worker calls these to reconcile (§5).

---

## 4. Database schema (PostgreSQL)

All field-element columns are `BYTEA` of exactly 32 bytes (raw, not hex — hex is an
API-boundary concern, §7). `tree`: `0`=main, `1`=escrow. Natural-key uniqueness makes
every insert idempotent (`ON CONFLICT DO NOTHING`), so re-ingesting an event (restart,
overlap, mild reorg) is a no-op.

```sql
-- Ingestion checkpoint (one row; supports multiple contracts if ever needed).
CREATE TABLE sync_state (
  contract_id   TEXT PRIMARY KEY,
  start_ledger  BIGINT      NOT NULL,            -- contract deploy ledger (genesis)
  last_cursor   TEXT,                            -- Soroban getEvents pagination cursor
  last_ledger   BIGINT      NOT NULL DEFAULT 0,  -- highest ledger fully ingested
  backfilled    BOOLEAN     NOT NULL DEFAULT FALSE,
  head_root     BYTEA,                           -- last computed root (per main tree)
  head_count    BIGINT      NOT NULL DEFAULT 0,  -- main-tree leaf count
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Every commitment inserted into a tree, in canonical leaf order.
CREATE TABLE leaves (
  tree         SMALLINT    NOT NULL,
  leaf_index   BIGINT      NOT NULL,
  commitment   BYTEA       NOT NULL,             -- 32 bytes (Poseidon, globally unique)
  tx_hash      TEXT        NOT NULL,
  ledger       BIGINT      NOT NULL,
  topic        TEXT        NOT NULL,             -- shield/transfer/unshield/...
  output_pos   SMALLINT    NOT NULL,             -- which output within the tx (0/1)
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tree, leaf_index),
  UNIQUE (commitment)
);
CREATE INDEX leaves_commitment_idx ON leaves (commitment);

-- Recent roots the contract has held (the anchor window). One row per effect,
-- even a 0-insert unshield (which re-publishes the current root) — mirrors the
-- contract's recent-roots ring exactly.
CREATE TABLE roots (
  tree        SMALLINT NOT NULL,
  seq         BIGINT   NOT NULL,                 -- monotonic effect order per tree
  root        BYTEA    NOT NULL,                 -- = event.new_root
  leaf_count  BIGINT   NOT NULL,                 -- tree size AFTER this effect
  tx_hash     TEXT     NOT NULL,
  ledger      BIGINT   NOT NULL,
  PRIMARY KEY (tree, seq)
);
CREATE INDEX roots_recent_idx ON roots (tree, seq DESC);
CREATE INDEX roots_value_idx  ON roots (tree, root);

-- Spent-input nullifiers (existence = spent).
CREATE TABLE nullifiers (
  nullifier  BYTEA       PRIMARY KEY,            -- 32 bytes
  tx_hash    TEXT        NOT NULL,
  ledger     BIGINT      NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-output-note ciphertexts (recipient scan + regulator disclosure).
CREATE TABLE ciphertexts (
  tx_hash      TEXT     NOT NULL,
  output_index SMALLINT NOT NULL,                -- 0/1 within the tx
  commitment   BYTEA    NOT NULL,                -- links to leaves.commitment
  circuit      TEXT     NOT NULL,
  ledger       BIGINT   NOT NULL,
  c_auditor    BYTEA[]  NOT NULL,                -- K_A=5 slots, each 32 bytes
  c_recipient  BYTEA[]  NOT NULL,                -- K_R=5 slots
  PRIMARY KEY (tx_hash, output_index)
);
CREATE INDEX ciphertexts_commitment_idx ON ciphertexts (commitment);
CREATE INDEX ciphertexts_ledger_idx     ON ciphertexts (ledger);

-- Regulator transaction ledger (one row per value-bearing effect).
CREATE TABLE transactions (
  tx_hash          TEXT        PRIMARY KEY,
  seq              BIGINT      NOT NULL,         -- global effect order (newest = max)
  circuit          TEXT        NOT NULL,         -- shield/transfer/unshield/dvp/...
  ledger           BIGINT      NOT NULL,
  closed_at        TIMESTAMPTZ NOT NULL,
  nullifiers       BYTEA[]     NOT NULL DEFAULT '{}',
  reveal_asset_id  BYTEA,                        -- unshield public reveal (else NULL)
  reveal_amount    BYTEA,
  reveal_recipient BYTEA
);
CREATE INDEX transactions_seq_idx ON transactions (seq DESC);

-- Issuer frozen set (clawback). The latest frozen_root is the max(seq) row.
CREATE TABLE frozen (
  commitment  BYTEA  PRIMARY KEY,                -- 32 bytes
  frozen_root BYTEA  NOT NULL,                   -- frozen_root AFTER this freeze
  tx_hash     TEXT   NOT NULL,
  ledger      BIGINT NOT NULL,
  seq         BIGINT NOT NULL
);

-- Compliance-root history (kyc/sanction/assets/frozen) from `rootupd`.
CREATE TABLE compliance_roots (
  id      BIGSERIAL PRIMARY KEY,
  kind    TEXT   NOT NULL,                       -- 'kyc'|'sanction'|'assets'|'frozen'
  root    BYTEA  NOT NULL,
  tx_hash TEXT   NOT NULL,
  ledger  BIGINT NOT NULL
);
CREATE INDEX compliance_roots_kind_idx ON compliance_roots (kind, id DESC);

-- FIN-010 registry mirrors (link field-encoded ids to concrete on-chain addresses).
CREATE TABLE asset_registry       (asset_id  BYTEA PRIMARY KEY, sac  TEXT NOT NULL); -- C… StrKey
CREATE TABLE transparent_registry (recipient BYTEA PRIMARY KEY, addr TEXT NOT NULL); -- G… StrKey

-- OPTIONAL (scale): persisted internal Merkle nodes for O(depth) path serving
-- instead of rebuilding the tree. Skip for the demo; add if leaf_count gets large.
CREATE TABLE nodes (
  tree  SMALLINT NOT NULL,
  level SMALLINT NOT NULL,                       -- 0 = leaves … TREE_DEPTH = root
  idx   BIGINT   NOT NULL,
  hash  BYTEA    NOT NULL,
  PRIMARY KEY (tree, level, idx)
);
```

Why this shape:
- **`leaves` is the canonical tree.** `leaf_index` is the order; the tree (and every
  path) is a pure function of it. `UNIQUE(commitment)` lets `/commitment/:cm` resolve
  a note to its leaf (replacing the demo's `commitments.indexOf`).
- **`roots` mirrors the contract's ring**, including 0-insert duplicates, so
  `is_recent_root` semantics can be answered exactly.
- **`ciphertexts` keyed by `(tx_hash, output_index)`** matches the on-chain slicing
  (`K_A`-wide per output) and links to a leaf by `commitment`.
- **Idempotent by construction** — safe to re-run backfill or overlap tail pages.

---

## 5. Ingestion worker

**Backfill (once):** from `sync_state.start_ledger` (the contract's deploy ledger),
page `getEvents` forward (reuse the cursor-following loop in
`frontend/lib/indexer.ts:64-94` — never break on an empty page). For each event in
ledger order: decode (§3), then in a single DB transaction insert the derived rows
(leaves, a `roots` row, nullifiers, ciphertexts, a `transactions` row, frozen,
registry). Maintain an **in-memory `IncrementalMerkleTree`** (from `@finnes/sdk`);
after each leaf-bearing effect assert `tree.root() === event.new_root` — **halt + alarm
on mismatch** (principle #4). Set `backfilled=true` when caught up to `latest`.

**Tail (continuous):** every ~2–5 s, `getEvents` from `last_cursor`, process the same
way, advance the cursor + `last_ledger`. Optionally lag a few ledgers behind `latest`
for finality (Soroban testnet has fast finality, so a small buffer or none is fine for
the demo; a production indexer should add rollback-on-reorg keyed by `(ledger, tx_hash)`).

**Reconciliation (periodic):** call `current_root()` / `leaf_count()` and assert they
equal the indexer head (`sync_state.head_root` / `head_count`). Surface the result in
`/v1/health` and `/v1/state` (`computedRootMatchesChain`). This is the multi-party
equivalent of the demo's one-shot `verify-indexer-live` check, run continuously.

**Path serving:** keep the in-memory tree hot for `/path`/`/paths`; on cold start,
rebuild it from `leaves` (O(n) once) or, at scale, from the `nodes` table (O(depth)
per path). For D=20 (≤ ~1M leaves) an in-memory tree is adequate; `nodes` is the
escape hatch.

---

## 6. HTTP API contract

Base path `/v1`. Read-only, public, **CORS enabled** (snarkjs/browser clients).
JSON responses. Errors: `{ "error": { "code": string, "message": string } }` with
HTTP `400` (bad params), `404` (unknown leaf/commitment/nullifier), `409` (still
backfilling — client should retry/fall back), `503` (indexer behind chain). Encoding
conventions in §7.

### `GET /v1/health`
Liveness + sync status.
```json
{ "ok": true, "contractId": "CD3AO6XD…", "backfilled": true,
  "lastLedger": 3326010, "latestLedger": 3326074, "lagLedgers": 64,
  "tree": { "leafCount": 23, "root": "4e35b2b1…" },
  "chain": { "root": "4e35b2b1…", "leafCount": 23, "matches": true } }
```

### `GET /v1/state?tree=main`
Authoritative append anchor + cross-check (for `shield` and sanity).
```json
{ "tree": "main", "leafCount": 23, "root": "4e35b2b1…",
  "frontier": ["…", "… (20 hex elems)"],
  "recentRootsCapacity": 64,
  "chainRoot": "4e35b2b1…", "computedRootMatchesChain": true }
```

### `GET /v1/roots?tree=main&limit=64`
The recent-roots window, newest first. A client anchors to `roots[0].root` (`latest`).
```json
{ "tree": "main", "latest": "4e35b2b1…",
  "roots": [ { "root": "4e35b2b1…", "leafCount": 23, "ledger": 3326010, "txHash": "…" }, … ] }
```

### `GET /v1/leaves?tree=main&from=0&limit=1000`
Raw commitments in leaf order (client-side rebuild / verification; paginated).
```json
{ "tree": "main", "leafCount": 23, "from": 0, "leaves": ["…","… hex"] }
```

### `GET /v1/commitment/:cm?tree=main`
Resolve a commitment to its leaf index (replaces `commitments.indexOf`). `404` if
unknown.
```json
{ "tree": "main", "commitment": "577c94d2…", "leafIndex": 7 }
```

### `GET /v1/path/:leafIndex?tree=main&anchor=latest`
Inclusion path for one leaf, against `anchor` (`latest` | a specific root hex). Shape
matches the SDK `IncrementalMerkleTree.inclusionPath` (siblings + pathBits, LSB =
level 0) so the witness builder consumes it directly.
```json
{ "tree": "main", "leafIndex": 7, "commitment": "577c94d2…",
  "siblings": ["… × TREE_DEPTH (20) hex"],
  "pathBits": [0,1,0, "… × 20 (0|1)"],
  "anchorRoot": "4e35b2b1…", "leafCount": 23 }
```

### `POST /v1/paths`
**Batch — required for multi-input spends.** A 2-in `transfer` (and `dvp`) must prove
both inputs against the **same** `anchor_root`; this endpoint guarantees one
consistent anchor for all requested leaves (a per-leaf `GET /path` race could straddle
a new insert and mix anchors).
```jsonc
// request
{ "tree": "main", "leafIndices": [7, 12], "anchor": "latest" }
// response
{ "tree": "main", "anchorRoot": "4e35b2b1…", "leafCount": 23,
  "paths": [ { "leafIndex": 7,  "commitment": "…", "siblings": ["…×20"], "pathBits": [/*20*/] },
             { "leafIndex": 12, "commitment": "…", "siblings": ["…×20"], "pathBits": [/*20*/] } ] }
```

### `GET /v1/nullifier/:nf`
Spent check (faster than the RPC `is_nullifier_used`; the contract remains the
authority at submit time).
```json
{ "nullifier": "126ef193…", "used": true, "txHash": "f8e47f81…" }
```

### `GET /v1/transactions?limit=50&before=<seq>`
Regulator ledger, newest first, cursor-paginated by `seq`.
```json
{ "transactions": [
    { "txHash": "bf6f54f0…", "seq": 19, "circuit": "transfer",
      "ledger": 3320001, "closedAt": "2026-06-20T…Z",
      "nullifiers": ["73bd4f2f…","4b7d8246…"],
      "outputs": [ { "commitment": "283af76c…", "cAuditor": ["… × 5"] },
                   { "commitment": "4340d50a…", "cAuditor": ["… × 5"] } ] },
    { "txHash": "f8e47f81…", "seq": 21, "circuit": "unshield",
      "nullifiers": ["126ef193…"], "outputs": [],
      "publicReveal": { "assetId": "555840ea…", "amount": "500", "recipient": "480b9681…" } }
  ],
  "nextBefore": 14 }
```
`outputs` carries the mandatory `c_auditor` for the regulator to decrypt with
`k_view` (via the SDK `discloseTransaction`); `publicReveal` is present only for
`unshield`. (`dvp`/`settled` have no ciphertexts on-chain — §11.)

### `GET /v1/ciphertexts?since=<seq>&limit=500`
Stream of per-output ciphertexts for wallet scanning (recipient discovery) and audit.
```json
{ "items": [ { "txHash": "…", "outputIndex": 0, "commitment": "…", "circuit": "transfer",
               "ledger": 3320001, "cAuditor": ["…×5"], "cRecipient": ["…×5"] } ],
  "next": 4201 }
```

### `GET /v1/frozen`
Issuer frozen set + current `frozen_root` (for spend-time frozen non-membership).
```json
{ "frozenRoot": "00…00", "frozen": ["…","…"] }
```

### `GET /v1/registry/asset/:assetId` · `GET /v1/registry/transparent/:recipient`
Link a field id to its concrete on-chain address (and `…/asset` / `…/transparent`
list forms).
```json
{ "assetId": "555840ea…", "sac": "CBJMD3SA…" }
{ "recipient": "480b9681…", "addr": "GCC3JWQSF…" }
```

---

## 7. Encoding conventions

- **32-byte field values** (commitment, root, nullifier, asset_id, recipient,
  ciphertext slot): **lowercase hex, 64 chars, no `0x`** — matches the frontend's
  existing `toBig(hex)` and `liveNoteNullifier` (`toString(16).padStart(64,'0')`).
- **`amount`** (unshield reveal): a field, but value `< 2^64`; return as a **decimal
  string** of raw SAC units (display-only scaling stays in the SDK, invariant #16).
- **Addresses** (`sac`, transparent `addr`): Stellar StrKey strings (`C…`/`G…`), as
  decoded by `scValToNative`.
- **`pathBits`**: array of `0|1` numbers, LSB = level 0 (`0` = node is a left child).
- **`leafIndex` / `leafCount` / `ledger` / `seq`**: JSON integers.

---

## 8. Frontend rewire

Add one config switch and route the read paths through the API, keeping the current
RPC implementation as a fallback when no indexer URL is set.

- **`frontend/lib/config.ts`**: `export const INDEXER_URL = env('NEXT_PUBLIC_INDEXER_URL', '')`.
- **`frontend/lib/indexer.ts`**: when `INDEXER_URL` is set,
  `buildChainTree`/`fetchLiveCommitments` → `GET /v1/leaves` (or skip the tree and use
  `/paths` directly), `indexTransactions` → `GET /v1/transactions`, `indexFrozen` →
  `GET /v1/frozen`. Keep the RPC bodies as the `else` fallback (and for local dev with
  no indexer). The `bridgeAgedOutPrefix` seed hack is then dead code — remove it once
  the API is the default.
- **`frontend/lib/write-flow.ts`**:
  - `spendableNotes` (`:152`): resolve each owned note's leaf via `GET /v1/commitment/:cm`
    instead of `chain.commitments.indexOf(...)`, and check spent via `GET /v1/nullifier/:nf`
    (or keep the on-chain `isNullifierUsed` for authority).
  - `runTransfer` (`:308`): fetch both inclusion paths + the single anchor via
    `POST /v1/paths { leafIndices:[in0,in1], anchor:"latest" }`; feed `siblings`/`pathBits`
    into `buildTransferWitness` and set `anchorRoot` to the response's `anchorRoot`.
  - `runUnshield` (`:240`): `GET /v1/path/:leaf` for the single input; same anchor wiring.
  - `doShield` (`:176`): **unchanged** — keep `readTreeState()` (the contract's
    `current_frontier`/`leaf_count` is the authoritative append anchor; shield needs no
    inclusion path). `/v1/state` is only a cross-check.
- **Invariant preserved:** the witness still anchors to a contract-recognized root; the
  difference is the path now comes from a complete persistent tree, so it is correct
  regardless of RPC retention → no more `UnknownAnchorRoot` (#10).

---

## 9. Deployment (Railway — no VPS)

- **Service**: a Node/TS app (reuse `@finnes/sdk`). One process running both the
  Express API and the `setInterval` ingest worker is fine for the demo; split into
  `web` + `worker` services sharing the DB if the worker's polling starves request
  latency.
- **Database**: Railway Postgres plugin → `DATABASE_URL`. Run the §4 DDL as a migration
  on boot (e.g. `node-pg-migrate` or a plain `CREATE TABLE IF NOT EXISTS` bootstrap).
- **Env**: `CONTRACT_ID`, `RPC_URL` (`https://soroban-testnet.stellar.org`),
  `START_LEDGER` (the deploy ledger of the fresh contract), `DATABASE_URL`, `PORT`,
  `FINALITY_LAG` (e.g. `0`–`5`).
- **Healthcheck**: `GET /v1/health` (Railway healthcheck path).
- **Domain**: `generate_domain` → set the frontend's `NEXT_PUBLIC_INDEXER_URL` to it.
- Lives in the **same Railway project** as the `ceremony` container — no new VPS, no
  new vendor.

---

## 10. Phasing & acceptance

Pair with a **fresh contract redeploy** (the current `CD3AO6XD…` has ~23 leaves whose
events aged out of RPC and cannot be fully recovered; start the indexer from a fresh
deploy's genesis ledger, or backfill from Horizon transaction history — heavier).

- **Phase A — schema + worker + backfill.** DDL applied; backfill from genesis with
  the per-effect `computed_root == event.new_root` assertion green; `sync_state` head
  equals `current_root()`/`leaf_count()`. *Verifiable:* `/v1/health.chain.matches == true`.
- **Phase B — API.** All §6 endpoints. *Verifiable:* a `/v1/path` response verifies via
  the SDK `verifyInclusionPath` against `/v1/roots.latest`, for every leaf.
- **Phase C — frontend rewire.** Config switch + write-flow/indexer routed to the API.
  *Verifiable (the FIN-029 acceptance):* a `confidential_transfer` and an `unshield`
  built from indexer-served paths + a recent root **verify on-chain with no #10**,
  even after the early leaves have aged out of RPC; two different browsers read the same
  complete tree.
- **Phase D — hardening.** Continuous reconciliation + alerting, finality/reorg
  handling, rate limiting, ciphertext retention policy, optional `nodes` table for
  large-tree path serving.

---

## 11. Open questions / decisions

1. **One process vs two** (web+worker). Recommend one for the demo, split if request
   latency suffers.
2. **Finality lag / reorg.** Soroban testnet is fast-final; start with `FINALITY_LAG=0`
   and idempotent upserts. Production: lag a few ledgers + rollback-by-ledger on reorg.
3. **DvP/escrow disclosure gap.** `dvp`/`settled` events carry **no ciphertexts**
   (`events.rs` `DvpEvent`/`settled`), yet their swap outputs have a mandatory
   `c_auditor` on-chain (invariant #5). The regulator therefore cannot decrypt
   DvP/settle outputs from events alone. This is a **contract-event** gap (add the
   ciphertext vectors to those events), not an indexer gap — track it when DvP/escrow
   go live (FIN-016/017). Until then the indexer simply records their leaves +
   nullifiers.
4. **Auth / rate limiting.** Reads are public (untrusted-indexer principle), so no
   auth; add basic rate limiting + caching headers (immutable `/path` per
   `(leafIndex, anchorRoot)`; short-TTL `/roots`/`/state`).
5. **Multi-contract.** `sync_state` is keyed by `contract_id` to allow re-pointing at a
   new deployment without wiping (each redeploy = a new genesis).
6. **Cross-party recipient scan** remains blocked on an on-chain-recoverable
   `c_recipient` key (FIN-027 "Known gap"); the indexer serves the ciphertexts but
   cannot close the key-agreement gap on its own.
```
