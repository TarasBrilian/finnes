# @finnes/indexer

Stateful indexer + HTTP API for Finnes (**FIN-029**). It persists the on-chain
commitment tree from genesis so any client — on any device, at any time — can fetch
a correct Merkle **inclusion path** and an **in-window anchor root**, which is the
root-cause fix for the `UnknownAnchorRoot` (#10) the write-path hits once the
contract's tree grows past the demo seed and early leaves age out of Soroban RPC's
~22h event retention.

Full design: [`../docs/INDEXER_IMPLEMENTATION.md`](../docs/INDEXER_IMPLEMENTATION.md).
Ticket: [`../docs/TASK.md` → FIN-029](../docs/TASK.md).

## Properties

- **Untrusted.** The on-chain Groth16 proof is the only integrity guarantee — a wrong
  path just yields an invalid proof the contract rejects. So reads are public, no auth.
- **Public data only** (invariant #8): commitments, nullifiers, roots, ciphertexts. It
  never holds `owner_sk`/`k_view`/note plaintext.
- **Self-checking** (invariant #11/#13): the tree is rebuilt from event leaves using the
  SDK's Poseidon-BLS, and every effect's computed root is asserted equal to the event's
  `new_root`; a mismatch halts ingestion.

## Layout

```
src/
  config.ts          env (CONTRACT_ID, RPC_URL, START_LEDGER, DATABASE_URL, PORT)
  encoding.ts        hex / bigint / Buffer helpers (API uses 64-char hex, no 0x)
  stellar.ts         RPC: paginated getEvents + read-only simulate (cross-check)
  db/{schema,client,migrate,repo}.ts   PostgreSQL DDL + access layer
  ingest/decode.ts   contract event → normalized EffectRecord (events.rs layout)
  ingest/tree.ts     in-memory IncrementalMerkleTree (from @finnes/sdk) per tree
  ingest/worker.ts   backfill from genesis + tail loop + per-effect root self-check
  api/server.ts      Express endpoints (§6 of the spec)
  index.ts           boot: migrate → rebuild → serve → backfill → tail
```

## Run

Requires Node ≥ 20, a PostgreSQL `DATABASE_URL`, and the SDK built (the workspace
`tsc -b` builds `@finnes/sdk` first via a project reference).

```bash
# from the repo root
npm install
export DATABASE_URL=postgres://user:pass@host:5432/finnes
export CONTRACT_ID=CD3AO6XD...            # a FRESH redeploy (capture from genesis)
export START_LEDGER=<deploy ledger>       # genesis ledger of that contract

npm run indexer:migrate    # apply schema (also run automatically on boot)
npm run indexer:dev        # tsx watch (dev)
# or
npm run indexer:build && npm run indexer:start   # tsc -b → node dist/index.js
```

Health: `GET http://localhost:8080/v1/health`. See the spec §6 for the full API.

## Deploy (Railway — no VPS)

Same project as the `ceremony` container. Add a Postgres plugin (`DATABASE_URL`), set
`CONTRACT_ID` / `START_LEDGER` / `RPC_URL`, build command `npm ci && npm run indexer:build`,
start command `npm run indexer:start`, healthcheck `/v1/health`, generate a domain, and
point the frontend's `NEXT_PUBLIC_INDEXER_URL` at it.

> Pair with a **fresh contract redeploy**: the current `CD3AO6XD…` has ~23 leaves whose
> events aged out of RPC and cannot be recovered (the contract stores no leaves). Start
> the indexer from a fresh deploy's genesis ledger.
