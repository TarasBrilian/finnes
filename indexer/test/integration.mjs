/**
 * Integration test for @finnes/indexer (FIN-029): drives the REAL built modules
 * (decode → worker.processEffect → Postgres → Express API) against a throwaway
 * Postgres, with SDK-computed commitments/roots so the per-effect root self-check
 * is exercised end-to-end. Run via `node indexer/test/integration.mjs` with
 * DATABASE_URL set (the harness in the verification step provides a disposable DB).
 *
 * Proves: schema applies; events decode; the in-memory tree matches the SDK; the
 * DB persists leaves/nullifiers/ciphertexts/txs/frozen; the API serves a Merkle
 * path that verifies against the served root; and a wrong new_root HALTS ingestion.
 */

import { IncrementalMerkleTree, TREE_DEPTH, commitNote, verifyInclusionPath } from '@finnes/sdk';

import { migrate } from '../dist/db/migrate.js';
import { pool } from '../dist/db/client.js';
import { boot, processEffect, isHalted } from '../dist/ingest/worker.js';
import { decodeEffect } from '../dist/ingest/decode.js';
import { createApp } from '../dist/api/server.js';
import { bigToBuf, bigToHex, toHex } from '../dist/encoding.js';

let failures = 0;
const ok = (label, cond) => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`);
  if (!cond) failures++;
};
const buf = (x) => Buffer.from(x);
const ct = (n) => Array.from({ length: 5 }, (_, i) => bigToBuf(BigInt(1000 * n + i + 1)));

// --- synthetic, SDK-consistent fixtures ------------------------------------
const ref = new IncrementalMerkleTree(TREE_DEPTH); // mirror to compute expected roots
const note = (v, sk) => ({ assetId: 777n, value: BigInt(v), ownerPk: BigInt(sk), rho: BigInt(v * 7 + 1), rNote: BigInt(v * 9 + 2) });

const cm0 = commitNote(note(1000, 1001));
ref.insert(cm0);
const rootAfterShield = ref.root();

const cm1 = commitNote(note(600, 1002)); // transfer recipient
const cm2 = commitNote(note(400, 1001)); // transfer change
ref.insert(cm1);
ref.insert(cm2);
const rootAfterTransfer = ref.root();

const nf0 = bigToBuf(0xaa01n);
const nf1 = bigToBuf(0xaa02n);
const nf2 = bigToBuf(0xaa03n);
const frozenRoot = bigToBuf(0xbeefn);

const events = [
  {
    topic: 'shield',
    txHash: 'tx_shield',
    ledger: 100,
    ledgerClosedAt: '2026-06-28T00:00:00Z',
    value: {
      asset_id: bigToBuf(777n),
      amount: bigToBuf(1000n),
      cm_out: bigToBuf(cm0),
      new_root: bigToBuf(rootAfterShield),
      c_auditor: ct(0),
      c_recipient: ct(1),
    },
  },
  {
    topic: 'transfer',
    txHash: 'tx_transfer',
    ledger: 101,
    ledgerClosedAt: '2026-06-28T00:01:00Z',
    value: {
      nf_in_0: nf0,
      nf_in_1: nf1,
      cm_out_0: bigToBuf(cm1),
      cm_out_1: bigToBuf(cm2),
      new_root: bigToBuf(rootAfterTransfer),
      c_auditor: [...ct(2), ...ct(3)], // 10 slots → 2 outputs × 5
      c_recipient: [...ct(4), ...ct(5)],
    },
  },
  {
    topic: 'unshield',
    txHash: 'tx_unshield',
    ledger: 102,
    ledgerClosedAt: '2026-06-28T00:02:00Z',
    value: {
      nf_in_0: nf2,
      asset_id: bigToBuf(777n),
      amount: bigToBuf(250n),
      recipient: bigToBuf(0x480b9681n),
      cm_change_0: bigToBuf(0n), // exact-spend sentinel → 0 inserts
      new_root: bigToBuf(rootAfterTransfer), // unchanged
      c_auditor: ct(6),
      c_recipient: ct(7),
    },
  },
  {
    topic: 'freeze',
    txHash: 'tx_freeze',
    ledger: 103,
    ledgerClosedAt: '2026-06-28T00:03:00Z',
    value: { cm_target: bigToBuf(cm1), new_frozen_root: frozenRoot },
  },
];

const PORT = 8099;
const base = `http://localhost:${PORT}`;
const get = async (p) => (await fetch(base + p)).json();

async function main() {
  await migrate();
  ok('schema applied (migrate)', true);

  await boot(); // fresh DB → empty trees
  for (const e of events) {
    const rec = decodeEffect(e);
    await processEffect(rec);
  }
  ok('ingested 4 effects without halting', !isHalted());

  const app = createApp();
  const srv = app.listen(PORT);
  await new Promise((r) => setTimeout(r, 300));

  // --- API correctness ----------------------------------------------------
  const health = await get('/v1/health');
  ok('health.ok', health.ok === true);
  ok('health tree.leafCount == 3', health.tree.leafCount === 3);
  ok('health root == SDK rootAfterTransfer', health.tree.root === bigToHex(rootAfterTransfer));

  const state = await get('/v1/state?tree=main');
  ok('state frontier length == TREE_DEPTH', Array.isArray(state.frontier) && state.frontier.length === TREE_DEPTH);
  ok('state root == SDK root', state.root === bigToHex(rootAfterTransfer));

  const roots = await get('/v1/roots');
  ok('roots.latest == SDK root', roots.latest === bigToHex(rootAfterTransfer));
  ok('roots window has >= 3 entries', roots.roots.length >= 3);

  // The headline: a served path must verify against the served root via the SDK.
  const path0 = await get('/v1/path/0');
  const siblings0 = path0.siblings.map((h) => BigInt('0x' + h));
  const verified0 = verifyInclusionPath(cm0, { siblings: siblings0, pathBits: path0.pathBits }, rootAfterTransfer);
  ok('path/0 siblings length == TREE_DEPTH', path0.siblings.length === TREE_DEPTH);
  ok('path/0 verifies against root via SDK verifyInclusionPath', verified0 === true);
  ok('path/0 anchorRoot == SDK root', path0.anchorRoot === bigToHex(rootAfterTransfer));

  const path2 = await get('/v1/path/2');
  const verified2 = verifyInclusionPath(
    cm2,
    { siblings: path2.siblings.map((h) => BigInt('0x' + h)), pathBits: path2.pathBits },
    rootAfterTransfer,
  );
  ok('path/2 (change note) verifies via SDK', verified2 === true);

  // Batch paths share ONE anchor (the transfer 2-input requirement).
  const batch = await (await fetch(base + '/v1/paths', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tree: 'main', leafIndices: [0, 1] }),
  })).json();
  ok('paths batch returns 2 paths with one anchor', batch.paths.length === 2 && typeof batch.anchorRoot === 'string');

  const byCm = await get('/v1/commitment/' + toHex(bigToBuf(cm1)));
  ok('commitment lookup → leafIndex 1', byCm.leafIndex === 1);

  const cm404 = await (await fetch(base + '/v1/commitment/' + 'de'.repeat(32))).status;
  ok('unknown commitment → 404', cm404 === 404);

  const nf = await get('/v1/nullifier/' + toHex(nf0));
  ok('nullifier nf0 used == true', nf.used === true);
  const nfUnused = await get('/v1/nullifier/' + 'ab'.repeat(32));
  ok('unused nullifier used == false', nfUnused.used === false);

  const txs = await get('/v1/transactions');
  ok('transactions: 3 value-bearing effects', txs.transactions.length === 3);
  const tTransfer = txs.transactions.find((t) => t.circuit === 'transfer');
  ok('transfer tx has 2 outputs', tTransfer && tTransfer.outputs.length === 2);
  ok('transfer output cAuditor has 5 slots', tTransfer && tTransfer.outputs[0].cAuditor.length === 5);
  ok('transfer tx has 2 nullifiers', tTransfer && tTransfer.nullifiers.length === 2);
  const tUnshield = txs.transactions.find((t) => t.circuit === 'unshield');
  ok('unshield exposes publicReveal.amount == 250', tUnshield && tUnshield.publicReveal && tUnshield.publicReveal.amount === '250');
  ok('unshield (exact spend) has 0 confidential outputs', tUnshield && tUnshield.outputs.length === 0);

  const cts = await get('/v1/ciphertexts?since=0&limit=100');
  ok('ciphertexts: 3 output notes (shield 1 + transfer 2)', cts.items.length === 3);

  const frozen = await get('/v1/frozen');
  ok('frozen set contains cm1', frozen.frozen.includes(toHex(bigToBuf(cm1))));
  ok('frozenRoot == event new_frozen_root', frozen.frozenRoot === toHex(frozenRoot));

  // --- DB persistence cross-check -----------------------------------------
  const leafCount = (await pool.query('SELECT count(*)::int AS n FROM leaves')).rows[0].n;
  ok('DB leaves table has 3 rows', leafCount === 3);
  const ctCount = (await pool.query('SELECT count(*)::int AS n FROM ciphertexts')).rows[0].n;
  ok('DB ciphertexts table has 3 rows', ctCount === 3);

  // --- idempotency: re-ingest the same events → no change ------------------
  for (const e of events) await processEffect(decodeEffect(e));
  const leafCount2 = (await pool.query('SELECT count(*)::int AS n FROM leaves')).rows[0].n;
  ok('re-ingest is idempotent (still 3 leaves)', leafCount2 === 3);

  // --- self-check HALT on a wrong new_root (last; it halts the worker) -----
  const badEvent = {
    topic: 'shield',
    txHash: 'tx_bad',
    ledger: 104,
    ledgerClosedAt: '2026-06-28T00:04:00Z',
    value: {
      asset_id: bigToBuf(777n),
      amount: bigToBuf(1n),
      cm_out: bigToBuf(commitNote(note(1, 1003))),
      new_root: bigToBuf(0xdeadn), // WRONG → must trip the self-check
      c_auditor: ct(8),
      c_recipient: ct(9),
    },
  };
  let threw = false;
  try {
    await processEffect(decodeEffect(badEvent));
  } catch {
    threw = true;
  }
  ok('wrong new_root throws (self-check)', threw === true);
  ok('worker is halted after self-check failure', isHalted() === true);
  ok('health.ok becomes false after halt', (await get('/v1/health')).ok === false);

  srv.close();
  await pool.end();
  console.log(`\n${failures === 0 ? 'ALL PASS' : failures + ' FAILURE(S)'}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('integration test error:', e);
  process.exit(1);
});
