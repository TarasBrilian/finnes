/**
 * Ingestion worker: backfill from genesis, then continuously tail. Per effect it
 * persists the derived rows, updates the in-memory tree, and — the core integrity
 * gate (INDEXER_IMPLEMENTATION §1.4) — asserts `tree.root() === event.new_root`.
 * A mismatch HALTS ingestion (it means leaf ordering drifted); the API keeps
 * serving the last consistent state and `/health` reports `ok:false`.
 *
 * Idempotent: leaves are skipped if already in the DB (so the in-memory tree,
 * rebuilt from the DB on boot, never double-counts on a resumed/overlapping page).
 */

import * as repo from '../db/repo.js';
import * as tree from './tree.js';
import { decodeEffect, type EffectRecord } from './decode.js';
import { fetchEventsPage, latestLedger } from '../stellar.js';
import { CONTRACT_ID, START_LEDGER, RETENTION_LEDGERS, POLL_INTERVAL_MS, TREE_MAIN, TREE_ESCROW } from '../config.js';
import { bufToBig } from '../encoding.js';

let halted = false;
let tailRunning = false;

export const isHalted = (): boolean => halted;

/** Rebuild the in-memory trees from persisted leaves (drift-proof on restart). */
export async function boot(): Promise<void> {
  await repo.ensureSyncState(CONTRACT_ID, START_LEDGER);
  for (const t of [TREE_MAIN, TREE_ESCROW]) {
    const leaves = await repo.getAllLeaves(t);
    for (const cm of leaves) tree.append(t, bufToBig(cm));
  }
  console.log(`[worker] boot: rebuilt main=${tree.size(TREE_MAIN)} escrow=${tree.size(TREE_ESCROW)} leaves`);
}

export async function processEffect(rec: EffectRecord): Promise<void> {
  const t = rec.tree;
  let added = false; // did this call append ≥1 NEW leaf at the tree head?
  for (let i = 0; i < rec.leaves.length; i++) {
    const cm = rec.leaves[i]!;
    if (await repo.leafExists(cm)) continue; // already indexed → already in the in-memory tree
    const leafIndex = tree.size(t);
    await repo.insertLeaf(t, leafIndex, cm, rec.txHash, rec.ledger, rec.topic, i);
    tree.append(t, bufToBig(cm));
    added = true;
  }
  if (rec.newRoot) await repo.insertRoot(t, rec.newRoot, tree.size(t), rec.txHash, rec.ledger);
  for (const nf of rec.nullifiers) await repo.insertNullifier(nf, rec.txHash, rec.ledger);
  for (const o of rec.outputs) {
    await repo.insertCiphertext(rec.txHash, o.outputIndex, o.commitment, rec.circuit, rec.ledger, o.cAuditor, o.cRecipient);
  }
  if (rec.isLedgerTx) {
    await repo.insertTransaction({
      txHash: rec.txHash,
      circuit: rec.circuit,
      ledger: rec.ledger,
      closedAt: rec.closedAt,
      nullifiers: rec.nullifiers,
      reveal: rec.reveal,
    });
  }
  if (rec.frozen) await repo.insertFrozen(rec.frozen.commitment, rec.frozen.frozenRoot, rec.txHash, rec.ledger);
  if (rec.complianceRoot) await repo.insertComplianceRoot(rec.complianceRoot.kind, rec.complianceRoot.root, rec.txHash, rec.ledger);
  if (rec.assetReg) await repo.upsertAssetRegistry(rec.assetReg.assetId, rec.assetReg.sac);
  if (rec.transparentReg) await repo.upsertTransparentRegistry(rec.transparentReg.recipient, rec.transparentReg.addr);

  // Integrity gate (only when this effect appended NEW leaves at the tree head):
  // the in-memory tree MUST equal the contract's published new_root. We skip it on
  // idempotent replay of a historical effect (its leaves are already in the tree, so
  // the now-advanced tree would not match that effect's old root — a false halt).
  // A 0-insert effect (exact-spend unshield) appends nothing, so there is no new
  // tree state to validate; its leaf-count/root are unchanged.
  if (rec.newRoot && added) {
    const computed = tree.rootBig(t);
    const expected = bufToBig(rec.newRoot);
    if (computed !== expected) {
      halted = true;
      const reason = `root mismatch at ${rec.topic} (tx ${rec.txHash}): computed ${computed.toString(16)} != event ${expected.toString(16)}`;
      await repo.setHalted(CONTRACT_ID, reason);
      throw new Error(`[worker] HALT — ${reason}`);
    }
    if (t === TREE_MAIN) await repo.setHead(CONTRACT_ID, rec.newRoot, tree.size(TREE_MAIN));
  }
}

/** One page of effects → DB + tree, advancing the cursor. Returns whether the
 *  cursor advanced (i.e. there may be more). */
async function ingestPage(cursor: string | undefined, fallbackStart: number): Promise<string | undefined> {
  const page = cursor ? await fetchEventsPage({ cursor }) : await fetchEventsPage({ startLedger: fallbackStart });
  for (const e of page.effects) {
    const rec = decodeEffect(e);
    if (rec) await processEffect(rec);
  }
  if (page.cursor && page.cursor !== cursor) {
    const last = page.effects.at(-1);
    await repo.setCursor(CONTRACT_ID, page.cursor, last ? last.ledger : 0);
    return page.cursor;
  }
  return undefined; // caught up
}

/** The ledger a getEvents paging token points at (TOID = ledger<<32 | …). Used to
 *  detect when the backfill has caught up to the chain tip and should hand off to
 *  the paced tail (the live `latestLedger` keeps advancing, so a cursor-only stall
 *  may never happen — bound it by the latest-at-start instead). */
function cursorLedger(cursor: string | undefined): number {
  if (!cursor) return Number.MAX_SAFE_INTEGER;
  try {
    const head = cursor.split('-')[0]!;
    return Number(BigInt(head) >> 32n);
  } catch {
    return 0;
  }
}

export async function backfill(): Promise<void> {
  const target = await latestLedger(); // catch up to here, then the paced tail takes over
  const st = await repo.getSyncState(CONTRACT_ID);
  let cursor = st?.last_cursor ?? undefined;
  let fallbackStart = 1;
  if (!cursor) {
    fallbackStart = START_LEDGER > 0 ? START_LEDGER : Math.max(1, target - RETENTION_LEDGERS);
    if (START_LEDGER <= 0) {
      console.warn(
        `[worker] START_LEDGER unset → backfill from ${fallbackStart} (latest-${RETENTION_LEDGERS}); ` +
          'correct only if the whole contract history is within RPC retention. Set START_LEDGER to the deploy ledger.',
      );
    }
  }
  let pages = 0;
  for (;;) {
    if (halted) return;
    const next = await ingestPage(cursor, fallbackStart);
    pages += 1;
    if (!next) break; // cursor stalled → fully caught up
    cursor = next;
    if (cursorLedger(next) >= target) break; // reached the tip-at-start → hand off to tail
    if (pages > 5000) break; // backstop against a runaway loop
  }
  await repo.setBackfilled(CONTRACT_ID);
  console.log(
    `[worker] backfill complete: main=${tree.size(TREE_MAIN)} leaves, root ${tree
      .rootBig(TREE_MAIN)
      .toString(16)
      .slice(0, 12)}… (caught up to ~ledger ${target})`,
  );
}

async function tick(): Promise<void> {
  if (halted || tailRunning) return;
  tailRunning = true;
  try {
    const st = await repo.getSyncState(CONTRACT_ID);
    const cursor = st?.last_cursor ?? undefined;
    await ingestPage(cursor, START_LEDGER > 0 ? START_LEDGER : 1);
  } catch (e) {
    console.error('[worker] tail error:', e instanceof Error ? e.message : e);
  } finally {
    tailRunning = false;
  }
}

export function startTail(): void {
  setInterval(() => {
    void tick();
  }, POLL_INTERVAL_MS);
  console.log(`[worker] tailing every ${POLL_INTERVAL_MS}ms`);
}
