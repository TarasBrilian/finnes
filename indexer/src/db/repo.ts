/** Data-access layer. All inserts are idempotent (natural-key `ON CONFLICT DO
 *  NOTHING`); BIGINT columns come back from pg as strings, so callers `Number(...)`
 *  the small ones (counts/ledgers/seq fit comfortably in a JS number here). */

import { Buffer } from 'node:buffer';
import { query } from './client.js';

type SyncRow = {
  contract_id: string;
  start_ledger: string;
  last_cursor: string | null;
  last_ledger: string;
  backfilled: boolean;
  head_root: Buffer | null;
  head_count: string;
  halted: boolean;
  halt_reason: string | null;
};

// --- sync_state -----------------------------------------------------------

export async function ensureSyncState(contractId: string, startLedger: number): Promise<void> {
  await query(
    `INSERT INTO sync_state (contract_id, start_ledger) VALUES ($1, $2)
     ON CONFLICT (contract_id) DO NOTHING`,
    [contractId, startLedger],
  );
}

export async function getSyncState(contractId: string): Promise<SyncRow | null> {
  const r = await query<SyncRow>(`SELECT * FROM sync_state WHERE contract_id = $1`, [contractId]);
  return r.rows[0] ?? null;
}

export async function setCursor(contractId: string, cursor: string | null, ledger: number): Promise<void> {
  await query(
    `UPDATE sync_state SET last_cursor = $2, last_ledger = GREATEST(last_ledger, $3), updated_at = now()
     WHERE contract_id = $1`,
    [contractId, cursor, ledger],
  );
}

export async function setBackfilled(contractId: string): Promise<void> {
  await query(`UPDATE sync_state SET backfilled = TRUE, updated_at = now() WHERE contract_id = $1`, [contractId]);
}

export async function setHead(contractId: string, root: Buffer, count: number): Promise<void> {
  await query(
    `UPDATE sync_state SET head_root = $2, head_count = $3, updated_at = now() WHERE contract_id = $1`,
    [contractId, root, count],
  );
}

export async function setHalted(contractId: string, reason: string): Promise<void> {
  await query(
    `UPDATE sync_state SET halted = TRUE, halt_reason = $2, updated_at = now() WHERE contract_id = $1`,
    [contractId, reason],
  );
}

// --- leaves ---------------------------------------------------------------

export async function leafExists(commitment: Buffer): Promise<boolean> {
  const r = await query(`SELECT 1 FROM leaves WHERE commitment = $1`, [commitment]);
  return (r.rowCount ?? 0) > 0;
}

export async function insertLeaf(
  tree: number,
  leafIndex: number,
  commitment: Buffer,
  txHash: string,
  ledger: number,
  topic: string,
  outputPos: number,
): Promise<void> {
  await query(
    `INSERT INTO leaves (tree, leaf_index, commitment, tx_hash, ledger, topic, output_pos)
     VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
    [tree, leafIndex, commitment, txHash, ledger, topic, outputPos],
  );
}

export async function getAllLeaves(tree: number): Promise<Buffer[]> {
  const r = await query<{ commitment: Buffer }>(
    `SELECT commitment FROM leaves WHERE tree = $1 ORDER BY leaf_index ASC`,
    [tree],
  );
  return r.rows.map((x) => x.commitment);
}

export async function getLeaves(tree: number, from: number, limit: number): Promise<Buffer[]> {
  const r = await query<{ commitment: Buffer }>(
    `SELECT commitment FROM leaves WHERE tree = $1 AND leaf_index >= $2 ORDER BY leaf_index ASC LIMIT $3`,
    [tree, from, limit],
  );
  return r.rows.map((x) => x.commitment);
}

export async function getCommitmentAt(tree: number, leafIndex: number): Promise<Buffer | null> {
  const r = await query<{ commitment: Buffer }>(
    `SELECT commitment FROM leaves WHERE tree = $1 AND leaf_index = $2`,
    [tree, leafIndex],
  );
  return r.rows[0]?.commitment ?? null;
}

export async function getLeafIndexByCommitment(tree: number, commitment: Buffer): Promise<number | null> {
  const r = await query<{ leaf_index: string }>(
    `SELECT leaf_index FROM leaves WHERE tree = $1 AND commitment = $2`,
    [tree, commitment],
  );
  return r.rows[0] ? Number(r.rows[0].leaf_index) : null;
}

// --- roots ----------------------------------------------------------------

export async function insertRoot(
  tree: number,
  root: Buffer,
  leafCount: number,
  txHash: string,
  ledger: number,
): Promise<void> {
  await query(
    `INSERT INTO roots (tree, root, leaf_count, tx_hash, ledger) VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (tree, tx_hash) DO NOTHING`,
    [tree, root, leafCount, txHash, ledger],
  );
}

export type RootRow = { root: Buffer; leaf_count: string; tx_hash: string; ledger: string };

export async function getRecentRoots(tree: number, limit: number): Promise<RootRow[]> {
  const r = await query<RootRow>(
    `SELECT root, leaf_count, tx_hash, ledger FROM roots WHERE tree = $1 ORDER BY seq DESC LIMIT $2`,
    [tree, limit],
  );
  return r.rows;
}

// --- nullifiers -----------------------------------------------------------

export async function insertNullifier(nullifier: Buffer, txHash: string, ledger: number): Promise<void> {
  await query(
    `INSERT INTO nullifiers (nullifier, tx_hash, ledger) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
    [nullifier, txHash, ledger],
  );
}

export async function nullifierUsed(nullifier: Buffer): Promise<{ used: boolean; txHash: string | null }> {
  const r = await query<{ tx_hash: string }>(`SELECT tx_hash FROM nullifiers WHERE nullifier = $1`, [nullifier]);
  return { used: (r.rowCount ?? 0) > 0, txHash: r.rows[0]?.tx_hash ?? null };
}

// --- ciphertexts ----------------------------------------------------------

export async function insertCiphertext(
  txHash: string,
  outputIndex: number,
  commitment: Buffer,
  circuit: string,
  ledger: number,
  cAuditor: Buffer[],
  cRecipient: Buffer[],
): Promise<void> {
  await query(
    `INSERT INTO ciphertexts (tx_hash, output_index, commitment, circuit, ledger, c_auditor, c_recipient)
     VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
    [txHash, outputIndex, commitment, circuit, ledger, cAuditor, cRecipient],
  );
}

export type CiphertextRow = {
  id: string;
  tx_hash: string;
  output_index: number;
  commitment: Buffer;
  circuit: string;
  ledger: string;
  c_auditor: Buffer[];
  c_recipient: Buffer[];
};

export async function getCiphertexts(sinceId: number, limit: number): Promise<CiphertextRow[]> {
  const r = await query<CiphertextRow>(
    `SELECT id, tx_hash, output_index, commitment, circuit, ledger, c_auditor, c_recipient
     FROM ciphertexts WHERE id > $1 ORDER BY id ASC LIMIT $2`,
    [sinceId, limit],
  );
  return r.rows;
}

// --- transactions (regulator ledger) -------------------------------------

export async function insertTransaction(tx: {
  txHash: string;
  circuit: string;
  ledger: number;
  closedAt: string;
  nullifiers: Buffer[];
  reveal: { assetId: Buffer; amount: Buffer; recipient: Buffer } | null;
}): Promise<void> {
  await query(
    `INSERT INTO transactions
       (tx_hash, circuit, ledger, closed_at, nullifiers, reveal_asset_id, reveal_amount, reveal_recipient)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tx_hash) DO NOTHING`,
    [
      tx.txHash,
      tx.circuit,
      tx.ledger,
      tx.closedAt,
      tx.nullifiers,
      tx.reveal?.assetId ?? null,
      tx.reveal?.amount ?? null,
      tx.reveal?.recipient ?? null,
    ],
  );
}

export type TxRow = {
  tx_hash: string;
  seq: string;
  circuit: string;
  ledger: string;
  closed_at: Date;
  nullifiers: Buffer[];
  reveal_asset_id: Buffer | null;
  reveal_amount: Buffer | null;
  reveal_recipient: Buffer | null;
};

export async function getTransactionRows(limit: number, before?: number): Promise<TxRow[]> {
  const sql = `SELECT tx_hash, seq, circuit, ledger, closed_at, nullifiers,
                      reveal_asset_id, reveal_amount, reveal_recipient
               FROM transactions ${before !== undefined ? 'WHERE seq < $2' : ''}
               ORDER BY seq DESC LIMIT $1`;
  const r = await query<TxRow>(sql, before !== undefined ? [limit, before] : [limit]);
  return r.rows;
}

export type OutputRow = { tx_hash: string; output_index: number; commitment: Buffer; c_auditor: Buffer[] };

export async function getOutputsFor(txHashes: string[]): Promise<OutputRow[]> {
  if (!txHashes.length) return [];
  const r = await query<OutputRow>(
    `SELECT tx_hash, output_index, commitment, c_auditor FROM ciphertexts
     WHERE tx_hash = ANY($1) ORDER BY tx_hash, output_index ASC`,
    [txHashes],
  );
  return r.rows;
}

// --- frozen set -----------------------------------------------------------

export async function insertFrozen(commitment: Buffer, frozenRoot: Buffer, txHash: string, ledger: number): Promise<void> {
  await query(
    `INSERT INTO frozen (commitment, frozen_root, tx_hash, ledger) VALUES ($1,$2,$3,$4)
     ON CONFLICT (commitment) DO NOTHING`,
    [commitment, frozenRoot, txHash, ledger],
  );
}

export async function getFrozen(): Promise<{ frozen: Buffer[]; frozenRoot: Buffer | null }> {
  const f = await query<{ commitment: Buffer }>(`SELECT commitment FROM frozen ORDER BY seq ASC`);
  const r = await query<{ frozen_root: Buffer }>(`SELECT frozen_root FROM frozen ORDER BY seq DESC LIMIT 1`);
  return { frozen: f.rows.map((x) => x.commitment), frozenRoot: r.rows[0]?.frozen_root ?? null };
}

// --- compliance roots + registries ---------------------------------------

export async function insertComplianceRoot(kind: string, root: Buffer, txHash: string, ledger: number): Promise<void> {
  await query(`INSERT INTO compliance_roots (kind, root, tx_hash, ledger) VALUES ($1,$2,$3,$4)`, [
    kind,
    root,
    txHash,
    ledger,
  ]);
}

export async function upsertAssetRegistry(assetId: Buffer, sac: string): Promise<void> {
  await query(
    `INSERT INTO asset_registry (asset_id, sac) VALUES ($1,$2)
     ON CONFLICT (asset_id) DO UPDATE SET sac = EXCLUDED.sac`,
    [assetId, sac],
  );
}

export async function upsertTransparentRegistry(recipient: Buffer, addr: string): Promise<void> {
  await query(
    `INSERT INTO transparent_registry (recipient, addr) VALUES ($1,$2)
     ON CONFLICT (recipient) DO UPDATE SET addr = EXCLUDED.addr`,
    [recipient, addr],
  );
}

export async function getAsset(assetId: Buffer): Promise<string | null> {
  const r = await query<{ sac: string }>(`SELECT sac FROM asset_registry WHERE asset_id = $1`, [assetId]);
  return r.rows[0]?.sac ?? null;
}

export async function getTransparent(recipient: Buffer): Promise<string | null> {
  const r = await query<{ addr: string }>(`SELECT addr FROM transparent_registry WHERE recipient = $1`, [recipient]);
  return r.rows[0]?.addr ?? null;
}
