'use client';

/**
 * On-chain indexer (FIN-019, the real backend-tier read). Reconstructs the live
 * commitment tree AND the regulator's transaction ledger by replaying the
 * contract's events over RPC — the exact effects the contract committed, in
 * order — instead of a hardcoded seed or a local fixture (both of which drift the
 * moment anyone transacts).
 *
 * Each effect event (events.rs, FIN-011) carries everything the indexer needs to
 * mirror state WITHOUT re-hashing (the contract does none, invariant #11):
 *   - shield    → cm_out (1 leaf)        + c_auditor[5]  + c_recipient[5]
 *   - transfer  → cm_out_0, cm_out_1 (2) + c_auditor[10] + c_recipient[10] + nf_in_0/1
 *   - unshield  → cm_change_0 if non-zero (0/1) + c_auditor[5] + c_recipient[5] + nf_in_0
 *   - recovery  → cm_out (1 leaf)        (issuer-minted; no ciphertext)
 * Replaying them in ledger order gives both the leaf list (the tree built from it
 * matches the on-chain root exactly, verified) and the per-tx auditor ciphertexts
 * the regulator decrypts.
 *
 * Only PUBLIC data crosses here (commitments, nullifiers, roots, and the
 * field-packed ciphertexts — already public inputs, invariant #5). Note openings
 * (to actually SPEND) come from the local note store / demo seeds, matched to a
 * leaf by commitment; the auditor PLAINTEXT is recovered client-side in the
 * regulator's own trust zone with the view key (invariant #8).
 */

import { rpc, scValToNative } from '@stellar/stellar-sdk';
import { Buffer } from 'buffer';
import type { Ciphertext, Commitment, Fr } from '@finnes/sdk';
import { IncrementalMerkleTree, K_A, TREE_DEPTH } from '@finnes/sdk';

import { CONTRACT_ID, RPC_URL } from './config.js';
import { liveSeedCommitments } from './live-notes.js';

const toBig = (b: Buffer | Uint8Array): bigint => BigInt('0x' + Buffer.from(b).toString('hex'));

/** Slice `K_a`/`K_r` field-packed ciphertext slots for output `n` into a Ciphertext. */
function cipherAt(packed: readonly (Buffer | Uint8Array)[] | undefined, n: number): Ciphertext {
  const fields: Fr[] = [];
  for (let i = 0; i < K_A; i++) {
    const slot = packed?.[n * K_A + i];
    fields.push(slot ? toBig(slot) : 0n);
  }
  return { fields };
}

/** Compact display form for a 32-byte hex value (nullifier / tx hash). */
const shortHex = (hex: string): string =>
  hex.length <= 14 ? hex : `0x${hex.slice(0, 6)}…${hex.slice(-4)}`;

/** One decoded contract event, in ledger order. */
interface RawEffect {
  readonly topic: string;
  readonly value: Record<string, unknown>;
  readonly txHash: string;
  readonly ledgerClosedAt: string;
}

/**
 * Single paginated pass over the contract's events, decoded to native objects.
 * One pass feeds BOTH the tree reconstruction and the transaction ledger, so the
 * regulator view and the write-path anchor read the same chain state.
 */
async function indexEffects(): Promise<RawEffect[]> {
  const s = new rpc.Server(RPC_URL);
  const latest = (await s.getLatestLedger()).sequence;
  const start = Math.max(1, latest - 17000); // within Testnet event retention (~22h)
  const effects: RawEffect[] = [];
  let cursor: string | undefined;

  for (let page = 0; page < 80; page++) {
    const filters = [{ type: 'contract' as const, contractIds: [CONTRACT_ID] }];
    const req = cursor ? { cursor, filters, limit: 200 } : { startLedger: start, filters, limit: 200 };
    const r = await s.getEvents(req as Parameters<typeof s.getEvents>[0]);
    if (!r.events.length) break;
    for (const ev of r.events) {
      effects.push({
        topic: scValToNative(ev.topic[0]!) as string,
        value: scValToNative(ev.value) as Record<string, unknown>,
        txHash: ev.txHash,
        ledgerClosedAt: ev.ledgerClosedAt,
      });
    }
    if (!r.cursor || r.cursor === cursor) break;
    cursor = r.cursor;
  }
  return effects;
}

/** All inserted leaf commitments, in on-chain leaf order, from contract events. */
export async function fetchLiveCommitments(): Promise<bigint[]> {
  const effects = await indexEffects();
  const leaves: bigint[] = [];
  for (const e of effects) {
    const v = e.value as Record<string, Buffer>;
    if (e.topic === 'shield') leaves.push(toBig(v.cm_out!));
    else if (e.topic === 'transfer') {
      leaves.push(toBig(v.cm_out_0!));
      leaves.push(toBig(v.cm_out_1!));
    } else if (e.topic === 'unshield') {
      const cc = toBig(v.cm_change_0!);
      if (cc !== 0n) leaves.push(cc);
    } else if (e.topic === 'recovery') leaves.push(toBig(v.cm_out!));
  }
  return leaves;
}

export interface ChainTree {
  readonly tree: IncrementalMerkleTree;
  /** Inserted commitments in leaf order; index = leaf index. */
  readonly commitments: readonly bigint[];
  readonly leafCount: number;
}

/**
 * Bridge any aged-out leaf prefix. A stateless RPC re-read only sees events
 * within Testnet's ~22h retention, so leaves committed before the window
 * (notably the genesis shield at leaf 0) are missing — which would mis-root the
 * tree and shift every leaf index. We splice the confirmed aged-out prefix from
 * the canonical seed, but ONLY when continuity is provable: the first in-window
 * leaf must equal a known seed leaf at position `p > 0`, so `seed[0..p)` is
 * exactly the prefix that aged out on THIS chain. If the first in-window leaf is
 * not a known seed leaf (a fresh / redeployed contract), we trust the events
 * verbatim and never prepend stale data.
 *
 * A production indexer is a stateful service that ingests events continuously
 * and persists the tree, so it never re-reads from genesis; this seed is the
 * demo's stand-in for that persistence (FIN-019).
 */
function bridgeAgedOutPrefix(events: readonly bigint[]): bigint[] {
  if (!events.length) return [...events];
  const seed = liveSeedCommitments();
  const p = seed.indexOf(events[0]!);
  return p > 0 ? [...seed.slice(0, p), ...events] : [...events];
}

/** Build the live commitment tree from on-chain events (the real anchor). */
export async function buildChainTree(): Promise<ChainTree> {
  const commitments = bridgeAgedOutPrefix(await fetchLiveCommitments());
  const tree = new IncrementalMerkleTree(TREE_DEPTH);
  commitments.forEach((c) => tree.insert(c));
  return { tree, commitments, leafCount: commitments.length };
}

// ---------------------------------------------------------------------------
// Regulator ledger: per-transaction nullifiers + per-output (commitment, c_auditor).
// This is exactly what `finnes-client.listOnChainTransactions` serves the
// regulator view; the disclosure path decrypts the mandatory c_auditor.
// ---------------------------------------------------------------------------

/** One on-chain output note as the public sees it: opaque commitment + its auditor ct. */
export interface IndexedOutput {
  readonly commitment: Commitment;
  /** Mandatory auditor ciphertext for this note (field-packed; invariant #5). */
  readonly cAuditor: Ciphertext;
}

/** One on-chain transaction reconstructed from a contract event (PUBLIC data only). */
export interface IndexedTransaction {
  readonly txHash: string;
  readonly timestamp: string;
  readonly circuit: 'shield' | 'transfer' | 'unshield';
  /** Opaque spent-input nullifiers (compact hex). */
  readonly nullifiers: readonly string[];
  /** Output notes carrying the regulator-decryptable auditor ciphertext. */
  readonly outputs: readonly IndexedOutput[];
}

const nfHex = (b: Buffer | Uint8Array): string =>
  shortHex(Buffer.from(b).toString('hex'));

/**
 * Reconstruct the regulator's transaction ledger from on-chain events. Only
 * value-bearing effects that carry auditor ciphertexts are surfaced
 * (shield / transfer / unshield); a `recovery` carries no ciphertext and a
 * no-change unshield contributes no output note (cm_change_0 == 0 sentinel).
 *
 * Returns transactions newest-first (the order the regulator scans them).
 */
export async function indexTransactions(): Promise<IndexedTransaction[]> {
  const effects = await indexEffects();
  const txs: IndexedTransaction[] = [];

  for (const e of effects) {
    const v = e.value as Record<string, Buffer | Buffer[]>;
    const cAud = v.c_auditor as Buffer[] | undefined;
    const ts = e.ledgerClosedAt;

    if (e.topic === 'shield') {
      txs.push({
        txHash: e.txHash,
        timestamp: ts,
        circuit: 'shield',
        nullifiers: [],
        outputs: [{ commitment: toBig(v.cm_out as Buffer), cAuditor: cipherAt(cAud, 0) }],
      });
    } else if (e.topic === 'transfer') {
      txs.push({
        txHash: e.txHash,
        timestamp: ts,
        circuit: 'transfer',
        nullifiers: [nfHex(v.nf_in_0 as Buffer), nfHex(v.nf_in_1 as Buffer)],
        outputs: [
          { commitment: toBig(v.cm_out_0 as Buffer), cAuditor: cipherAt(cAud, 0) },
          { commitment: toBig(v.cm_out_1 as Buffer), cAuditor: cipherAt(cAud, 1) },
        ],
      });
    } else if (e.topic === 'unshield') {
      const cc = toBig(v.cm_change_0 as Buffer);
      txs.push({
        txHash: e.txHash,
        timestamp: ts,
        circuit: 'unshield',
        nullifiers: [nfHex(v.nf_in_0 as Buffer)],
        // No change note (exact spend, cm_change_0 == 0) → no decryptable output.
        outputs: cc === 0n ? [] : [{ commitment: cc, cAuditor: cipherAt(cAud, 0) }],
      });
    }
  }

  return txs.reverse();
}

// ---------------------------------------------------------------------------
// Frozen set (clawback, FIN-018): replay `freeze` events → frozen commitments +
// the latest on-chain `frozen_root`. The issuer freezes a commitment to make a
// note unspendable (every spend proves non-membership against `frozen_root`).
// ---------------------------------------------------------------------------

export interface FrozenState {
  /** Commitments in the issuer frozen set (from `freeze` events, in range). */
  readonly frozen: bigint[];
  /** The latest on-chain `frozen_root` (null if no freeze events in range). */
  readonly frozenRoot: bigint | null;
}

/**
 * Reconstruct the frozen set from `freeze` events. NOTE: like the tree, a
 * stateless re-read only sees events within Testnet's ~22h retention; a freeze
 * older than the window would be missed (a production indexer persists the set).
 * For the demo, freezes are recent. Returns an empty set when none are in range,
 * which reproduces the genesis `frozen_root` (consistent with the write-path).
 */
export async function indexFrozen(): Promise<FrozenState> {
  const effects = await indexEffects();
  const frozen: bigint[] = [];
  let frozenRoot: bigint | null = null;
  for (const e of effects) {
    if (e.topic !== 'freeze') continue;
    const v = e.value as Record<string, Buffer>;
    frozen.push(toBig(v.cm_target!));
    frozenRoot = toBig(v.new_frozen_root!);
  }
  return { frozen, frozenRoot };
}
