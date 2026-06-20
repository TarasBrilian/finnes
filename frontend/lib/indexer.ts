'use client';

/**
 * On-chain indexer (FIN-019, the real fix). Reconstructs the live commitment tree
 * by reading the contract's events over RPC — the exact leaves the contract holds,
 * in order — instead of a hardcoded seed (which drifts the moment anyone shields).
 *
 * Each effect event carries the inserted commitment(s): shield → cm_out (1 leaf),
 * transfer → cm_out_0, cm_out_1 (2), unshield → cm_change_0 if non-zero (0/1),
 * recovery → cm_out (1). Replaying them in ledger order gives the leaf list; the
 * tree built from it matches the on-chain root exactly (verified).
 *
 * Only PUBLIC data crosses here (commitments + roots are public). Note openings
 * (to actually spend) come from the local note store / demo seeds, matched to a
 * leaf by commitment.
 */

import { rpc, scValToNative } from '@stellar/stellar-sdk';
import { Buffer } from 'buffer';
import { IncrementalMerkleTree, TREE_DEPTH } from '@finnes/sdk';

import { CONTRACT_ID, RPC_URL } from './config.js';

const toBig = (b: Buffer | Uint8Array): bigint => BigInt('0x' + Buffer.from(b).toString('hex'));

/** All inserted leaf commitments, in on-chain leaf order, from contract events. */
export async function fetchLiveCommitments(): Promise<bigint[]> {
  const s = new rpc.Server(RPC_URL);
  const latest = (await s.getLatestLedger()).sequence;
  const start = Math.max(1, latest - 17000); // within Testnet event retention (~22h)
  const leaves: bigint[] = [];
  let cursor: string | undefined;

  for (let page = 0; page < 80; page++) {
    const filters = [{ type: 'contract' as const, contractIds: [CONTRACT_ID] }];
    const req = cursor ? { cursor, filters, limit: 200 } : { startLedger: start, filters, limit: 200 };
    const r = await s.getEvents(req as Parameters<typeof s.getEvents>[0]);
    if (!r.events.length) break;
    for (const ev of r.events) {
      const topic = scValToNative(ev.topic[0]) as string;
      const v = scValToNative(ev.value) as Record<string, Buffer>;
      if (topic === 'shield') leaves.push(toBig(v.cm_out));
      else if (topic === 'transfer') {
        leaves.push(toBig(v.cm_out_0));
        leaves.push(toBig(v.cm_out_1));
      } else if (topic === 'unshield') {
        const cc = toBig(v.cm_change_0);
        if (cc !== 0n) leaves.push(cc);
      } else if (topic === 'recovery') leaves.push(toBig(v.cm_out));
    }
    if (!r.cursor || r.cursor === cursor) break;
    cursor = r.cursor;
  }
  return leaves;
}

export interface ChainTree {
  readonly tree: IncrementalMerkleTree;
  /** Inserted commitments in leaf order; index = leaf index. */
  readonly commitments: readonly bigint[];
  readonly leafCount: number;
}

/** Build the live commitment tree from on-chain events (the real anchor). */
export async function buildChainTree(): Promise<ChainTree> {
  const commitments = await fetchLiveCommitments();
  const tree = new IncrementalMerkleTree(TREE_DEPTH);
  commitments.forEach((c) => tree.insert(c));
  return { tree, commitments, leafCount: commitments.length };
}
