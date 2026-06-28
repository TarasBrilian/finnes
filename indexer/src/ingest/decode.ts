/**
 * Decode a raw contract event (already `scValToNative`'d) into a normalized
 * EffectRecord the worker can apply. Field layout follows `contracts/finnes/src/
 * events.rs`: struct topics decode to objects (snake_case keys, BytesN<32> →
 * Buffer, Vec → Buffer[], Address/Symbol → string); escrow topics decode to
 * positional tuples (arrays).
 */

import { Buffer } from 'node:buffer';
import { K_A } from '@finnes/sdk';

import { isZeroBuf } from '../encoding.js';
import { TREE_MAIN, TREE_ESCROW } from '../config.js';
import type { RawEffect } from '../stellar.js';

export interface OutputCt {
  outputIndex: number;
  commitment: Buffer;
  cAuditor: Buffer[];
  cRecipient: Buffer[];
}

export interface EffectRecord {
  topic: string;
  txHash: string;
  ledger: number;
  closedAt: string;
  tree: number;
  leaves: Buffer[];
  newRoot: Buffer | null;
  nullifiers: Buffer[];
  outputs: OutputCt[];
  isLedgerTx: boolean;
  circuit: string;
  reveal: { assetId: Buffer; amount: Buffer; recipient: Buffer } | null;
  frozen: { commitment: Buffer; frozenRoot: Buffer } | null;
  complianceRoot: { kind: string; root: Buffer } | null;
  assetReg: { assetId: Buffer; sac: string } | null;
  transparentReg: { recipient: Buffer; addr: string } | null;
}

function base(e: RawEffect): EffectRecord {
  return {
    topic: e.topic,
    txHash: e.txHash,
    ledger: e.ledger,
    closedAt: e.ledgerClosedAt,
    tree: TREE_MAIN,
    leaves: [],
    newRoot: null,
    nullifiers: [],
    outputs: [],
    isLedgerTx: false,
    circuit: e.topic,
    reveal: null,
    frozen: null,
    complianceRoot: null,
    assetReg: null,
    transparentReg: null,
  };
}

/** Split a flat field-packed ciphertext vector into per-output K-wide slots
 *  (K_A == K_R == 5). One output per commitment. */
function sliceCts(commitments: Buffer[], cAud: Buffer[], cRec: Buffer[]): OutputCt[] {
  const out: OutputCt[] = [];
  for (let i = 0; i < commitments.length; i++) {
    out.push({
      outputIndex: i,
      commitment: commitments[i]!,
      cAuditor: cAud.slice(i * K_A, i * K_A + K_A),
      cRecipient: cRec.slice(i * K_A, i * K_A + K_A),
    });
  }
  return out;
}

export function decodeEffect(e: RawEffect): EffectRecord | null {
  const r = base(e);
  const v = e.value as Record<string, unknown>; // struct topics
  const a = e.value as unknown[]; // escrow tuple topics

  switch (e.topic) {
    case 'shield': {
      const cm = v.cm_out as Buffer;
      r.leaves = [cm];
      r.newRoot = v.new_root as Buffer;
      r.isLedgerTx = true;
      r.circuit = 'shield';
      r.outputs = sliceCts([cm], v.c_auditor as Buffer[], v.c_recipient as Buffer[]);
      return r;
    }
    case 'transfer': {
      const cms = [v.cm_out_0 as Buffer, v.cm_out_1 as Buffer];
      r.leaves = cms;
      r.newRoot = v.new_root as Buffer;
      r.nullifiers = [v.nf_in_0 as Buffer, v.nf_in_1 as Buffer];
      r.isLedgerTx = true;
      r.circuit = 'transfer';
      r.outputs = sliceCts(cms, v.c_auditor as Buffer[], v.c_recipient as Buffer[]);
      return r;
    }
    case 'unshield': {
      const cc = v.cm_change_0 as Buffer;
      const hasChange = !isZeroBuf(cc);
      r.leaves = hasChange ? [cc] : [];
      r.newRoot = v.new_root as Buffer;
      r.nullifiers = [v.nf_in_0 as Buffer];
      r.isLedgerTx = true;
      r.circuit = 'unshield';
      r.outputs = hasChange ? sliceCts([cc], v.c_auditor as Buffer[], v.c_recipient as Buffer[]) : [];
      r.reveal = {
        assetId: v.asset_id as Buffer,
        amount: v.amount as Buffer,
        recipient: v.recipient as Buffer,
      };
      return r;
    }
    case 'recovery': {
      r.leaves = [v.cm_out as Buffer];
      r.newRoot = v.new_root as Buffer;
      r.circuit = 'recovery';
      return r;
    }
    case 'dvp': {
      // DvpEvent carries NO ciphertexts (disclosure gap — see INDEXER_IMPLEMENTATION §11).
      const cms = [v.cm_out_x as Buffer, v.cm_out_y as Buffer];
      r.leaves = cms;
      r.newRoot = v.new_root as Buffer;
      r.nullifiers = [v.nf_leg_x_0 as Buffer, v.nf_leg_y_0 as Buffer];
      r.isLedgerTx = true;
      r.circuit = 'dvp';
      return r;
    }
    case 'freeze': {
      r.frozen = { commitment: v.cm_target as Buffer, frozenRoot: v.new_frozen_root as Buffer };
      r.circuit = 'freeze';
      return r;
    }
    case 'rootupd': {
      r.complianceRoot = { kind: String(v.kind), root: v.new_root as Buffer };
      r.circuit = 'rootupd';
      return r;
    }
    case 'regasset': {
      r.assetReg = { assetId: v.asset_id as Buffer, sac: String(v.sac) };
      r.circuit = 'regasset';
      return r;
    }
    case 'regtrans': {
      r.transparentReg = { recipient: v.recipient as Buffer, addr: String(v.addr) };
      r.circuit = 'regtrans';
      return r;
    }
    case 'escrowdep': {
      // (intent_id, nf_in_0, cm_out, new_root, c_auditor, c_recipient) → ESCROW tree
      const cm = a[2] as Buffer;
      r.tree = TREE_ESCROW;
      r.leaves = [cm];
      r.newRoot = a[3] as Buffer;
      r.nullifiers = [a[1] as Buffer];
      r.circuit = 'escrow_deposit';
      r.outputs = sliceCts([cm], a[4] as Buffer[], a[5] as Buffer[]);
      return r;
    }
    case 'settled': {
      // (intent_id, nf_x, nf_y, cm_out_x, cm_out_y, new_root) → MAIN tree
      r.leaves = [a[3] as Buffer, a[4] as Buffer];
      r.newRoot = a[5] as Buffer;
      r.nullifiers = [a[1] as Buffer, a[2] as Buffer];
      r.isLedgerTx = true;
      r.circuit = 'settle';
      return r;
    }
    case 'refunded': {
      // (intent_id, nf_in_0, cm_out, new_root, c_auditor, c_recipient) → MAIN tree
      const cm = a[2] as Buffer;
      r.leaves = [cm];
      r.newRoot = a[3] as Buffer;
      r.nullifiers = [a[1] as Buffer];
      r.circuit = 'escrow_refund';
      r.outputs = sliceCts([cm], a[4] as Buffer[], a[5] as Buffer[]);
      return r;
    }
    default:
      return null; // 'intent' (no tree effect) and any unknown topic
  }
}
