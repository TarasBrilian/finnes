// Convert a snarkjs transfer proof bundle into the contract's host-byte `Proof` +
// `TransferPublicInputs` JSON args for `stellar contract invoke` (FIN-025) — the
// transfer analogue of scripts/submit-shield-live.ts.
//
// Reads setup/build/transfer-proof-live.json ({ proof, publicSignals[73] }) and
// emits setup/build/transfer-args.json = { proof, pi } where:
//   - proof.{a,c} = host G1 (96B hex), proof.b = host G2 (192B hex) — the EXACT
//     encoding verifier.rs decodes (reuses scripts/lib/vk-host.ts, cargo-verified).
//   - pi fields follow docs/PUBLIC_IO.md § transfer (73 signals) → the named
//     TransferPublicInputs fields so the contract's `to_scalars()` rebuilds the
//     SAME vector the proof binds. c_auditor / c_recipient are the contract's
//     CONCATENATED 2·K_a / 2·K_r vectors (note 0 ‖ note 1), 10 elements each.
//
// PUBLIC data only (invariant #8). Run: npx tsx scripts/submit-transfer-live.ts

import { readFileSync, writeFileSync } from 'node:fs';

import { g1ToHex, g2ToHex, frToHex } from './lib/vk-host.js';

const IN = 'setup/build/transfer-proof-live.json';
const OUT = 'setup/build/transfer-args.json';
const D = 20;
const K_A = 5;
const K_R = 5;

type G1 = [string, string, string];
type G2 = [[string, string], [string, string], [string, string]];

const bundle = JSON.parse(readFileSync(IN, 'utf8')) as {
  proof: { pi_a: G1; pi_b: G2; pi_c: G1 };
  publicSignals: string[];
};

const sig = bundle.publicSignals;
if (sig.length !== 73) {
  throw new Error(`expected 73 public signals, got ${sig.length}`);
}

// docs/PUBLIC_IO.md § transfer.circom — absolute indices.
let i = 0;
const next = () => frToHex(sig[i++]!);
const nextVec = (n: number) => Array.from({ length: n }, () => frToHex(sig[i++]!));

const pi = {
  anchor_root: next(), // 0
  kyc_root: next(), // 1
  sanction_root: next(), // 2
  assets_root: next(), // 3
  frozen_root: next(), // 4
  auditor_pk: next(), // 5
  nf_in_0: next(), // 6
  nf_in_1: next(), // 7
  cm_out_0: next(), // 8
  cm_out_1: next(), // 9
  new_root: next(), // 10
  fee: next(), // 11
  next_index: next(), // 12
  old_frontier: nextVec(D), // 13..32
  new_frontier: nextVec(D), // 33..52
  c_auditor: nextVec(2 * K_A), // 53..62  (note 0 ‖ note 1)
  c_recipient: nextVec(2 * K_R), // 63..72 (note 0 ‖ note 1)
};
if (i !== 73) throw new Error(`consumed ${i} signals, expected 73`);

const proof = {
  a: g1ToHex(bundle.proof.pi_a),
  b: g2ToHex(bundle.proof.pi_b),
  c: g1ToHex(bundle.proof.pi_c),
};

writeFileSync(OUT, JSON.stringify({ proof, pi }, null, 2));
console.log(`wrote ${OUT}`);
console.log(`  proof.a ${proof.a.length / 2}B, proof.b ${proof.b.length / 2}B, proof.c ${proof.c.length / 2}B`);
console.log(`  pi: nf_in_0=${pi.nf_in_0.slice(0, 16)}… cm_out_0=${pi.cm_out_0.slice(0, 16)}… next_index=0x${pi.next_index.slice(-2)}`);
console.log(`  c_auditor ${pi.c_auditor.length} fields, c_recipient ${pi.c_recipient.length} fields`);
