// Convert a snarkjs unshield proof bundle into the contract's host-byte `Proof` +
// `UnshieldPublicInputs` JSON args for `stellar contract invoke` (FIN-026) — the
// unshield analogue of scripts/submit-transfer-live.ts.
//
// Reads setup/build/unshield-proof-live.json ({ proof, publicSignals[64] }) and
// emits setup/build/unshield-args.json = { proof, pi } following
// docs/PUBLIC_IO.md § unshield. The change-note ciphertexts are SINGLE-note
// vectors (K_a / K_r = 5 each, all-zero for an exact spend) — NOT the transfer's
// concatenated 2·K vectors.
//
// PUBLIC data only (invariant #8). Run: npx tsx scripts/submit-unshield-live.ts

import { readFileSync, writeFileSync } from 'node:fs';

import { g1ToHex, g2ToHex, frToHex } from './lib/vk-host.js';

// Optional argv lets the same converter serve the exact-spend unshield (no args)
// and the partial unshield (FIN-026 1-insert): `... <in.json> <out.json>`.
const IN = process.argv[2] ?? 'setup/build/unshield-proof-live.json';
const OUT = process.argv[3] ?? 'setup/build/unshield-args.json';
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
if (sig.length !== 64) {
  throw new Error(`expected 64 public signals, got ${sig.length}`);
}

// docs/PUBLIC_IO.md § unshield.circom — absolute indices.
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
  asset_id: next(), // 7
  amount: next(), // 8
  recipient: next(), // 9
  cm_change_0: next(), // 10
  new_root: next(), // 11
  fee: next(), // 12
  next_index: next(), // 13
  old_frontier: nextVec(D), // 14..33
  new_frontier: nextVec(D), // 34..53
  c_auditor: nextVec(K_A), // 54..58 (change note; all-zero for exact spend)
  c_recipient: nextVec(K_R), // 59..63
};
if (i !== 64) throw new Error(`consumed ${i} signals, expected 64`);

const proof = {
  a: g1ToHex(bundle.proof.pi_a),
  b: g2ToHex(bundle.proof.pi_b),
  c: g1ToHex(bundle.proof.pi_c),
};

writeFileSync(OUT, JSON.stringify({ proof, pi }, null, 2));
console.log(`wrote ${OUT}`);
console.log(`  proof.a ${proof.a.length / 2}B, proof.b ${proof.b.length / 2}B, proof.c ${proof.c.length / 2}B`);
console.log(`  pi: nf_in_0=${pi.nf_in_0.slice(0, 16)}… amount=0x${pi.amount.slice(-8)} recipient=${pi.recipient.slice(0, 16)}…`);
const exactSpend = /^0+$/.test(pi.cm_change_0);
console.log(`  cm_change_0=${exactSpend ? '0 (exact spend, 0 inserts)' : pi.cm_change_0.slice(0, 16) + '… (change note, 1 insert)'} · c_auditor ${pi.c_auditor.length} fields`);
