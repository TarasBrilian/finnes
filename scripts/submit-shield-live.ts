// Convert a snarkjs shield proof bundle into the contract's host-byte `Proof` +
// `ShieldPublicInputs` JSON args for `stellar contract invoke` (FIN-015).
//
// Reads setup/build/shield-proof-live.json ({ proof, publicSignals }) and emits
// setup/build/shield-args.json = { proof, pi } where:
//   - proof.{a,c} = host G1 (96B hex), proof.b = host G2 (192B hex) — the EXACT
//     encoding verifier.rs decodes (reuses scripts/lib/vk-host.ts, cargo-verified).
//   - pi fields follow docs/PUBLIC_IO.md § shield (59 signals), each a 32B Fr hex.
//
// The 59 publicSignals are the circuit's ordered public IO; this maps them to the
// named ShieldPublicInputs struct fields so the contract's `to_scalars()` rebuilds
// the SAME vector the proof binds (a mismatch = bogus "invalid proof").
//
// PUBLIC data only (invariant #8). Run: `npx tsx scripts/submit-shield-live.ts`.

import { readFileSync, writeFileSync } from 'node:fs';

import { g1ToHex, g2ToHex, frToHex } from './lib/vk-host.js';

// Optional argv lets the same converter serve the genesis shield (no args) and
// shield #2 (FIN-025): `... submit-shield-live.ts <in.json> <out.json>`.
const IN = process.argv[2] ?? 'setup/build/shield-proof-live.json';
const OUT = process.argv[3] ?? 'setup/build/shield-args.json';
const D = 20;

type G1 = [string, string, string];
type G2 = [[string, string], [string, string], [string, string]];

const bundle = JSON.parse(readFileSync(IN, 'utf8')) as {
  proof: { pi_a: G1; pi_b: G2; pi_c: G1 };
  publicSignals: string[];
};

const sig = bundle.publicSignals;
if (sig.length !== 59) {
  throw new Error(`expected 59 public signals, got ${sig.length}`);
}

// docs/PUBLIC_IO.md § shield.circom — absolute indices.
let i = 0;
const next = () => frToHex(sig[i++]!);
const nextVec = (n: number) => Array.from({ length: n }, () => frToHex(sig[i++]!));

const pi = {
  asset_id: next(), // 0
  amount: next(), // 1
  kyc_root: next(), // 2
  assets_root: next(), // 3
  auditor_pk: next(), // 4
  cm_out_0: next(), // 5
  new_root: next(), // 6
  fee: next(), // 7
  next_index: next(), // 8
  old_frontier: nextVec(D), // 9..28
  new_frontier: nextVec(D), // 29..48
  c_auditor: nextVec(5), // 49..53
  c_recipient: nextVec(5), // 54..58
};
if (i !== 59) throw new Error(`consumed ${i} signals, expected 59`);

const proof = {
  a: g1ToHex(bundle.proof.pi_a),
  b: g2ToHex(bundle.proof.pi_b),
  c: g1ToHex(bundle.proof.pi_c),
};

writeFileSync(OUT, JSON.stringify({ proof, pi }, null, 2));
console.log(`wrote ${OUT}`);
console.log(`  proof.a ${proof.a.length / 2}B, proof.b ${proof.b.length / 2}B, proof.c ${proof.c.length / 2}B`);
console.log(`  pi: asset_id=${pi.asset_id.slice(0, 16)}… amount=0x${pi.amount.slice(-8)} next_index=0x${pi.next_index.slice(-2)}`);
