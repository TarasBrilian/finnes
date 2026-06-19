// Full-field comparator soundness gate (FIN-003, fund-critical).
//
// The IMT non-membership check (sanctions + frozen, invariants #14/#19) compares
// raw Poseidon outputs that span the whole scalar field. These tests prove the
// vendored r-aware gadgets (circuits/lib/bits.circom) are SOUND over [0, r):
//   - AliasCheckBLS accepts canonical (< r) bit reps and REJECTS r, r+k, and the
//     all-ones 255-bit value - including the exact r/r-1 boundary tied to the
//     SDK modulus, so a malicious non-canonical witness cannot pass.
//   - LessThanField matches integer `<` for values that exceed 2^252.
// Run: `npx tsx scripts/test-comparator-parity.ts`.

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { FR_MODULUS } from '../sdk/src/poseidon.js';

const BUILD = 'circuits/build/bits';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'pipe'] });
}
function compile(name: string): void {
  sh(`circom circuits/test/bits/${name}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`);
}
function symIndex(name: string, signal: string): number {
  for (const line of readFileSync(`${BUILD}/${name}.sym`, 'utf8').split('\n')) {
    const p = line.split(',');
    if (p[3] === signal) return Number(p[1]);
  }
  throw new Error(`signal ${signal} not found`);
}
/** Attempt witness generation; return true on success, false on a constraint failure. */
function tryWitness(name: string, input: unknown): boolean {
  writeFileSync(`${BUILD}/${name}.input.json`, JSON.stringify(input));
  try {
    sh(`npx --no-install snarkjs wtns calculate ${BUILD}/${name}_js/${name}.wasm ${BUILD}/${name}.input.json ${BUILD}/${name}.wtns`);
    return true;
  } catch {
    return false;
  }
}
function readOut(name: string, signal: string): bigint {
  sh(`npx --no-install snarkjs wtns export json ${BUILD}/${name}.wtns ${BUILD}/${name}.wtns.json`);
  const w = JSON.parse(readFileSync(`${BUILD}/${name}.wtns.json`, 'utf8')) as string[];
  return BigInt(w[symIndex(name, signal)]!);
}
/** Little-endian bit array (length n) of v, as decimal strings. */
function bitsLE(v: bigint, n: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < n; i++) out.push(((v >> BigInt(i)) & 1n).toString());
  return out;
}

let failed = false;
function expect(label: string, ok: boolean, detail = ''): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `   ${detail}`}`);
}

// --- AliasCheckBLS: canonical accepted, non-canonical rejected -----------------
compile('aliascheck255');
const aliasCases: ReadonlyArray<{ v: bigint; canonical: boolean; label: string }> = [
  { v: 0n, canonical: true, label: 'bits(0)' },
  { v: 1n, canonical: true, label: 'bits(1)' },
  { v: FR_MODULUS - 1n, canonical: true, label: 'bits(r-1) [max field elt]' },
  { v: FR_MODULUS, canonical: false, label: 'bits(r) [not a field elt]' },
  { v: FR_MODULUS + 5n, canonical: false, label: 'bits(r+5)' },
  { v: (1n << 255n) - 1n, canonical: false, label: 'bits(2^255-1) [all ones]' },
];
for (const c of aliasCases) {
  const ok = tryWitness('aliascheck255', { bits: bitsLE(c.v, 255) });
  expect(`AliasCheckBLS ${c.canonical ? 'accepts' : 'rejects'} ${c.label}`, ok === c.canonical);
}

// --- LessThanField: matches integer < across the full field --------------------
compile('lessfield');
const BIG = 1n << 253n; // exceeds 2^252 - the vendored LessThan would be unsound here
const cmpCases: ReadonlyArray<[bigint, bigint]> = [
  [3n, 7n],
  [7n, 3n],
  [5n, 5n],
  [BIG, BIG + 1n],
  [BIG + 1n, BIG],
  [FR_MODULUS - 1n, 0n],
  [0n, FR_MODULUS - 1n],
  [FR_MODULUS - 1n, FR_MODULUS - 2n],
];
for (const [a, b] of cmpCases) {
  if (!tryWitness('lessfield', { a: a.toString(), b: b.toString() })) {
    expect(`LessThanField(${a}, ${b}) witness`, false, 'witness gen failed');
    continue;
  }
  const out = readOut('lessfield', 'main.out');
  const want = a < b ? 1n : 0n;
  expect(`LessThanField(${a < BIG ? a : 'BIG..'}, ${b < BIG ? b : 'BIG..'}) == ${want}`, out === want, `got ${out}`);
}

if (failed) {
  console.error('\nCOMPARATOR SOUNDNESS FAILED.');
  process.exit(1);
}
console.log('\nCOMPARATOR SOUNDNESS OK - r-aware alias check + full-field LessThan are sound.');
