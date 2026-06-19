// Poseidon-BLS parity gate (FIN-002, invariant #13).
//
// Compiles the parity circuits with `circom --prime bls12381`, computes a witness
// for fixed inputs, and asserts the circuit's digest equals the SDK's
// poseidonBLS() output - proving the circuit and the SDK use identical params and
// permutation. Run: `npx tsx scripts/test-poseidon-parity.ts`.

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { poseidonBLS } from '../sdk/src/poseidon.js';

const CASES = [
  { name: 'p1', inputs: [1n] },
  { name: 'p2', inputs: [1n, 2n] },
  { name: 'p5', inputs: [1n, 2n, 3n, 4n, 5n] },
];

const BUILD = 'circuits/build/poseidon';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'inherit'] });
}

// Find a signal's witness index from the .sym file (robust against layout assumptions).
function witnessIndex(symPath: string, signal: string): number {
  for (const line of readFileSync(symPath, 'utf8').split('\n')) {
    const parts = line.split(',');
    if (parts[3] === signal) return Number(parts[1]);
  }
  throw new Error(`signal ${signal} not found in ${symPath}`);
}

let failed = false;
for (const c of CASES) {
  const t = c.inputs.length + 1;
  sh(`circom circuits/test/poseidon/${c.name}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`);

  const inputPath = `${BUILD}/${c.name}.input.json`;
  writeFileSync(inputPath, JSON.stringify({ in: c.inputs.map(String) }));

  const wtns = `${BUILD}/${c.name}.wtns`;
  sh(`npx --no-install snarkjs wtns calculate ${BUILD}/${c.name}_js/${c.name}.wasm ${inputPath} ${wtns}`);
  const wjson = `${BUILD}/${c.name}.wtns.json`;
  sh(`npx --no-install snarkjs wtns export json ${wtns} ${wjson}`);

  const witness = JSON.parse(readFileSync(wjson, 'utf8')) as string[];
  const idx = witnessIndex(`${BUILD}/${c.name}.sym`, 'main.out');
  const circuitOut = BigInt(witness[idx]!);
  const sdkOut = poseidonBLS(c.inputs);
  const ok = circuitOut === sdkOut;
  if (!ok) failed = true;
  console.log(`${c.name} (t=${t}): ${ok ? 'MATCH  ' : 'MISMATCH'} ${circuitOut}${ok ? '' : `\n        sdk=${sdkOut}`}`);
}

if (failed) {
  console.error('\nPARITY FAILED - circuit and SDK disagree.');
  process.exit(1);
}
console.log('\nPARITY OK - circuit and SDK produce identical digests.');
// Print the t=3 vector so it can be locked into POSEIDON_BLS_TEST_VECTOR.
console.log(`\nLock this in sdk/src/poseidon.ts POSEIDON_BLS_TEST_VECTOR.expected:`);
console.log(`  inputs [1n, 2n] -> ${poseidonBLS([1n, 2n])}n`);
