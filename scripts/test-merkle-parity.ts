// Merkle gadget parity gate (FIN-003).
//
// Compiles the Merkle parity circuits with `circom --prime bls12381`, computes a
// witness, and asserts the circuit's outputs equal the SDK's
// (sdk/src/merkle.ts) outputs for the same inputs - proving inclusion-root and
// the `old_frontier → (new_frontier, new_root)` transition agree across surfaces
// (invariant #12). Run: `npx tsx scripts/test-merkle-parity.ts`.

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import {
  IncrementalMerkleTree,
  applyFrontierTransition,
} from '../sdk/src/merkle.js';

const DEPTH = 6;
const BUILD = 'circuits/build/merkle';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'inherit'] });
}

// Map signal name -> witness index via the .sym file (robust to layout).
function symIndex(symPath: string, signal: string): number {
  for (const line of readFileSync(symPath, 'utf8').split('\n')) {
    const parts = line.split(',');
    if (parts[3] === signal) return Number(parts[1]);
  }
  throw new Error(`signal ${signal} not found in ${symPath}`);
}

function witnessFor(name: string, input: unknown): { witness: string[]; sym: string } {
  sh(
    `circom circuits/test/merkle/${name}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`,
  );
  const inputPath = `${BUILD}/${name}.input.json`;
  writeFileSync(inputPath, JSON.stringify(input));
  const wtns = `${BUILD}/${name}.wtns`;
  sh(`npx --no-install snarkjs wtns calculate ${BUILD}/${name}_js/${name}.wasm ${inputPath} ${wtns}`);
  const wjson = `${BUILD}/${name}.wtns.json`;
  sh(`npx --no-install snarkjs wtns export json ${wtns} ${wjson}`);
  return { witness: JSON.parse(readFileSync(wjson, 'utf8')) as string[], sym: `${BUILD}/${name}.sym` };
}

let failed = false;
function check(label: string, ok: boolean, detail = ''): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'MATCH   ' : 'MISMATCH'} ${label}${ok ? '' : `\n         ${detail}`}`);
}

// --- 1. MerkleInclusion: SDK path/root must satisfy + match the circuit. -------
{
  const tree = new IncrementalMerkleTree(DEPTH);
  [11n, 22n, 33n, 44n, 55n].forEach((l) => tree.insert(l));
  const leafIndex = 3;
  const leaf = 44n;
  const path = tree.inclusionPath(leafIndex);
  const root = tree.root();

  const { witness, sym } = witnessFor('incl6', {
    leaf: leaf.toString(),
    pathElements: path.siblings.map(String),
    pathIndices: path.pathBits.map(String),
    root: root.toString(),
  });
  // Witness generation succeeding already proves root === computedRoot in-circuit.
  const computed = BigInt(witness[symIndex(sym, 'main.computedRoot')]!);
  check('inclusion computedRoot == SDK root', computed === root, `circuit=${computed} sdk=${root}`);
}

// --- 2. FrontierTransition: SDK new_frontier/new_root must match the circuit. --
{
  const base = new IncrementalMerkleTree(DEPTH);
  [1n, 2n, 3n].forEach((l) => base.insert(l));
  const oldFrontier = base.frontier();
  const nextIndex = base.size;
  const newLeaves = [4n, 5n];
  const { newFrontier, newRoot } = applyFrontierTransition(oldFrontier, nextIndex, newLeaves, DEPTH);

  const { witness, sym } = witnessFor('frontier6_2', {
    old_frontier: [...oldFrontier].map(String),
    leaves: newLeaves.map(String),
    nextIndex: nextIndex.toString(),
  });
  const circuitRoot = BigInt(witness[symIndex(sym, 'main.new_root')]!);
  check('transition new_root', circuitRoot === newRoot, `circuit=${circuitRoot} sdk=${newRoot}`);
  let frontierOk = true;
  for (let i = 0; i < DEPTH; i++) {
    const ci = BigInt(witness[symIndex(sym, `main.new_frontier[${i}]`)]!);
    if (ci !== newFrontier[i]) frontierOk = false;
  }
  check('transition new_frontier[0..D-1]', frontierOk);
}

if (failed) {
  console.error('\nMERKLE PARITY FAILED - circuit and SDK disagree.');
  process.exit(1);
}
console.log('\nMERKLE PARITY OK - circuit and SDK agree on inclusion root + frontier transition.');
