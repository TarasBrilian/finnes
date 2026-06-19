/**
 * Poseidon-BLS parameter-parity CI gate (CLAUDE.md invariant #13).
 *
 * Asserts FIXED cross-implementation test vectors: the same inputs must hash to
 * the same digest in this SDK and in `circuits/lib/poseidon_bls.circom`. The
 * digests below were verified equal in both surfaces by
 * `scripts/test-poseidon-parity.ts` (circom --prime bls12381 vs SDK). If the SDK
 * silently switches to circomlibjs' BN254 Poseidon (invariant #1), or the params
 * drift from the circuit, these locked vectors fail.
 *
 * Run: `npm test` in sdk/ (uses a TS loader). The full circuit↔SDK parity is
 * `npx tsx scripts/test-poseidon-parity.ts` (needs circom + snarkjs).
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { POSEIDON_BLS_TEST_VECTOR, poseidonBLS, FR_MODULUS } from '../src/poseidon.js';

// Locked digests, verified against the circuit (do not edit without regenerating
// params + re-running the ceremony - a parity-breaking event).
const LOCKED: ReadonlyArray<{ inputs: bigint[]; expected: bigint }> = [
  { inputs: [1n], expected: 34917507619340176517384719106072291112335569024831212256807722082447975477987n },
  { inputs: [1n, 2n], expected: 1539466174953200397849885941806203218514759356197876052928772286378091849564n },
  {
    inputs: [1n, 2n, 3n, 4n, 5n],
    expected: 6320524702893319544816904670399199184903984267921319944071342089290415783697n,
  },
];

test('Poseidon-BLS parity vector (invariant #13 CI gate)', () => {
  assert.equal(POSEIDON_BLS_TEST_VECTOR.finalized, true, 'parity vector must be finalized');
  assert.deepEqual([...POSEIDON_BLS_TEST_VECTOR.inputs], [1n, 2n]);
  assert.equal(poseidonBLS(POSEIDON_BLS_TEST_VECTOR.inputs), POSEIDON_BLS_TEST_VECTOR.expected);
});

test('Poseidon-BLS matches the circuit across widths t=2,3,6', () => {
  for (const { inputs, expected } of LOCKED) {
    const digest = poseidonBLS(inputs);
    assert.ok(digest >= 0n && digest < FR_MODULUS, 'digest must be a reduced field element');
    assert.equal(digest, expected, `arity ${inputs.length} digest must equal the circuit output`);
  }
});

test('Poseidon-BLS is deterministic and reduces inputs', () => {
  assert.equal(poseidonBLS([1n, 2n]), poseidonBLS([1n + FR_MODULUS, 2n]), 'inputs reduced mod r');
});

test('Poseidon-BLS rejects unsupported arities', () => {
  assert.throws(() => poseidonBLS([1n, 2n, 3n]), /unsupported arity/); // t=4 not generated
});
