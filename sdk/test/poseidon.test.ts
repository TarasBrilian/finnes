/**
 * Poseidon-BLS parameter-parity CI gate (CLAUDE.md invariant #13).
 *
 * This test asserts a FIXED cross-implementation test vector: the same inputs
 * must hash to the same digest in this SDK and in
 * `circuits/lib/poseidon_bls.circom`. If the SDK ever silently switches to
 * circomlibjs' BN254 Poseidon (invariant #1), or the parameter set drifts from
 * the circuit, this gate fails.
 *
 * Run with: `node --test` (after `npm run build`, against the compiled `dist`,
 * or via a TS loader). Imports the SDK source directly.
 *
 * SCAFFOLD STATUS: `poseidonBLS` is an unimplemented stub that throws, and the
 * vector's `expected` is a placeholder (0n, `finalized: false`). Until the
 * crypto lands this test ASSERTS THE STUB STILL THROWS — so it stays green as a
 * scaffold yet documents the exact parity check that must replace it. Do NOT
 * let it pass with a fabricated digest.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  POSEIDON_BLS_TEST_VECTOR,
  poseidonBLS,
  FR_MODULUS,
} from '../src/poseidon.js';

test('Poseidon-BLS parity vector is the invariant #13 CI gate', () => {
  const { inputs, expected, finalized } = POSEIDON_BLS_TEST_VECTOR;

  if (!finalized) {
    // Scaffold phase: the implementation is a TODO stub and the expected digest
    // is not yet the real circuit output. Assert the stub still throws so a fake
    // implementation cannot sneak through, and remind the human to finalize.
    assert.throws(
      () => poseidonBLS(inputs),
      /TODO: poseidonBLS not implemented/,
      'poseidonBLS must remain a throwing stub until the BLS param set is vendored',
    );
    assert.equal(
      expected,
      0n,
      'placeholder expected digest must stay 0n until finalized with the real circuit output',
    );
    return;
  }

  // Real parity gate (active once the crypto and circuit vector are finalized).
  const digest = poseidonBLS(inputs);
  assert.ok(digest >= 0n && digest < FR_MODULUS, 'digest must be a reduced field element');
  assert.equal(
    digest,
    expected,
    'SDK Poseidon-BLS digest must equal circuits/lib/poseidon_bls.circom output (invariant #13)',
  );
});
