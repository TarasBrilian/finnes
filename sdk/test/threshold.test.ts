/**
 * Threshold / multi-auditor view-key tests (FIN-020).
 *
 * Asserts the Shamir k-of-n split over the BLS12-381 scalar field is correct and
 * confidential: ANY k shares reconstruct the exact `k_view` (so the derived
 * `auditor_pk` matches the single-key one the contract uses), and fewer than k
 * shares reveal nothing (no single honeypot). Pure field arithmetic — no embedded
 * curve, no circuit/contract change (invariant #1).
 *
 * Run: `npm test` in sdk/.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  splitViewKey,
  combineShares,
  auditorPkFromShares,
  type KeyShare,
} from '../src/threshold.js';
import { auditorPkFromKey } from '../src/encrypt.js';
import { FR_MODULUS } from '../src/poseidon.js';

const K_VIEW = 777_000_001n; // the demo auditor view key (frontend/scripts demo-state)

/** Every k-sized subset of `arr` (combinations). */
function combinations<T>(arr: readonly T[], k: number): T[][] {
  if (k === 0) return [[]];
  if (k > arr.length) return [];
  const [head, ...rest] = arr;
  return [
    ...combinations(rest, k - 1).map((c) => [head!, ...c]),
    ...combinations(rest, k),
  ];
}

test('2-of-3: ANY 2 shares reconstruct k_view; 1 share does not', () => {
  // Deterministic coefficients so the test is reproducible.
  const shares = splitViewKey(K_VIEW, { threshold: 2, total: 3, coefficients: [123456789n] });
  assert.equal(shares.length, 3);
  assert.deepEqual(shares.map((s) => Number(s.x)), [1, 2, 3]);

  for (const pair of combinations(shares, 2)) {
    assert.equal(combineShares(pair), K_VIEW, `pair x=${pair.map((s) => s.x)} must recover the key`);
  }
  // A single share (below quorum) must NOT equal the secret.
  for (const s of shares) {
    assert.notEqual(combineShares([s]), K_VIEW, 'a single share must not reveal the key');
  }
});

test('3-of-5: any 3 reconstruct; no 2 do', () => {
  const shares = splitViewKey(K_VIEW, {
    threshold: 3,
    total: 5,
    coefficients: [111n, 222n], // degree-2 polynomial (k-1 = 2 coeffs)
  });
  assert.equal(shares.length, 5);
  for (const trio of combinations(shares, 3)) {
    assert.equal(combineShares(trio), K_VIEW);
  }
  // Over-quorum (4 shares) still reconstructs.
  assert.equal(combineShares(shares.slice(0, 4)), K_VIEW);
  // Below quorum (any 2) must not reveal it.
  for (const pair of combinations(shares, 2)) {
    assert.notEqual(combineShares(pair), K_VIEW);
  }
});

test('threshold key derives the SAME auditor_pk as the single-key path', () => {
  const single = auditorPkFromKey(K_VIEW).pk;
  const shares = splitViewKey(K_VIEW, { threshold: 2, total: 3, coefficients: [99n] });
  // Any quorum → same auditor_pk the contract is initialised with (drop-in custody).
  assert.equal(auditorPkFromShares([shares[0]!, shares[2]!]).pk, single);
  assert.equal(auditorPkFromShares(shares).pk, single);
});

test('n-of-n (3-of-3): all shares required', () => {
  const shares = splitViewKey(K_VIEW, { threshold: 3, total: 3, coefficients: [7n, 11n] });
  assert.equal(combineShares(shares), K_VIEW);
  for (const pair of combinations(shares, 2)) {
    assert.notEqual(combineShares(pair), K_VIEW);
  }
});

test('1-of-n is the degenerate single-key case (every share is the key)', () => {
  const shares = splitViewKey(K_VIEW, { threshold: 1, total: 3 }); // no coefficients needed
  for (const s of shares) {
    assert.equal(s.y, K_VIEW % FR_MODULUS);
    assert.equal(combineShares([s]), K_VIEW);
  }
});

test('shares lie in the field and reduce a large secret', () => {
  const big = FR_MODULUS - 5n;
  const shares = splitViewKey(big, { threshold: 2, total: 4, coefficients: [FR_MODULUS - 1n] });
  for (const s of shares) {
    assert.ok(s.x >= 0n && s.x < FR_MODULUS);
    assert.ok(s.y >= 0n && s.y < FR_MODULUS);
  }
  assert.equal(combineShares([shares[1]!, shares[3]!]), big);
});

test('input validation', () => {
  assert.throws(() => splitViewKey(K_VIEW, { threshold: 0, total: 3 }), /threshold/);
  assert.throws(() => splitViewKey(K_VIEW, { threshold: 3, total: 2 }), /threshold/);
  assert.throws(
    () => splitViewKey(K_VIEW, { threshold: 2, total: 3, coefficients: [] }),
    /coefficient/,
  );
  assert.throws(() => combineShares([]), /no shares/);
  // duplicate x cannot be interpolated.
  const dup: KeyShare[] = [
    { x: 1n, y: 5n },
    { x: 1n, y: 9n },
  ];
  assert.throws(() => combineShares(dup), /duplicate/);
});

test('random split (default coefficients) round-trips', () => {
  const shares = splitViewKey(K_VIEW, { threshold: 3, total: 5 }); // secure-random coeffs
  assert.equal(combineShares(shares.slice(0, 3)), K_VIEW);
  assert.equal(combineShares([shares[0]!, shares[2]!, shares[4]!]), K_VIEW);
  assert.notEqual(combineShares(shares.slice(0, 2)), K_VIEW);
});
