/**
 * Poseidon hash over the BLS12-381 SCALAR field `r`.
 *
 * ============================================================================
 * INVARIANT #1 / #13 — PARAMETER PARITY (FUND/PRIVACY CRITICAL)
 * ============================================================================
 * This module MUST NOT use circomlibjs' default Poseidon. circomlibjs ships
 * Poseidon parameterized for the BN254 scalar field. Using those constants
 * (even "reduced into" the BLS field) is NOT a valid Poseidon instance for `r`
 * and silently breaks commitment/nullifier parity with the circuit.
 *
 * The parameter set used here MUST be generated specifically for the BLS12-381
 * scalar field
 *
 *   r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
 *     = 52435875175126190479447740508185965837690552500527637822603658699938581184513
 *
 * following the neptune / Filecoin Poseidon lineage (Poseidon over the BLS12-381
 * scalar field), and cross-checked against the SDF "Privacy Pools" parameter
 * choices. Concretely the round constants `C`, the MDS matrix `M`, the S-box
 * exponent `alpha`, and the round counts `(R_F, R_P)` per `t` (width) must be:
 *
 *   - derived from the Grain LFSR seeded for field `r` (not BN254), AND
 *   - BYTE-FOR-BYTE IDENTICAL to the parameters embedded in
 *     `circuits/lib/poseidon_bls.circom`.
 *
 * The cross-implementation test vector below (`POSEIDON_BLS_TEST_VECTOR`) is the
 * CI parity gate (invariant #13): the circuit and this SDK must produce the same
 * hash for the same inputs. `sdk/test/poseidon.test.ts` asserts it.
 *
 * SECURITY (invariant #8): inputs to Poseidon frequently include secrets
 * (`owner_sk`, `rho`, `r_note`, plaintext `value`). NEVER log inputs or outputs
 * of this function to anything outside the client trust zone.
 * ============================================================================
 */

import type { Fr } from './types.js';

/**
 * The BLS12-381 scalar field modulus `r`. The Poseidon parameters and all
 * inputs/outputs of {@link poseidonBLS} live in `[0, r)`.
 */
export const BLS12_381_SCALAR_FIELD_MODULUS: bigint =
  0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

/** Convenience alias used throughout the SDK. */
export const FR_MODULUS = BLS12_381_SCALAR_FIELD_MODULUS;

/**
 * Poseidon parameter identity. These describe WHICH parameter set must be
 * loaded; the actual constants (C, M) are a TODO to be vendored from the same
 * source that generates `circuits/lib/poseidon_bls.circom`.
 *
 * The values below document the intended configuration; they are NOT the
 * constants themselves and changing them is a parity-breaking event that
 * requires regenerating the circuit parameters and re-running the ceremony.
 */
export const POSEIDON_BLS_PARAMS = {
  /** Field the parameters are generated for. */
  field: 'BLS12-381-scalar-field-r' as const,
  /** S-box exponent. x^5 is standard for this field (gcd(5, r-1) == 1). */
  alpha: 5 as const,
  /**
   * Parameter lineage. Must match the generator used for the circuit.
   * neptune/Filecoin Poseidon over BLS12-381; cross-checked vs SDF Privacy Pools.
   */
  lineage: 'neptune/filecoin (BLS12-381); cross-check SDF Privacy Pools' as const,
  /**
   * Round counts (R_F full, R_P partial) are width-dependent and TODO: vendor
   * the exact table from the circuit's parameter generator. Listed widths are
   * the ones Finnes needs (commitment uses t=6 → 5 inputs, nullifier t=3 → 2).
   */
  widthsInUse: [3, 6] as const,
} as const;

/**
 * Reduce a bigint into the canonical `[0, r)` representative.
 * (Field arithmetic helper; safe to use on public values.)
 */
export function toField(x: bigint): Fr {
  const m = x % FR_MODULUS;
  return m >= 0n ? m : m + FR_MODULUS;
}

/**
 * Poseidon over the BLS12-381 scalar field.
 *
 * @param inputs field elements (each in `[0, r)`); arity selects the width `t`.
 * @returns the Poseidon digest as a field element in `[0, r)`.
 *
 * TODO(crypto): implement the permutation using the BLS12-381 parameter set
 * (round constants C, MDS matrix M, alpha=5, width-specific R_F/R_P) vendored
 * byte-identically from `circuits/lib/poseidon_bls.circom`. This is a SCAFFOLD
 * STUB — it MUST NOT return a fake digest (that would produce commitments that
 * silently disagree with the circuit). It throws until implemented.
 */
export function poseidonBLS(_inputs: readonly Fr[]): Fr {
  throw new Error(
    'TODO: poseidonBLS not implemented. Vendor the BLS12-381 scalar-field ' +
      'Poseidon parameters (byte-identical to circuits/lib/poseidon_bls.circom) ' +
      'and implement the permutation. Do NOT use circomlibjs BN254 Poseidon.',
  );
}

/**
 * FIXED cross-implementation parity vector (invariant #13 CI gate).
 *
 * `expected` is a PLACEHOLDER (0n) and MUST be replaced with the real digest
 * emitted by BOTH the circuit and this SDK once Poseidon is implemented. The
 * test in `sdk/test/poseidon.test.ts` references this constant. Inputs are a
 * fixed 2-element vector (width t=3), the smallest case both surfaces exercise.
 *
 * TODO(crypto): populate `expected` from `circuits/lib/poseidon_bls.circom`
 * output for `inputs` and keep it locked thereafter.
 */
export const POSEIDON_BLS_TEST_VECTOR: {
  readonly inputs: readonly Fr[];
  readonly expected: Fr;
  /** Set true once `expected` is the real circuit-derived digest. */
  readonly finalized: boolean;
} = {
  inputs: [1n, 2n],
  expected: 0n, // TODO: replace with circuit-derived digest; do not ship as 0n.
  finalized: false,
};
