pragma circom 2.1.6;

// =============================================================================
// unshield.circom - shielded -> transparent (1 shielded input, transparent out)
// =============================================================================
//
// FIN-013 COMPLETE. Fixes the PRODUCTION parameters and the normative
// public-signal ordering on `main`; the reusable body lives in
// `lib/unshield.circom` as `Unshield(D, K_a, K_r)` so the same template can be
// instantiated at a small depth by the circuit-test harness
// (`circuits/test/unshield/unshield_test.circom`). The FIN-013 wiring:
//   (a) the spent commitment proves FROZEN-SET NON-MEMBERSHIP (escape-hatch
//       closure) and the transparent `recipient` proves KYC membership +
//       sanctions non-membership (invariant #19);
//   (b) the change note carries a MANDATORY c_auditor + a c_recipient, both gated
//       on the `cm_change_0 == 0` no-change sentinel (all-zero when no change);
//   (c) `next_index` is a PUBLIC INPUT pinned to the contract leaf count (the
//       same insert-position soundness fix as FIN-006/012, invariants #11/#12);
//   (d) the conditional frontier transition: inserting the gated cm_change_0
//       reproduces the current root when there is no change, and new_frontier is
//       MUX'd to old_frontier in that case.
// The scaffold's broken circomlib include, wrong MerkleNonMembership/enc-check
// signatures, and the missing c_recipient (PUBLIC_IO.md carries K_a + K_r) are
// all corrected; D/K constants de-drifted to D=20, K_a=K_r=5.
//
// COMPILE WITH:  circom unshield.circom --prime bls12381 --r1cs --wasm --sym
//   `--prime bls12381` is a COMPILER FLAG, not a pragma (Security invariant #1).
//
// -----------------------------------------------------------------------------
// PUBLIC INPUT ORDER - COPIED VERBATIM FROM docs/PUBLIC_IO.md § unshield.circom
// (THE canonical ordering. Must match contracts/finnes/src/types.rs
//  UnshieldPublicInputs::to_scalars(), the prover, and sdk/src/.)
// -----------------------------------------------------------------------------
//  0  anchor_root
//  1  kyc_root            (transparent recipient compliance)
//  2  sanction_root
//  3  assets_root
//  4  frozen_root
//  5  auditor_pk          (= Poseidon(k_view); single field, LOCKED FIN-001)
//  6  nf_in_0
//  7  asset_id            (public - for the SAC transfer)
//  8  amount              (public - raw SAC units leaving)
//  9  recipient           (public - transparent Stellar address; single field)
// 10  cm_change_0         (change note; 0 SENTINEL = no change)
// 11  new_root
// 12  fee
// 13  next_index          (contract leaf count; checked == state. FIN-013)
// 14 .. 14+D-1            old_frontier[0..D-1]    (D = 20)
//    .. +D                new_frontier[0..D-1]
//    .. +K_a              c_auditor   (change note; all-zero when cm_change_0 == 0)
//    .. +K_r              c_recipient (change note; all-zero when cm_change_0 == 0)
// Total: 64 public signals (14 + 2·D + K_a + K_r = 14 + 40 + 5 + 5).
// -----------------------------------------------------------------------------

include "lib/unshield.circom";

// -----------------------------------------------------------------------------
// main - public signal order MUST match docs/PUBLIC_IO.md (see header).
// D=20, K_a=K_r=5 (LOCKED FIN-001). Changing D / K_a / K_r requires a fresh
// phase-2 ceremony + new VK.
// -----------------------------------------------------------------------------
component main { public [
    anchor_root,
    kyc_root,
    sanction_root,
    assets_root,
    frozen_root,
    auditor_pk,
    nf_in_0,
    asset_id,
    amount,
    recipient,
    cm_change_0,
    new_root,
    fee,
    next_index,
    old_frontier,
    new_frontier,
    c_auditor,
    c_recipient
] } = Unshield(20, 5, 5);
