pragma circom 2.1.6;

// =============================================================================
// dvp.circom - atomic two-asset settlement (DEMO: single combined proof) (FIN-016)
// =============================================================================
//
// Top-level circuit: fixes the production parameters D=20, K_a=K_r=5 (LOCKED
// FIN-001) and declares the public-signal `main` in the canonical order. The
// reusable Dvp(D,K_a,K_r) template lives in lib/dvp.circom so the same body can
// be instantiated at a small depth by the test harness.
//
// COMPILE WITH:  circom dvp.circom --prime bls12381 --r1cs --wasm --sym
//   (`--prime bls12381` is a COMPILER flag, not a pragma. Without it the field is
//    BN254 and every Poseidon-BLS hash is wrong - Security invariant #1.)
//
// -----------------------------------------------------------------------------
// !!! NON-PRODUCTION DEMO CIRCUIT (Security invariant #15) - see lib/dvp.circom.
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
// PUBLIC INPUT ORDER - MUST match docs/PUBLIC_IO.md and DvpPublicInputs in
// contracts/finnes/src/types.rs. 74 public signals (D=20, K_a=K_r=5):
// -----------------------------------------------------------------------------
//  0  anchor_root        1  kyc_root      2  sanction_root   3  assets_root
//  4  frozen_root        5  auditor_pk
//  6  nf_legX_0          7  nf_legY_0
//  8  cm_out_X           9  cm_out_Y
// 10  new_root          11  fee_X        12  fee_Y          13  next_index
// 14 .. 33   old_frontier[0..19]
// 34 .. 53   new_frontier[0..19]
// 54 .. 58   c_auditor_X[0..4]   59 .. 63  c_auditor_Y[0..4]
// 64 .. 68   c_recipient_X[0..4] 69 .. 73  c_recipient_Y[0..4]
//   total = 14 + 2·20 + 2·5 + 2·5 = 74
// -----------------------------------------------------------------------------

include "lib/dvp.circom";

component main { public [
    anchor_root,
    kyc_root,
    sanction_root,
    assets_root,
    frozen_root,
    auditor_pk,
    nf_legX_0,
    nf_legY_0,
    cm_out_X,
    cm_out_Y,
    new_root,
    fee_X,
    fee_Y,
    next_index,
    old_frontier,
    new_frontier,
    c_auditor_X,
    c_auditor_Y,
    c_recipient_X,
    c_recipient_Y
] } = Dvp(20, 5, 5);
