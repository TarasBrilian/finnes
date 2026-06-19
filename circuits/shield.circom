pragma circom 2.1.6;

// =============================================================================
// shield.circom - transparent -> shielded (0 shielded inputs, 1 transparent in)
// =============================================================================
//
// FIN-012 COMPLETE. This top-level file fixes the PRODUCTION parameters and the
// normative public-signal ordering on `main`; the reusable circuit body lives in
// `lib/shield.circom` as `Shield(D, K_a, K_r)` so the same template can be
// instantiated at a small depth by the circuit-test harness
// (`circuits/test/shield/shield_test.circom`) without a second `main`. The
// FIN-012 wiring is done in the template:
//   (a) the output note carries a MANDATORY c_auditor + a c_recipient (inv #5);
//   (b) `next_index` is a PUBLIC INPUT pinned to the contract's leaf count
//       (the contract checks pi.next_index == state.leaf_count), so the frontier
//       transition is sound across more than the first transaction (the prior
//       private `nextIndex` witness let a prover insert at index 0 every time,
//       silently corrupting the tree after tx #1 - the same hole FIN-006 closed
//       for transfer, invariants #11/#12);
//   (c) the output cm opens to the PUBLIC (asset_id, amount) without revealing
//       (owner_pk, rho, r_note), with self-binding asset_id = Poseidon(sac_address)
//       (invariant #18, via AssetsMembership).
// The depth/packing constants and all gadget interfaces are de-drifted to the
// libs (D=20, K_a=K_r=5) and the broken circomlib include / wrong enc-check
// signatures from the scaffold are removed.
//
// COMPILE WITH:  circom shield.circom --prime bls12381 --r1cs --wasm --sym
//   `--prime bls12381` is a COMPILER FLAG, not a pragma. Without it the field is
//   BN254 and every Poseidon-BLS hash is wrong (Security invariant #1).
//
// -----------------------------------------------------------------------------
// PUBLIC INPUT ORDER - COPIED VERBATIM FROM docs/PUBLIC_IO.md § shield.circom
// (THE canonical ordering. Must match contracts/finnes/src/types.rs
//  ShieldPublicInputs::to_scalars(), the prover, and sdk/src/.)
// -----------------------------------------------------------------------------
//  0  asset_id            (public - derived from deposited SAC; = Poseidon(sac_address))
//  1  amount              (public - deposited raw SAC units)
//  2  kyc_root            (depositor/owner KYC membership)
//  3  assets_root
//  4  auditor_pk          (= Poseidon(k_view); single field, LOCKED FIN-001)
//  5  cm_out_0
//  6  new_root
//  7  fee                 (per-asset; 0 in demo)
//  8  next_index          (contract leaf count; checked == state. FIN-012)
//  9 .. 9+D-1             old_frontier[0..D-1]    (D = 20)
//    .. +D                new_frontier[0..D-1]
//    .. +K_a              c_auditor               (mandatory, inv #5)
//    .. +K_r              c_recipient
// Total: 59 public signals (9 + 2·D + K_a + K_r = 9 + 40 + 5 + 5).
// -----------------------------------------------------------------------------

include "lib/shield.circom";

// -----------------------------------------------------------------------------
// main - public signal order MUST match docs/PUBLIC_IO.md (see header).
// D=20, K_a=K_r=5 (LOCKED FIN-001). Changing D / K_a / K_r requires a fresh
// phase-2 ceremony + new VK.
// -----------------------------------------------------------------------------
component main { public [
    asset_id,
    amount,
    kyc_root,
    assets_root,
    auditor_pk,
    cm_out_0,
    new_root,
    fee,
    next_index,
    old_frontier,
    new_frontier,
    c_auditor,
    c_recipient
] } = Shield(20, 5, 5);
