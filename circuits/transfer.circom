pragma circom 2.1.6;

// =============================================================================
// transfer.circom - confidential transfer, 2-in / 2-out, single asset
// =============================================================================
//
// FIN-006 COMPLETE. This top-level file fixes the PRODUCTION parameters and the
// normative public-signal ordering on `main`; the reusable circuit body lives in
// `lib/transfer.circom` as `Transfer(D, K_a, K_r)` so the same template can be
// instantiated at a small depth by the circuit-test harness
// (`circuits/test/transfer/transfer_test.circom`) without a second `main`. The
// FIN-006 wiring is done in the template:
//   (a) BOTH output notes carry a mandatory c_auditor + a c_recipient (the
//       PUBLIC_IO layout carries 2·K_a + 2·K_r - Security invariant #5: every
//       output note, including the change note, MUST be auditor-encrypted);
//   (b) `next_index` is a PUBLIC INPUT pinned to the contract's leaf count
//       (the contract checks pi.next_index == state.leaf_count), so the frontier
//       transition is sound across more than the first transaction (the prior
//       `nextIndex <== 0` placeholder inserted at index 0 every time, which
//       silently corrupted the tree after tx #1);
//   (c) `kyc_leaf` is bound to output note 0's owner_pk (demo recipient; KYC
//       privacy deferred to production per CLAUDE.md "out of scope").
// The depth/packing constants and all gadget interfaces are de-drifted to the
// libs (D=20, K_a=K_r=5).
//
// COMPILE WITH:  circom transfer.circom --prime bls12381 --r1cs --wasm --sym
//   `--prime bls12381` is a COMPILER FLAG, not a pragma. Without it the field is
//   BN254 and every Poseidon-BLS hash is wrong (Security invariant #1).
//
// -----------------------------------------------------------------------------
// PUBLIC INPUT ORDER - COPIED VERBATIM FROM docs/PUBLIC_IO.md
// (THE canonical ordering. Must match contracts/finnes/src/types.rs
//  PublicInputs::to_vec(), prover/src/witness.ts, and sdk/src/.)
// -----------------------------------------------------------------------------
//  0  anchor_root
//  1  kyc_root
//  2  sanction_root
//  3  assets_root
//  4  frozen_root
//  5  auditor_pk          (= Poseidon(k_view); single field, LOCKED FIN-001)
//  6  nf_in_0
//  7  nf_in_1
//  8  cm_out_0
//  9  cm_out_1
// 10  new_root
// 11  fee                 (per-asset; 0 in demo)
// 12  next_index          (contract leaf count; checked == state. FIN-006)
// 13 .. 13+D-1            old_frontier[0..D-1]    (D = 20)
//    .. +D                new_frontier[0..D-1]
//    .. +K_a              c_auditor[0]  (output note 0; K_a = 5)
//    .. +K_a              c_auditor[1]  (output note 1 / change; MANDATORY, inv #5)
//    .. +K_r              c_recipient[0] (output note 0)
//    .. +K_r              c_recipient[1] (output note 1 / change)
// Total: 73 public signals (13 + 2·D + 2·K_a + 2·K_r).
// -----------------------------------------------------------------------------

include "lib/transfer.circom";

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
    nf_in_1,
    cm_out_0,
    cm_out_1,
    new_root,
    fee,
    next_index,
    old_frontier,
    new_frontier,
    c_auditor,
    c_recipient
] } = Transfer(20, 5, 5);
