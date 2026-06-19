//! Contract test skeleton.
//!
//! These are scaffolds. The Groth16 verify (`verifier.rs`) is a TODO, so the
//! positive (proof-accepted) paths cannot pass until the pairing math and real
//! VK/proof test vectors exist. The negative/structural paths (double-init,
//! uninitialised access, double-spend rejection, stale-root rejection) exercise
//! the contract's ordered checks **before** the proof step and are wired up to
//! be filled in once helper fixtures land.
//!
//! Every circuit must ship a passing AND a failing witness (CLAUDE.md →
//! Conventions / Tests); the corresponding fixtures belong under `setup/` and
//! the prover, surfaced here as `TODO` constructors.

extern crate std;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

use crate::errors::Error;
use crate::types::{
    InitConfig, Proof, Root, Scalar, TransferPublicInputs, VerifyingKey, TREE_DEPTH,
};
use crate::{FinnesContract, FinnesContractClient};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// All-zero 32-byte field element / root placeholder.
fn zero32(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

/// A distinct non-zero 32-byte value (last byte = `tag`) for fixtures.
fn tagged32(env: &Env, tag: u8) -> BytesN<32> {
    let mut b = [0u8; 32];
    b[31] = tag;
    BytesN::from_array(env, &b)
}

/// An empty-but-correctly-sized frontier (`TREE_DEPTH` zero scalars).
fn empty_frontier(env: &Env) -> Vec<Scalar> {
    let mut v: Vec<Scalar> = Vec::new(env);
    for _ in 0..TREE_DEPTH {
        v.push_back(zero32(env));
    }
    v
}

/// A placeholder verifying key. TODO: replace with a real per-circuit VK
/// exported from the phase-2 ceremony (`setup/`); `ic` length must equal the
/// circuit's public-input count + 1 or `verify_groth16` returns
/// `VerifyingKeyArityMismatch`.
fn dummy_vk(env: &Env) -> VerifyingKey {
    use soroban_sdk::Bytes;
    let empty = Bytes::new(env);
    VerifyingKey {
        alpha_g1: empty.clone(),
        beta_g2: empty.clone(),
        gamma_g2: empty.clone(),
        delta_g2: empty.clone(),
        ic: Vec::new(env), // TODO: real IC points
    }
}

/// Register the contract and run `init` with placeholder config. Returns the
/// client plus the admin/issuer addresses.
fn setup(env: &Env) -> (FinnesContractClient<'static>, Address, Address) {
    let contract_id = env.register(FinnesContract, ());
    let client = FinnesContractClient::new(env, &contract_id);

    let admin = Address::generate(env);
    let issuer = Address::generate(env);
    let auditor_pk: Scalar = tagged32(env, 0xAA);
    let kyc: Root = tagged32(env, 0x01);
    let sanction: Root = tagged32(env, 0x02);
    let assets: Root = tagged32(env, 0x03);
    let frozen: Root = tagged32(env, 0x04);
    let init_root: Root = tagged32(env, 0x10);

    // `mock_all_auths` lets `require_auth` calls pass in unit tests.
    env.mock_all_auths();

    let cfg = InitConfig {
        admin: admin.clone(),
        issuer_authority: issuer.clone(),
        auditor_pk,
        kyc_root: kyc,
        sanction_root: sanction,
        assets_root: assets,
        frozen_root: frozen,
        initial_frontier: empty_frontier(env),
        initial_root: init_root,
        vk_shield: dummy_vk(env),
        vk_transfer: dummy_vk(env),
        vk_unshield: dummy_vk(env),
        vk_dvp: dummy_vk(env),
    };
    client.init(&cfg);

    (client, admin, issuer)
}

// ---------------------------------------------------------------------------
// Lifecycle / structural tests (do not require a valid proof).
// ---------------------------------------------------------------------------

#[test]
fn init_sets_root_and_window() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    assert_eq!(client.current_root(), Some(tagged32(&env, 0x10)));
}

#[test]
#[should_panic] // AlreadyInitialized
fn double_init_rejected() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    // Second init must fail. TODO: assert on the specific Error code via
    // `try_init` once fixtures are factored out.
    let cfg = InitConfig {
        admin: Address::generate(&env),
        issuer_authority: Address::generate(&env),
        auditor_pk: tagged32(&env, 0xAA),
        kyc_root: tagged32(&env, 0x01),
        sanction_root: tagged32(&env, 0x02),
        assets_root: tagged32(&env, 0x03),
        frozen_root: tagged32(&env, 0x04),
        initial_frontier: empty_frontier(&env),
        initial_root: tagged32(&env, 0x10),
        vk_shield: dummy_vk(&env),
        vk_transfer: dummy_vk(&env),
        vk_unshield: dummy_vk(&env),
        vk_dvp: dummy_vk(&env),
    };
    client.init(&cfg);
}

#[test]
fn unused_nullifier_reports_false() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let nf = tagged32(&env, 0x77);
    assert!(!client.is_nullifier_used(&nf));
}

#[test]
fn admin_can_update_kyc_root() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let new_kyc = tagged32(&env, 0x21);
    // Issuer authority is mocked-authorised in `setup`.
    client.update_kyc_root(&new_kyc);
    // No getter for kyc_root exposed; a future revision can add a view to assert.
    // TODO: add `kyc_root()` view + assert equality here.
}

// ---------------------------------------------------------------------------
// Transfer-flow tests (BLOCKED on real proof verification).
// ---------------------------------------------------------------------------

/// Build a `TransferPublicInputs` whose roots all match the `setup` state, so a
/// call reaches the ordered checks down to `next_index` / the verifier. Only
/// `next_index` is parameterised here. Ciphertext vectors are the canonical
/// 2·K_a / 2·K_r length (10 each); the verifier is never reached in these
/// pre-proof tests.
fn transfer_pi(env: &Env, next_index: Scalar) -> TransferPublicInputs {
    use soroban_sdk::Bytes;
    let mut cts: Vec<Scalar> = Vec::new(env);
    for _ in 0..10u32 {
        cts.push_back(zero32(env));
    }
    let _ = Bytes::new(env);
    TransferPublicInputs {
        anchor_root: tagged32(env, 0x10), // == init_root, in the recent-roots window
        kyc_root: tagged32(env, 0x01),
        sanction_root: tagged32(env, 0x02),
        assets_root: tagged32(env, 0x03),
        frozen_root: tagged32(env, 0x04),
        auditor_pk: tagged32(env, 0xAA),
        nf_in_0: tagged32(env, 0x55),
        nf_in_1: tagged32(env, 0x56),
        cm_out_0: tagged32(env, 0x60),
        cm_out_1: tagged32(env, 0x61),
        new_root: tagged32(env, 0x11),
        fee: zero32(env),
        next_index,
        old_frontier: empty_frontier(env),
        new_frontier: empty_frontier(env),
        c_auditor: cts.clone(),
        c_recipient: cts,
    }
}

fn dummy_proof(env: &Env) -> Proof {
    use soroban_sdk::Bytes;
    Proof {
        a: Bytes::new(env),
        b: Bytes::new(env),
        c: Bytes::new(env),
    }
}

#[test]
fn transfer_rejects_wrong_next_index() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    // Stored leaf count is 0; supplying next_index = 5 must be rejected BEFORE the
    // proof step (invariants #11/#12) so a prover cannot pick the insert position.
    let pi = transfer_pi(&env, tagged32(&env, 0x05));
    let res = client.try_confidential_transfer(&dummy_proof(&env), &pi);
    assert_eq!(res, Err(Ok(Error::NextIndexMismatch)));
}

#[test]
fn transfer_correct_next_index_passes_gate_then_hits_verifier() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    // next_index = 0 matches the empty-tree leaf count, so the next_index gate
    // passes and the flow proceeds to the verifier. The dummy VK has 0 IC points,
    // so we land on VerifyingKeyArityMismatch - NOT NextIndexMismatch. This proves
    // the gate accepts the true index and fails open only at the (unimplemented)
    // proof step.
    let pi = transfer_pi(&env, zero32(&env));
    let res = client.try_confidential_transfer(&dummy_proof(&env), &pi);
    assert_eq!(res, Err(Ok(Error::VerifyingKeyArityMismatch)));
}

// TODO: positive `confidential_transfer` - needs (a) a real Transfer VK, (b) a
//       proof + public inputs from the prover for a 2-in/2-out witness, (c)
//       `verifier::verify_groth16` implemented. Until then this path returns
//       Error::InvalidProof by construction (the verifier placeholder refuses).
//
// TODO: negative - double-spend: submit a transfer reusing a nullifier already
//       inserted; expect Error::NullifierAlreadyUsed (this check runs BEFORE the
//       proof, so it is testable without real proof math once we can insert a
//       nullifier via a successful prior transfer or a test seam).
//
// TODO: negative - stale frozen_root: supply a frozen_root != state; expect
//       Error::StaleFrozenRoot (also pre-proof; testable now with a test seam to
//       set public inputs).
//
// TODO: negative - unknown anchor root: supply an anchor_root not in the window;
//       expect Error::UnknownAnchorRoot.
//
// TODO: unshield - assert frozen_root strict + zero-recipient rejection
//       (Error::RecipientNotAuthorised), then the full happy path once proofs land.
//
// TODO: settle_dvp - assert both `require_auth`s are demanded and a single proof
//       path is taken (invariant #7).
//
// TODO: freeze - assert AlreadyFrozen on a repeat, and that frozen_root advances.

// ---------------------------------------------------------------------------
// Groth16 verifier (FIN-009) - exercises `verifier::verify_groth16` directly
// against a REAL BLS12-381 proof.
//
// The vectors in `test_vectors.rs` are a genuine snarkjs proof for the depth-4
// `transfer_test4` demo circuit (41 public signals), generated by
// `npm run verifier:fixture` and encoded in the Soroban host's point layout.
// We test the pairing math at the `verify_groth16` boundary because the full
// `confidential_transfer` entrypoint is hard-wired to the D=20 layout (73
// signals) and a production proof for it awaits the heavier D=20 ceremony
// (FIN-007 production note); the math under test is identical.
// ---------------------------------------------------------------------------

use crate::test_vectors as tv;
use crate::verifier;

fn real_vk(env: &Env) -> VerifyingKey {
    use soroban_sdk::Bytes;
    let mut ic: Vec<Bytes> = Vec::new(env);
    for p in tv::VK_IC.iter() {
        ic.push_back(Bytes::from_slice(env, p));
    }
    VerifyingKey {
        alpha_g1: Bytes::from_slice(env, tv::VK_ALPHA_G1),
        beta_g2: Bytes::from_slice(env, tv::VK_BETA_G2),
        gamma_g2: Bytes::from_slice(env, tv::VK_GAMMA_G2),
        delta_g2: Bytes::from_slice(env, tv::VK_DELTA_G2),
        ic,
    }
}

fn real_proof(env: &Env) -> Proof {
    use soroban_sdk::Bytes;
    Proof {
        a: Bytes::from_slice(env, tv::PROOF_A),
        b: Bytes::from_slice(env, tv::PROOF_B),
        c: Bytes::from_slice(env, tv::PROOF_C),
    }
}

fn real_public_inputs(env: &Env) -> Vec<Scalar> {
    let mut v: Vec<Scalar> = Vec::new(env);
    for s in tv::PUBLIC_SIGNALS.iter() {
        v.push_back(BytesN::from_array(env, s));
    }
    v
}

#[test]
fn verifier_accepts_real_proof() {
    let env = Env::default();
    // A full Groth16 verify (MSM over the public inputs + a 4-pair pairing-check)
    // exceeds the test env's default CPU budget; lift it so the host runs the
    // real curve math. On-chain the cost is bounded by the protocol budget and is
    // dominated by the single pairing (invariant #7) - measured via
    // simulateTransaction at deploy time, not here.
    env.cost_estimate().budget().reset_unlimited();
    let vk = real_vk(&env);
    let proof = real_proof(&env);
    let pi = real_public_inputs(&env);
    // The real proof MUST satisfy the pairing equation for the matching VK +
    // public inputs (invariant #1: BLS12-381 host pairing-check).
    assert_eq!(verifier::verify_groth16(&env, &vk, &proof, &pi), Ok(()));
}

#[test]
fn verifier_rejects_tampered_public_input() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let vk = real_vk(&env);
    let proof = real_proof(&env);
    let mut pi = real_public_inputs(&env);
    // Flip one bit of public signal index 6 (nf_in_0 in the transfer layout):
    // vk_x changes, the pairing equation no longer holds -> InvalidProof. Proves
    // the VK genuinely binds every public input (invariant #5/#12).
    let mut bad = tv::PUBLIC_SIGNALS[6];
    bad[31] ^= 0x01;
    pi.set(6, BytesN::from_array(&env, &bad));
    assert_eq!(
        verifier::verify_groth16(&env, &vk, &proof, &pi),
        Err(Error::InvalidProof)
    );
}

#[test]
fn verifier_rejects_arity_mismatch() {
    let env = Env::default();
    let vk = real_vk(&env);
    let proof = real_proof(&env);
    let mut pi = real_public_inputs(&env);
    // One extra input makes n_pub + 1 != ic.len(): rejected before any pairing.
    pi.push_back(zero32(&env));
    assert_eq!(
        verifier::verify_groth16(&env, &vk, &proof, &pi),
        Err(Error::VerifyingKeyArityMismatch)
    );
}

#[test]
fn verifier_rejects_malformed_proof_point() {
    let env = Env::default();
    use soroban_sdk::Bytes;
    let vk = real_vk(&env);
    let pi = real_public_inputs(&env);
    // A1: a too-short A point must be rejected structurally (no panic, no unwrap).
    let proof = Proof {
        a: Bytes::from_slice(&env, &[0u8; 95]),
        b: Bytes::from_slice(&env, tv::PROOF_B),
        c: Bytes::from_slice(&env, tv::PROOF_C),
    };
    assert_eq!(
        verifier::verify_groth16(&env, &vk, &proof, &pi),
        Err(Error::MalformedProof)
    );
}
