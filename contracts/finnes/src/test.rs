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
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::{Address, BytesN, Env, Vec};

use crate::errors::Error;
use crate::sac;
use crate::types::{
    InitConfig, Proof, Root, Scalar, ShieldPublicInputs, TransferPublicInputs,
    UnshieldPublicInputs, VerifyingKey, TREE_DEPTH,
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

// The ordered pre-proof checks (unknown anchor, double-spend, stale frozen_root,
// windowed kyc) are covered by the FIN-011 tests at the bottom of this file; the
// Groth16 verify itself (FIN-009) is exercised directly in the verifier section
// above against a real BLS12-381 proof.
//
// TODO: positive `confidential_transfer` end-to-end through the entrypoint - needs
//       a real D=20 Transfer VK + a proof/public-inputs for a 2-in/2-out witness
//       (the heavier D=20 ceremony, FIN-007 production note). The pre-proof gate
//       and the verify math are each already tested; only their composition awaits
//       the ceremony.
//
// TODO: settle_dvp - assert both `require_auth`s are demanded and a single proof
//       path is taken (invariant #7).
//
// TODO: freeze - assert AlreadyFrozen on a repeat (the happy path + event are now
//       covered by `freeze_emits_event_for_the_indexer`).

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

// ---------------------------------------------------------------------------
// SAC token movement on the shield / unshield boundary (FIN-010).
//
// The full positive path *through the entrypoints* needs a real D=20 proof
// (same ceremony friction as FIN-009), so we test the two halves that ARE
// reachable without one:
//   1. the SAC pull/push helpers move a real test SAC in/out via the admin
//      registry + amount decoding (run inside `as_contract`), and
//   2. the entrypoints gate those effects: an invalid proof reverts before any
//      SAC moves (verify-before-effects), and an unregistered transparent
//      recipient is rejected.
// ---------------------------------------------------------------------------

/// A 64-bit raw SAC amount as a big-endian `Fr` scalar (low 8 bytes).
fn amount_scalar(env: &Env, v: u64) -> Scalar {
    let mut b = [0u8; 32];
    b[24..32].copy_from_slice(&v.to_be_bytes());
    BytesN::from_array(env, &b)
}

/// Five zero ciphertext slots (K_a = K_r = 5).
fn zero_ct(env: &Env) -> Vec<Scalar> {
    let mut v: Vec<Scalar> = Vec::new(env);
    for _ in 0..5u32 {
        v.push_back(zero32(env));
    }
    v
}

/// A `ShieldPublicInputs` whose roots match `setup` state, reaching the verifier.
fn shield_pi(
    env: &Env,
    asset_id: Scalar,
    amount: Scalar,
    next_index: Scalar,
) -> ShieldPublicInputs {
    ShieldPublicInputs {
        asset_id,
        amount,
        kyc_root: tagged32(env, 0x01),
        assets_root: tagged32(env, 0x03),
        auditor_pk: tagged32(env, 0xAA),
        cm_out_0: tagged32(env, 0x60),
        new_root: tagged32(env, 0x11),
        fee: zero32(env),
        next_index,
        old_frontier: empty_frontier(env),
        new_frontier: empty_frontier(env),
        c_auditor: zero_ct(env),
        c_recipient: zero_ct(env),
    }
}

/// An `UnshieldPublicInputs` whose roots match `setup` state.
fn unshield_pi(
    env: &Env,
    asset_id: Scalar,
    amount: Scalar,
    recipient: Scalar,
) -> UnshieldPublicInputs {
    UnshieldPublicInputs {
        anchor_root: tagged32(env, 0x10),
        kyc_root: tagged32(env, 0x01),
        sanction_root: tagged32(env, 0x02),
        assets_root: tagged32(env, 0x03),
        frozen_root: tagged32(env, 0x04),
        auditor_pk: tagged32(env, 0xAA),
        nf_in_0: tagged32(env, 0x55),
        asset_id,
        amount,
        recipient,
        cm_change_0: zero32(env), // exact spend, no change note
        new_root: tagged32(env, 0x11),
        fee: zero32(env),
        next_index: zero32(env),
        old_frontier: empty_frontier(env),
        new_frontier: empty_frontier(env),
        c_auditor: zero_ct(env),
        c_recipient: zero_ct(env),
    }
}

#[test]
fn scalar_to_i128_decodes_64bit_amount() {
    let env = Env::default();
    assert_eq!(sac::scalar_to_i128(&amount_scalar(&env, 700)), Ok(700i128));
    assert_eq!(sac::scalar_to_i128(&zero32(&env)), Ok(0i128));
    assert_eq!(
        sac::scalar_to_i128(&amount_scalar(&env, u64::MAX)),
        Ok(u64::MAX as i128)
    );
}

#[test]
fn scalar_to_i128_rejects_oversized_amount() {
    let env = Env::default();
    // A byte just above the low 8 means value >= 2^64 -> not a valid raw amount.
    let mut b = [0u8; 32];
    b[23] = 1;
    let s: Scalar = BytesN::from_array(&env, &b);
    assert_eq!(sac::scalar_to_i128(&s), Err(Error::MalformedPublicInputs));
}

#[test]
fn sac_moves_in_and_out_through_registry() {
    let env = Env::default();
    let (client, admin, _issuer) = setup(&env); // setup mocks all auths
                                                // The SAC `transfer(depositor, ...)` runs INSIDE `as_contract` (a sub-contract
                                                // call not tied to a root invocation), so allow non-root authorization.
    env.mock_all_auths_allowing_non_root_auth();
    let contract_id = client.address.clone();

    let depositor = Address::generate(&env);
    let recipient = Address::generate(&env);
    let sac_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let sac_addr = sac_contract.address();
    StellarAssetClient::new(&env, &sac_addr).mint(&depositor, &1000);
    let token = TokenClient::new(&env, &sac_addr);

    // Mirror the registry: asset_id -> SAC address.
    let asset_id: Scalar = tagged32(&env, 0x77);
    client.register_asset(&asset_id, &sac_addr);

    // shield: pull 700 depositor -> contract.
    env.as_contract(&contract_id, || {
        sac::pull_deposit(&env, &asset_id, &depositor, &amount_scalar(&env, 700)).unwrap();
    });
    assert_eq!(token.balance(&depositor), 300);
    assert_eq!(token.balance(&contract_id), 700);

    // unshield: pay 700 contract -> recipient.
    env.as_contract(&contract_id, || {
        sac::pay_out(&env, &asset_id, &recipient, &amount_scalar(&env, 700)).unwrap();
    });
    assert_eq!(token.balance(&contract_id), 0);
    assert_eq!(token.balance(&recipient), 700);
}

#[test]
fn pull_deposit_unregistered_asset_errors() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let contract_id = client.address.clone();
    let depositor = Address::generate(&env);
    let asset_id: Scalar = tagged32(&env, 0x78); // never registered
    let res = env.as_contract(&contract_id, || {
        sac::pull_deposit(&env, &asset_id, &depositor, &amount_scalar(&env, 100))
    });
    assert_eq!(res, Err(Error::AssetNotRegistered));
}

#[test]
fn shield_reverts_before_moving_sac_on_invalid_proof() {
    let env = Env::default();
    let (client, admin, _issuer) = setup(&env);
    let contract_id = client.address.clone();

    let depositor = Address::generate(&env);
    let sac_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let sac_addr = sac_contract.address();
    StellarAssetClient::new(&env, &sac_addr).mint(&depositor, &1000);
    let token = TokenClient::new(&env, &sac_addr);

    let asset_id: Scalar = tagged32(&env, 0x77);
    client.register_asset(&asset_id, &sac_addr);

    // The dummy VK has 0 IC points, so verify fails (arity mismatch) BEFORE the
    // SAC pull. Verify-before-effects => no token moves.
    let pi = shield_pi(&env, asset_id, amount_scalar(&env, 700), zero32(&env));
    let res = client.try_shield(&depositor, &dummy_proof(&env), &pi);
    assert_eq!(res, Err(Ok(Error::VerifyingKeyArityMismatch)));
    assert_eq!(token.balance(&depositor), 1000);
    assert_eq!(token.balance(&contract_id), 0);
}

#[test]
fn unshield_unregistered_recipient_rejected() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let asset_id: Scalar = tagged32(&env, 0x77);
    let recipient: Scalar = tagged32(&env, 0x90); // not in the demo account registry
    let pi = unshield_pi(&env, asset_id, amount_scalar(&env, 700), recipient);
    let res = client.try_unshield(&dummy_proof(&env), &pi);
    assert_eq!(res, Err(Ok(Error::RecipientNotAuthorised)));
}

#[test]
fn unshield_registered_recipient_passes_gate_then_hits_verifier() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let asset_id: Scalar = tagged32(&env, 0x77);
    let recipient_field: Scalar = tagged32(&env, 0x90);
    let recipient_addr = Address::generate(&env);
    // Register the demo account; the recipient gate now resolves and the flow
    // proceeds to the verifier (dummy VK -> arity mismatch), proving the gate
    // accepts a registered recipient and only fails open at the proof step.
    client.register_transparent(&recipient_field, &recipient_addr);
    let pi = unshield_pi(&env, asset_id, amount_scalar(&env, 700), recipient_field);
    let res = client.try_unshield(&dummy_proof(&env), &pi);
    assert_eq!(res, Err(Ok(Error::VerifyingKeyArityMismatch)));
}

// ---------------------------------------------------------------------------
// FIN-011: ordered checks, windowed compliance roots, and indexer events.
//
// These exercise the pre-proof half of the canonical order (invariant #9):
//   anchor window -> nullifier unused -> compliance roots -> (verify) -> mutate.
// Each fails at exactly its own step (the dummy VK means a flow that passes all
// pre-proof checks lands on VerifyingKeyArityMismatch at the verify step, which
// is the marker for "reached the verifier"). Event emission is tested on the
// admin paths (freeze / root update), which are not proof-gated.
// ---------------------------------------------------------------------------

use crate::events as ev;
use crate::state;
use soroban_sdk::testutils::Events;
use soroban_sdk::{symbol_short, vec, IntoVal};

#[test]
fn ordered_unknown_anchor_root_rejected_first() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let mut pi = transfer_pi(&env, zero32(&env));
    pi.anchor_root = tagged32(&env, 0xEE); // not in the recent-roots window
    assert_eq!(
        client.try_confidential_transfer(&dummy_proof(&env), &pi),
        Err(Ok(Error::UnknownAnchorRoot))
    );
}

#[test]
fn ordered_double_spent_nullifier_rejected_before_proof() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let contract_id = client.address.clone();
    // Seed nf_in_0 (0x55, from transfer_pi) as already spent, then reuse it.
    env.as_contract(&contract_id, || {
        state::insert_nullifier(&env, &tagged32(&env, 0x55));
    });
    let pi = transfer_pi(&env, zero32(&env));
    assert_eq!(
        client.try_confidential_transfer(&dummy_proof(&env), &pi),
        Err(Ok(Error::NullifierAlreadyUsed))
    );
}

#[test]
fn ordered_stale_frozen_root_rejected_strictly() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let mut pi = transfer_pi(&env, zero32(&env));
    pi.frozen_root = tagged32(&env, 0xEE); // frozen_root is STRICT (invariant #6)
    assert_eq!(
        client.try_confidential_transfer(&dummy_proof(&env), &pi),
        Err(Ok(Error::StaleFrozenRoot))
    );
}

#[test]
fn windowed_kyc_root_accepts_prior_root_after_update() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    // Rotate the kyc root; the prior value (0x01) must stay within the window.
    client.update_kyc_root(&tagged32(&env, 0x21));

    let mut pi = transfer_pi(&env, zero32(&env)); // kyc_root = 0x01 (prior)
                                                  // Prior root still accepted -> flow proceeds past compliance to the verifier.
    assert_eq!(
        client.try_confidential_transfer(&dummy_proof(&env), &pi),
        Err(Ok(Error::VerifyingKeyArityMismatch))
    );
    // The new root is accepted too.
    pi.kyc_root = tagged32(&env, 0x21);
    assert_eq!(
        client.try_confidential_transfer(&dummy_proof(&env), &pi),
        Err(Ok(Error::VerifyingKeyArityMismatch))
    );
    // A never-published root is windowed-out (StaleKycRoot).
    pi.kyc_root = tagged32(&env, 0xEE);
    assert_eq!(
        client.try_confidential_transfer(&dummy_proof(&env), &pi),
        Err(Ok(Error::StaleKycRoot))
    );
}

#[test]
fn freeze_emits_event_for_the_indexer() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let cm = tagged32(&env, 0xC1);
    let new_frozen = tagged32(&env, 0x44);
    client.freeze(&cm, &new_frozen);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("freeze"),).into_val(&env),
                ev::FreezeEvent {
                    cm_target: cm,
                    new_frozen_root: new_frozen,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn update_kyc_root_emits_event_for_the_indexer() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let new_kyc = tagged32(&env, 0x21);
    client.update_kyc_root(&new_kyc);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("rootupd"),).into_val(&env),
                ev::RootUpdatedEvent {
                    kind: symbol_short!("kyc"),
                    new_root: new_kyc,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn windowed_assets_root_is_independent_of_kyc() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    // Rotate the ASSETS root; rotating KYC must not touch the assets window.
    client.update_assets_root(&tagged32(&env, 0x33));
    client.update_kyc_root(&tagged32(&env, 0x21));

    // A transfer with the PRIOR assets root (0x03) AND the new kyc root (0x21)
    // passes both windowed checks -> reaches the verifier (arity mismatch).
    let mut pi = transfer_pi(&env, zero32(&env));
    pi.assets_root = tagged32(&env, 0x03);
    pi.kyc_root = tagged32(&env, 0x21);
    assert_eq!(
        client.try_confidential_transfer(&dummy_proof(&env), &pi),
        Err(Ok(Error::VerifyingKeyArityMismatch))
    );
    // A never-published assets root is windowed-out (per-key window, not shared).
    pi.assets_root = tagged32(&env, 0xEE);
    assert_eq!(
        client.try_confidential_transfer(&dummy_proof(&env), &pi),
        Err(Ok(Error::StaleAssetsRoot))
    );
}

#[test]
fn compliance_window_dedups_nonconsecutive_repeat_and_evicts_oldest() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env); // kyc window = [0x01]
    let mut pi = transfer_pi(&env, zero32(&env));

    // Non-consecutive repeat of 0x21 must NOT consume a second slot (membership
    // dedup, not tail-only) — else duplicates would evict 0x01 early below.
    client.update_kyc_root(&tagged32(&env, 0x21)); // [0x01,0x21]
    client.update_kyc_root(&tagged32(&env, 0x22)); // [0x01,0x21,0x22]
    client.update_kyc_root(&tagged32(&env, 0x21)); // dedup -> unchanged (3 distinct)

    // Add 0x23..=0x2f (13 distinct) -> 16 distinct total == capacity; 0x01 retained.
    for t in 0x23u8..=0x2f {
        client.update_kyc_root(&tagged32(&env, t));
    }
    pi.kyc_root = tagged32(&env, 0x01);
    assert_eq!(
        client.try_confidential_transfer(&dummy_proof(&env), &pi),
        Err(Ok(Error::VerifyingKeyArityMismatch)),
        "the original root must survive: the repeated 0x21 must not have evicted it"
    );

    // One more distinct root (17th) evicts the oldest (0x01).
    client.update_kyc_root(&tagged32(&env, 0x30));
    assert_eq!(
        client.try_confidential_transfer(&dummy_proof(&env), &pi),
        Err(Ok(Error::StaleKycRoot))
    );
}

#[test]
fn register_asset_emits_event_for_the_indexer() {
    let env = Env::default();
    let (client, _admin, _issuer) = setup(&env);
    let asset_id: Scalar = tagged32(&env, 0x77);
    let sac = Address::generate(&env);
    client.register_asset(&asset_id, &sac);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("regasset"),).into_val(&env),
                ev::AssetRegisteredEvent { asset_id, sac }.into_val(&env),
            ),
        ]
    );
}
