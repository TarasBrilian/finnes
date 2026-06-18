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

#![cfg(test)]

extern crate std;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

use crate::types::{Root, Scalar, VerifyingKey, TREE_DEPTH};
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

    client.init(
        &admin,
        &issuer,
        &auditor_pk,
        &kyc,
        &sanction,
        &assets,
        &frozen,
        &empty_frontier(env),
        &init_root,
        &dummy_vk(env),
        &dummy_vk(env),
        &dummy_vk(env),
        &dummy_vk(env),
    );

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
    client.init(
        &Address::generate(&env),
        &Address::generate(&env),
        &tagged32(&env, 0xAA),
        &tagged32(&env, 0x01),
        &tagged32(&env, 0x02),
        &tagged32(&env, 0x03),
        &tagged32(&env, 0x04),
        &empty_frontier(&env),
        &tagged32(&env, 0x10),
        &dummy_vk(&env),
        &dummy_vk(&env),
        &dummy_vk(&env),
        &dummy_vk(&env),
    );
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

// TODO: positive `confidential_transfer` — needs (a) a real Transfer VK, (b) a
//       proof + public inputs from the prover for a 2-in/2-out witness, (c)
//       `verifier::verify_groth16` implemented. Until then this path returns
//       Error::InvalidProof by construction (the verifier placeholder refuses).
//
// TODO: negative — double-spend: submit a transfer reusing a nullifier already
//       inserted; expect Error::NullifierAlreadyUsed (this check runs BEFORE the
//       proof, so it is testable without real proof math once we can insert a
//       nullifier via a successful prior transfer or a test seam).
//
// TODO: negative — stale frozen_root: supply a frozen_root != state; expect
//       Error::StaleFrozenRoot (also pre-proof; testable now with a test seam to
//       set public inputs).
//
// TODO: negative — unknown anchor root: supply an anchor_root not in the window;
//       expect Error::UnknownAnchorRoot.
//
// TODO: unshield — assert frozen_root strict + zero-recipient rejection
//       (Error::RecipientNotAuthorised), then the full happy path once proofs land.
//
// TODO: settle_dvp — assert both `require_auth`s are demanded and a single proof
//       path is taken (invariant #7).
//
// TODO: freeze — assert AlreadyFrozen on a repeat, and that frozen_root advances.
