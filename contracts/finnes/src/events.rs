//! Indexer events (FIN-011).
//!
//! Every state-mutating effect publishes a typed event so the off-chain indexer
//! (ARCHITECTURE.md → Backend) can reconstruct the commitment tree, the nullifier
//! set, and the ciphertext store WITHOUT re-deriving anything — the contract does
//! no hashing (invariant #11). All event data is PUBLIC: opaque commitments,
//! nullifiers, the new tree root, and the field-packed ciphertexts (already public
//! inputs, invariant #5). No secret is ever emitted (invariant #8).
//!
//! Events are published AFTER the state mutation, on the verify-before-effects
//! path (invariant #9), so an event implies a committed, proof-validated change.
//! The `#[contracttype]` payloads give the indexer a stable, named schema; the
//! single-symbol topic identifies the effect kind.

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::types::{Commitment, Nullifier, Root, Scalar};

/// `shield`: a transparent deposit minted one confidential note.
#[contracttype]
#[derive(Clone)]
pub struct ShieldEvent {
    pub asset_id: Scalar,
    pub amount: Scalar,
    pub cm_out: Commitment,
    pub new_root: Root,
    pub c_auditor: Vec<Scalar>,
    pub c_recipient: Vec<Scalar>,
}

/// `confidential_transfer`: 2 spent inputs, 2 minted outputs.
#[contracttype]
#[derive(Clone)]
pub struct TransferEvent {
    pub nf_in_0: Nullifier,
    pub nf_in_1: Nullifier,
    pub cm_out_0: Commitment,
    pub cm_out_1: Commitment,
    pub new_root: Root,
    pub c_auditor: Vec<Scalar>,
    pub c_recipient: Vec<Scalar>,
}

/// `unshield`: 1 spent input, value left to a transparent recipient, optional change.
#[contracttype]
#[derive(Clone)]
pub struct UnshieldEvent {
    pub nf_in_0: Nullifier,
    pub asset_id: Scalar,
    pub amount: Scalar,
    pub recipient: Scalar,
    /// `0` sentinel when there is no change note.
    pub cm_change_0: Commitment,
    pub new_root: Root,
    pub c_auditor: Vec<Scalar>,
    pub c_recipient: Vec<Scalar>,
}

/// `settle_dvp`: two legs, one combined proof (demo).
#[contracttype]
#[derive(Clone)]
pub struct DvpEvent {
    pub nf_leg_x_0: Nullifier,
    pub nf_leg_y_0: Nullifier,
    pub cm_out_x: Commitment,
    pub cm_out_y: Commitment,
    pub new_root: Root,
}

/// `freeze`: a commitment was added to the frozen set; `frozen_root` advanced.
#[contracttype]
#[derive(Clone)]
pub struct FreezeEvent {
    pub cm_target: Commitment,
    pub new_frozen_root: Root,
}

/// `mint_recovery` / `clawback`: a recovery note was minted into the tree.
#[contracttype]
#[derive(Clone)]
pub struct RecoveryEvent {
    pub cm_out: Commitment,
    pub new_root: Root,
}

/// An admin compliance-root update (kyc / sanction / assets / frozen). `kind`
/// names which root so the indexer can mirror the windowed/strict state.
#[contracttype]
#[derive(Clone)]
pub struct RootUpdatedEvent {
    pub kind: Symbol,
    pub new_root: Root,
}

/// Admin registered/updated an `asset_id → SAC Address` mapping (FIN-010 mirror).
/// The indexer needs this to link the field-encoded `asset_id` in shield/unshield
/// events to the concrete on-chain token.
#[contracttype]
#[derive(Clone)]
pub struct AssetRegisteredEvent {
    pub asset_id: Scalar,
    pub sac: Address,
}

/// Admin registered/updated a transparent `recipient field → Stellar Address`
/// mapping (FIN-010 demo account registry). Links an `unshield` recipient field to
/// the concrete payout address.
#[contracttype]
#[derive(Clone)]
pub struct TransparentRegisteredEvent {
    pub recipient: Scalar,
    pub addr: Address,
}

// ---------------------------------------------------------------------------
// Emit helpers. Topic = a single short symbol naming the effect.
// ---------------------------------------------------------------------------

pub fn shield(
    env: &Env,
    asset_id: &Scalar,
    amount: &Scalar,
    cm_out: &Commitment,
    new_root: &Root,
    c_auditor: &Vec<Scalar>,
    c_recipient: &Vec<Scalar>,
) {
    env.events().publish(
        (symbol_short!("shield"),),
        ShieldEvent {
            asset_id: asset_id.clone(),
            amount: amount.clone(),
            cm_out: cm_out.clone(),
            new_root: new_root.clone(),
            c_auditor: c_auditor.clone(),
            c_recipient: c_recipient.clone(),
        },
    );
}

#[allow(clippy::too_many_arguments)]
pub fn transfer(
    env: &Env,
    nf_in_0: &Nullifier,
    nf_in_1: &Nullifier,
    cm_out_0: &Commitment,
    cm_out_1: &Commitment,
    new_root: &Root,
    c_auditor: &Vec<Scalar>,
    c_recipient: &Vec<Scalar>,
) {
    env.events().publish(
        (symbol_short!("transfer"),),
        TransferEvent {
            nf_in_0: nf_in_0.clone(),
            nf_in_1: nf_in_1.clone(),
            cm_out_0: cm_out_0.clone(),
            cm_out_1: cm_out_1.clone(),
            new_root: new_root.clone(),
            c_auditor: c_auditor.clone(),
            c_recipient: c_recipient.clone(),
        },
    );
}

#[allow(clippy::too_many_arguments)]
pub fn unshield(
    env: &Env,
    nf_in_0: &Nullifier,
    asset_id: &Scalar,
    amount: &Scalar,
    recipient: &Scalar,
    cm_change_0: &Commitment,
    new_root: &Root,
    c_auditor: &Vec<Scalar>,
    c_recipient: &Vec<Scalar>,
) {
    env.events().publish(
        (symbol_short!("unshield"),),
        UnshieldEvent {
            nf_in_0: nf_in_0.clone(),
            asset_id: asset_id.clone(),
            amount: amount.clone(),
            recipient: recipient.clone(),
            cm_change_0: cm_change_0.clone(),
            new_root: new_root.clone(),
            c_auditor: c_auditor.clone(),
            c_recipient: c_recipient.clone(),
        },
    );
}

pub fn dvp(
    env: &Env,
    nf_leg_x_0: &Nullifier,
    nf_leg_y_0: &Nullifier,
    cm_out_x: &Commitment,
    cm_out_y: &Commitment,
    new_root: &Root,
) {
    env.events().publish(
        (symbol_short!("dvp"),),
        DvpEvent {
            nf_leg_x_0: nf_leg_x_0.clone(),
            nf_leg_y_0: nf_leg_y_0.clone(),
            cm_out_x: cm_out_x.clone(),
            cm_out_y: cm_out_y.clone(),
            new_root: new_root.clone(),
        },
    );
}

pub fn freeze(env: &Env, cm_target: &Commitment, new_frozen_root: &Root) {
    env.events().publish(
        (symbol_short!("freeze"),),
        FreezeEvent {
            cm_target: cm_target.clone(),
            new_frozen_root: new_frozen_root.clone(),
        },
    );
}

pub fn recovery(env: &Env, cm_out: &Commitment, new_root: &Root) {
    env.events().publish(
        (symbol_short!("recovery"),),
        RecoveryEvent {
            cm_out: cm_out.clone(),
            new_root: new_root.clone(),
        },
    );
}

pub fn root_updated(env: &Env, kind: Symbol, new_root: &Root) {
    env.events().publish(
        (symbol_short!("rootupd"),),
        RootUpdatedEvent {
            kind,
            new_root: new_root.clone(),
        },
    );
}

pub fn asset_registered(env: &Env, asset_id: &Scalar, sac: &Address) {
    env.events().publish(
        (symbol_short!("regasset"),),
        AssetRegisteredEvent {
            asset_id: asset_id.clone(),
            sac: sac.clone(),
        },
    );
}

pub fn transparent_registered(env: &Env, recipient: &Scalar, addr: &Address) {
    env.events().publish(
        (symbol_short!("regtrans"),),
        TransparentRegisteredEvent {
            recipient: recipient.clone(),
            addr: addr.clone(),
        },
    );
}
