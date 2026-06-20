#![no_std]
//! Finnes - confidential RWA settlement contract for Soroban.
//!
//! Shielded-note (UTXO) settlement: RWA value moves as Poseidon commitments
//! (hidden amount/asset/owner) with nullifiers preventing double-spend. The
//! contract verifies a single Groth16 proof per transaction over the native
//! BLS12-381 host functions, then mutates state atomically. It performs **no
//! hashing** (invariant #11): the circuit proves the Merkle transition and the
//! contract stores the output `(new_frontier, new_root)` verbatim.
//!
//! See README.md, ARCHITECTURE.md, CLAUDE.md (Security invariants - binding),
//! and docs/PUBLIC_IO.md (canonical public-input ordering) at the repo root.
//!
//! ## Canonical ordering of checks in every transfer entrypoint (invariant #9)
//!
//! 1. validate the anchor root (recent-roots window),
//! 2. check nullifiers are unused,
//! 3. check compliance roots match state - `frozen_root` **strict**;
//!    `kyc_root`/`sanction_root`/`assets_root` **windowed**; `auditor_pk` exact,
//! 4. verify the Groth16 proof (binds ciphertexts + frozen non-membership),
//! 5. only then mutate state: store new frontier/root, insert nullifiers and
//!    commitments.
//!
//! Steps 1–4 are read-only; effects happen only after a fully valid proof
//! ("verify before effects").

mod errors;
mod events;
mod merkle;
mod sac;
mod state;
mod types;
mod verifier;

#[cfg(test)]
mod test;

#[cfg(test)]
mod test_vectors;

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

use crate::errors::Error;
use crate::state::RECENT_ROOTS_CAPACITY;
use crate::types::{
    Circuit, DvpPublicInputs, InitConfig, Proof, Root, Scalar, ShieldPublicInputs,
    TransferPublicInputs, UnshieldPublicInputs, TREE_DEPTH,
};

#[contract]
pub struct FinnesContract;

#[contractimpl]
impl FinnesContract {
    // -----------------------------------------------------------------------
    // init - admin setup. Idempotent guard; sets config + seeds the tree.
    // -----------------------------------------------------------------------
    /// Initialise the contract. Stores the admin, the auditor (read) key, the
    /// issuer authority (write) key, the initial compliance roots, the seed
    /// commitment-tree frontier/root, and the per-circuit verifying keys.
    ///
    /// `auditor_pk` and `issuer_authority` are kept as **distinct** authorities
    /// even if one operator holds both in the demo (invariant #14). Config is
    /// passed as one `InitConfig` struct (Soroban caps a contract fn at 10 args).
    pub fn init(env: Env, cfg: InitConfig) -> Result<(), Error> {
        if state::is_initialized(&env) {
            return Err(Error::AlreadyInitialized);
        }
        // Admin authorises its own setup.
        cfg.admin.require_auth();

        if cfg.initial_frontier.len() != TREE_DEPTH {
            return Err(Error::MalformedPublicInputs);
        }

        state::set_admin(&env, &cfg.admin);
        state::set_issuer_authority(&env, &cfg.issuer_authority);
        state::set_auditor_pk(&env, &cfg.auditor_pk);
        state::set_kyc_root(&env, &cfg.kyc_root);
        state::set_sanction_root(&env, &cfg.sanction_root);
        state::set_assets_root(&env, &cfg.assets_root);
        state::set_frozen_root(&env, &cfg.frozen_root);

        // Seed the commitment tree (empty-tree frontier/root) and the anchor ring.
        state::set_frontier(&env, &cfg.initial_frontier);
        state::set_tree_root(&env, &cfg.initial_root);
        state::init_recent_roots(&env, &cfg.initial_root);
        // Empty tree => 0 leaves. Advanced on every successful tree mutation and
        // checked against each circuit's `next_index` public input.
        state::set_leaf_count(&env, 0);

        state::set_vk(&env, Circuit::Shield, &cfg.vk_shield);
        state::set_vk(&env, Circuit::Transfer, &cfg.vk_transfer);
        state::set_vk(&env, Circuit::Unshield, &cfg.vk_unshield);
        state::set_vk(&env, Circuit::Dvp, &cfg.vk_dvp);

        state::bump_instance_ttl(&env);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // shield - transparent → shielded.
    // -----------------------------------------------------------------------
    /// Deposit a transparent RWA token, minting one confidential output note.
    ///
    /// `(asset_id, amount)` are public; the proof shows the new commitment opens
    /// to them without revealing `(owner, rho, r)` (invariant #18 - prevents
    /// minting a note labelled as a more-valuable asset). No shielded inputs,
    /// hence no nullifiers and no anchor root.
    ///
    /// After verifying the proof, the real SAC token is pulled
    /// `depositor -> contract` (FIN-010), resolving the SAC from the admin asset
    /// registry; the transfer is atomic with the state mutation.
    pub fn shield(
        env: Env,
        depositor: Address,
        proof: Proof,
        pi: ShieldPublicInputs,
    ) -> Result<(), Error> {
        ensure_initialized(&env)?;

        // 0. Authorise. The actual SAC pull (depositor -> contract) is an EFFECT
        //    and happens only after the proof verifies (step 5, FIN-010).
        depositor.require_auth();

        // 3. Compliance roots match state (shield uses kyc + assets + auditor_pk;
        //    no sanction/frozen inputs in this circuit's public-IO).
        check_kyc_root(&env, &pi.kyc_root)?;
        check_assets_root(&env, &pi.assets_root)?;
        check_auditor_pk(&env, &pi.auditor_pk)?;

        // 1'. Tree transition: old_frontier must equal state, and next_index must
        //     equal the stored leaf count so the in-circuit FrontierTransition
        //     inserts the new leaf at the true append position (#11/#12, FIN-012).
        if !merkle::check_old_frontier(&env, &pi.old_frontier)? {
            return Err(Error::UnknownAnchorRoot);
        }
        check_next_index(&env, &pi.next_index)?;

        // 4. Verify Groth16 (binds c_auditor - mandatory, invariant #5).
        let vk = state::get_vk(&env, Circuit::Shield).ok_or(Error::VerifyingKeyMissing)?;
        verifier::verify_groth16(&env, &vk, &proof, &pi.to_scalars(&env))?;

        // 5. Effects (verify-before-effects). Pull the real SAC token
        //    depositor -> contract for the deposited (asset_id, amount), then fold
        //    the new commitment into the tree. If the SAC transfer fails (e.g.
        //    insufficient balance) the whole tx reverts atomically - no note is
        //    minted for value that never arrived (FIN-010).
        sac::pull_deposit(&env, &pi.asset_id, &depositor, &pi.amount)?;
        merkle::apply_transition(&env, &pi.new_frontier, &pi.new_root, 1)?;
        state::bump_instance_ttl(&env);
        events::shield(
            &env,
            &pi.asset_id,
            &pi.amount,
            &pi.cm_out_0,
            &pi.new_root,
            &pi.c_auditor,
            &pi.c_recipient,
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // confidential_transfer - shielded → shielded (2-in / 2-out).
    // -----------------------------------------------------------------------
    /// Move value confidentially. The public sees only opaque commitments,
    /// nullifiers, and ciphertexts. Enforces the canonical ordered checks.
    pub fn confidential_transfer(
        env: Env,
        proof: Proof,
        pi: TransferPublicInputs,
    ) -> Result<(), Error> {
        ensure_initialized(&env)?;

        // 1. Validate anchor root (recent-roots window).
        if !merkle::is_recent_root(&env, &pi.anchor_root) {
            return Err(Error::UnknownAnchorRoot);
        }

        // 2. Nullifiers unused (both inputs). Reject if either already spent.
        if state::nullifier_exists(&env, &pi.nf_in_0) || state::nullifier_exists(&env, &pi.nf_in_1)
        {
            return Err(Error::NullifierAlreadyUsed);
        }

        // 3. Compliance roots match state. frozen_root STRICT; others windowed;
        //    auditor_pk exact.
        check_frozen_root_strict(&env, &pi.frozen_root)?;
        check_kyc_root(&env, &pi.kyc_root)?;
        check_sanction_root(&env, &pi.sanction_root)?;
        check_assets_root(&env, &pi.assets_root)?;
        check_auditor_pk(&env, &pi.auditor_pk)?;

        // 1'. Tree transition input: old_frontier must equal state, and
        //     next_index must equal the stored leaf count so the in-circuit
        //     FrontierTransition inserts at the true append position (#11/#12).
        if !merkle::check_old_frontier(&env, &pi.old_frontier)? {
            return Err(Error::UnknownAnchorRoot);
        }
        check_next_index(&env, &pi.next_index)?;

        // 4. Verify the single Groth16 proof. This binds the auditor/recipient
        //    ciphertexts (public inputs, invariant #5) and proves frozen-set
        //    non-membership of every spent note in-circuit.
        let vk = state::get_vk(&env, Circuit::Transfer).ok_or(Error::VerifyingKeyMissing)?;
        verifier::verify_groth16(&env, &vk, &proof, &pi.to_scalars(&env))?;

        // 5. Effects (verify-before-effects): record nullifiers, then store the
        //    new frontier/root and advance the leaf count by the 2 output notes.
        //    Commitments are folded into new_root by the circuit; we emit them
        //    for the indexer.
        state::insert_nullifier(&env, &pi.nf_in_0);
        state::insert_nullifier(&env, &pi.nf_in_1);
        merkle::apply_transition(&env, &pi.new_frontier, &pi.new_root, 2)?;
        state::bump_instance_ttl(&env);
        events::transfer(
            &env,
            &pi.nf_in_0,
            &pi.nf_in_1,
            &pi.cm_out_0,
            &pi.cm_out_1,
            &pi.new_root,
            &pi.c_auditor,
            &pi.c_recipient,
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // settle_dvp - atomic two-asset settlement.
    // -----------------------------------------------------------------------
    /// Settle a two-asset DvP.
    ///
    /// DEMO: a single combined proof holding both parties' secrets (one
    /// pairing), acceptable ONLY because a test harness controls both keypairs
    /// (invariant #15). PRODUCTION uses an escrow / two-phase flow built from
    /// `transfer`/`shield` variants (ARCHITECTURE.md → "Settlement (DvP)"); that
    /// is **out of scope** in this scaffold.
    ///
    /// Counterparty consent is on-chain via `require_auth` over the concrete
    /// intent (never an in-circuit signature, invariant #15).
    pub fn settle_dvp(
        env: Env,
        party_a: Address,
        party_b: Address,
        proof: Proof,
        pi: DvpPublicInputs,
    ) -> Result<(), Error> {
        ensure_initialized(&env)?;

        // Counterparty consent: both parties authorise the concrete intent
        // (output commitments live in `pi`). TODO: bind a nonce + the output
        // commitments into the auth payload so consent commits to *this* intent.
        party_a.require_auth();
        party_b.require_auth();

        // 1. Anchor root window.
        if !merkle::is_recent_root(&env, &pi.anchor_root) {
            return Err(Error::UnknownAnchorRoot);
        }

        // 2. Nullifiers unused (one per leg).
        if state::nullifier_exists(&env, &pi.nf_leg_x_0)
            || state::nullifier_exists(&env, &pi.nf_leg_y_0)
        {
            return Err(Error::NullifierAlreadyUsed);
        }

        // 3. Compliance roots: frozen STRICT; others windowed; auditor_pk exact.
        check_frozen_root_strict(&env, &pi.frozen_root)?;
        check_kyc_root(&env, &pi.kyc_root)?;
        check_sanction_root(&env, &pi.sanction_root)?;
        check_assets_root(&env, &pi.assets_root)?;
        check_auditor_pk(&env, &pi.auditor_pk)?;

        // 1'. Tree transition input.
        if !merkle::check_old_frontier(&env, &pi.old_frontier)? {
            return Err(Error::UnknownAnchorRoot);
        }

        // 4. ONE Groth16 proof for both legs (invariant #7 - never two).
        let vk = state::get_vk(&env, Circuit::Dvp).ok_or(Error::VerifyingKeyMissing)?;
        verifier::verify_groth16(&env, &vk, &proof, &pi.to_scalars(&env))?;

        // 5. Effects. Two output notes (one per leg) => advance leaf count by 2.
        // TODO(FIN-016): check pi.next_index == leaf_count once dvp.circom
        //    exposes the next_index public input.
        state::insert_nullifier(&env, &pi.nf_leg_x_0);
        state::insert_nullifier(&env, &pi.nf_leg_y_0);
        merkle::apply_transition(&env, &pi.new_frontier, &pi.new_root, 2)?;
        state::bump_instance_ttl(&env);
        events::dvp(
            &env,
            &pi.nf_leg_x_0,
            &pi.nf_leg_y_0,
            &pi.cm_out_x,
            &pi.cm_out_y,
            &pi.new_root,
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // unshield - shielded → transparent.
    // -----------------------------------------------------------------------
    /// Exit the shielded domain: reveal `(asset_id, amount, recipient)` and
    /// `transfer` the SAC token to the transparent recipient.
    ///
    /// Top compliance checkpoint (invariant #19): the circuit MUST prove
    /// (a) the transparent recipient is KYC-approved / non-sanctioned, and
    /// (b) **frozen-set non-membership** of the spent commitment (escape-hatch
    /// closure). Both are part of the proven statement (public inputs:
    /// `kyc_root`, `sanction_root`, `frozen_root`). The contract additionally
    /// checks `frozen_root` strictly against state here so a stale frozen root
    /// can never let a frozen note exit.
    pub fn unshield(env: Env, proof: Proof, pi: UnshieldPublicInputs) -> Result<(), Error> {
        ensure_initialized(&env)?;

        // 1. Anchor root window.
        if !merkle::is_recent_root(&env, &pi.anchor_root) {
            return Err(Error::UnknownAnchorRoot);
        }

        // 2. Nullifier unused.
        if state::nullifier_exists(&env, &pi.nf_in_0) {
            return Err(Error::NullifierAlreadyUsed);
        }

        // 3. Compliance roots. frozen_root STRICT (invariant #19 (b) is matched
        //    in-circuit; we also assert the root equals current state here so
        //    the proven non-membership is against the *current* frozen set).
        check_frozen_root_strict(&env, &pi.frozen_root)?;
        check_kyc_root(&env, &pi.kyc_root)?;
        check_sanction_root(&env, &pi.sanction_root)?;
        check_assets_root(&env, &pi.assets_root)?;
        check_auditor_pk(&env, &pi.auditor_pk)?;

        // 3'. Recipient authorisation (invariant #19 (a)). KYC/non-sanctioned is
        //     proven in-circuit via kyc_root/sanction_root membership of
        //     `pi.recipient`; on-chain we resolve the field-encoded recipient to a
        //     concrete Stellar `Address` via the demo account registry. A missing
        //     entry (incl. the zero sentinel, which is never registered) means the
        //     recipient is not an authorised transparent payout target (FIN-010).
        let recipient_addr = state::get_transparent_addr(&env, &pi.recipient)
            .ok_or(Error::RecipientNotAuthorised)?;

        // 1'. Tree transition input: old_frontier == state, and next_index ==
        //     leaf count (the in-circuit FrontierTransition anchors the change
        //     insert - or the no-change no-op - at the true append index, #11/#12).
        if !merkle::check_old_frontier(&env, &pi.old_frontier)? {
            return Err(Error::UnknownAnchorRoot);
        }
        check_next_index(&env, &pi.next_index)?;

        // 4. Verify the single Groth16 proof (binds change-note ciphertext +
        //    frozen non-membership + recipient compliance).
        let vk = state::get_vk(&env, Circuit::Unshield).ok_or(Error::VerifyingKeyMissing)?;
        verifier::verify_groth16(&env, &vk, &proof, &pi.to_scalars(&env))?;

        // 5. Effects: record nullifier, apply tree transition, then perform the
        //    transparent payout. The change-note sentinel decides how far the tree
        //    advances: cm_change_0 == 0 means no change note, so 0 leaves were
        //    inserted (the circuit's gated 0-leaf reproduces the current root and
        //    leaves new_frontier == old_frontier); otherwise exactly 1.
        state::insert_nullifier(&env, &pi.nf_in_0);
        let n_inserts: u32 = if is_zero_scalar(&pi.cm_change_0) {
            0
        } else {
            1
        };
        merkle::apply_transition(&env, &pi.new_frontier, &pi.new_root, n_inserts)?;
        // Transparent payout: move the real SAC token contract -> recipient for the
        // revealed (asset_id, amount). Atomic with the rest of the tx (FIN-010).
        sac::pay_out(&env, &pi.asset_id, &recipient_addr, &pi.amount)?;
        state::bump_instance_ttl(&env);
        events::unshield(
            &env,
            &pi.nf_in_0,
            &pi.asset_id,
            &pi.amount,
            &pi.recipient,
            &pi.cm_change_0,
            &pi.new_root,
            &pi.c_auditor,
            &pi.c_recipient,
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Admin: root updates (write authority = issuer_authority).
    // -----------------------------------------------------------------------
    /// Update `kyc_root`, pushing the prior value out of the window naturally
    /// (windowed acceptance is per-root; KYC change is benign - invariant #6).
    pub fn update_kyc_root(env: Env, new_root: Root) -> Result<(), Error> {
        require_issuer(&env)?;
        state::set_kyc_root(&env, &new_root);
        state::bump_instance_ttl(&env);
        events::root_updated(&env, symbol_short!("kyc"), &new_root);
        Ok(())
    }

    /// Update `sanction_root`.
    pub fn update_sanction_root(env: Env, new_root: Root) -> Result<(), Error> {
        require_issuer(&env)?;
        state::set_sanction_root(&env, &new_root);
        state::bump_instance_ttl(&env);
        events::root_updated(&env, symbol_short!("sanction"), &new_root);
        Ok(())
    }

    /// Update `assets_root` (authorized-assets registry).
    pub fn update_assets_root(env: Env, new_root: Root) -> Result<(), Error> {
        require_issuer(&env)?;
        state::set_assets_root(&env, &new_root);
        state::bump_instance_ttl(&env);
        events::root_updated(&env, symbol_short!("assets"), &new_root);
        Ok(())
    }

    /// Register (or update) the concrete SAC `Address` for an `asset_id` (FIN-010).
    ///
    /// The contract performs no on-chain hashing (invariant #11), so it cannot
    /// recompute `asset_id = Poseidon(sac_address)`; this admin-managed mirror of
    /// the authorized-assets registry is how shield/unshield resolve the real
    /// token to move. The admin MUST keep it in lockstep with `assets_root` (the
    /// same `(asset_id, sac_address, …)` leaf), so an `asset_id` resolves to the
    /// SAC whose Poseidon hash it is.
    pub fn register_asset(env: Env, asset_id: Scalar, sac: Address) -> Result<(), Error> {
        require_issuer(&env)?;
        state::set_asset_sac(&env, &asset_id, &sac);
        state::bump_instance_ttl(&env);
        events::asset_registered(&env, &asset_id, &sac);
        Ok(())
    }

    /// Register (or update) the concrete Stellar `Address` for a transparent
    /// `recipient` field (FIN-010, the demo account registry). `unshield` resolves
    /// `pi.recipient` to this address for the SAC payout; the in-circuit proof
    /// binds the recipient's KYC/non-sanction to the same field.
    pub fn register_transparent(env: Env, recipient: Scalar, addr: Address) -> Result<(), Error> {
        require_issuer(&env)?;
        state::set_transparent_addr(&env, &recipient, &addr);
        state::bump_instance_ttl(&env);
        events::transparent_registered(&env, &recipient, &addr);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Admin: freeze / clawback (two-phase, two-key - invariant #14).
    // -----------------------------------------------------------------------
    /// Phase 2 (write): add `cm_target` to the frozen set and advance
    /// `frozen_root` to `new_frozen_root` (the issuer-set root the circuits will
    /// match strictly). `frozen_root` is matched STRICTLY on every transfer, so
    /// this takes effect immediately for all subsequent spends.
    ///
    /// `cm_target` is identified in phase 1 by the auditor (read authority) who
    /// decrypts with the view key. This entrypoint MAY require both signatures.
    pub fn freeze(
        env: Env,
        cm_target: types::Commitment,
        new_frozen_root: Root,
    ) -> Result<(), Error> {
        // Write authority (issuer). TODO: optionally also require the auditor's
        // signature here to make the read+write join explicit (DualAuthRequired).
        require_issuer(&env)?;

        if state::frozen_contains(&env, &cm_target) {
            return Err(Error::AlreadyFrozen);
        }
        state::insert_frozen(&env, &cm_target);
        // Advance the strict frozen root verbatim (computed off-chain by the
        // issuer; the contract performs NO hashing - invariant #11).
        state::set_frozen_root(&env, &new_frozen_root);
        state::bump_instance_ttl(&env);
        events::freeze(&env, &cm_target, &new_frozen_root);
        Ok(())
    }

    /// Mint a recovery note for a clawed-back commitment (issuer write
    /// authority). The recovery is a normal output note whose commitment is
    /// folded into the tree via a proof - so this reuses the `shield`-style
    /// transition. Frozen notes are unspendable by their owner (non-membership
    /// in every spend), and clawback cannot be done by computing a nullifier
    /// (that needs the owner's spending key, which no authority holds -
    /// invariant #14).
    pub fn mint_recovery(env: Env, proof: Proof, pi: ShieldPublicInputs) -> Result<(), Error> {
        require_issuer(&env)?;
        // Reuse the shield circuit/VK for the recovery mint (asset_id/amount
        // public; opens to the recovered value). Same compliance checks as shield,
        // minus the depositor SAC pull (value originates from the frozen note).
        // The shield circuit binds `kyc_root`, so the recovery mint is held to the
        // same windowed freshness check as shield (parity — adversarial-review fix);
        // a recovery note holder must be compliant just like a shield depositor.
        check_kyc_root(&env, &pi.kyc_root)?;
        check_assets_root(&env, &pi.assets_root)?;
        check_auditor_pk(&env, &pi.auditor_pk)?;
        if !merkle::check_old_frontier(&env, &pi.old_frontier)? {
            return Err(Error::UnknownAnchorRoot);
        }
        // Pin the recovery mint's insert position to state (#11/#12, FIN-012);
        // it reuses the shield circuit, which exposes `next_index`.
        check_next_index(&env, &pi.next_index)?;
        let vk = state::get_vk(&env, Circuit::Shield).ok_or(Error::VerifyingKeyMissing)?;
        verifier::verify_groth16(&env, &vk, &proof, &pi.to_scalars(&env))?;
        // Recovery mints one note => advance leaf count by 1.
        merkle::apply_transition(&env, &pi.new_frontier, &pi.new_root, 1)?;
        state::bump_instance_ttl(&env);
        events::recovery(&env, &pi.cm_out_0, &pi.new_root);
        Ok(())
    }

    /// Alias for `mint_recovery` under the spec name `clawback`. Phase-2 write
    /// step paired with the prior `freeze`.
    pub fn clawback(env: Env, proof: Proof, pi: ShieldPublicInputs) -> Result<(), Error> {
        Self::mint_recovery(env, proof, pi)
    }

    // -----------------------------------------------------------------------
    // Read-only views (handy for the indexer / tests).
    // -----------------------------------------------------------------------
    pub fn current_root(env: Env) -> Option<Root> {
        state::get_tree_root(&env)
    }

    pub fn recent_roots_capacity() -> u32 {
        RECENT_ROOTS_CAPACITY
    }

    pub fn is_nullifier_used(env: Env, nf: types::Nullifier) -> bool {
        state::nullifier_exists(&env, &nf)
    }
}

// ===========================================================================
// Internal helpers (not contract entrypoints).
// ===========================================================================

fn ensure_initialized(env: &Env) -> Result<(), Error> {
    if state::is_initialized(env) {
        Ok(())
    } else {
        Err(Error::NotInitialized)
    }
}

/// Require the configured issuer authority (write authority) to sign.
fn require_issuer(env: &Env) -> Result<(), Error> {
    let issuer = state::get_issuer_authority(env).ok_or(Error::NotInitialized)?;
    issuer.require_auth();
    Ok(())
}

/// `frozen_root` is matched STRICTLY against current state (invariant #6 - the
/// immediacy of clawback). Never accept a stale frozen root.
fn check_frozen_root_strict(env: &Env, supplied: &Root) -> Result<(), Error> {
    let current = state::get_frozen_root(env).ok_or(Error::NotInitialized)?;
    if &current == supplied {
        Ok(())
    } else {
        Err(Error::StaleFrozenRoot)
    }
}

// Windowed compliance roots (FIN-011, invariant #6). kyc/sanction/assets change
// rarely and benignly, so each is accepted if it appears anywhere in its recent
// window (seeded at `init`, appended on every admin update). This lets a proof
// built against the immediately-prior root still validate while proving latency
// elapses, without weakening soundness — the root is still bound in the proof and
// matched to state, just against a short window instead of the single latest
// value. `frozen_root` is the exception: matched STRICTLY (immediacy of clawback).
fn check_kyc_root(env: &Env, supplied: &Root) -> Result<(), Error> {
    if state::get_kyc_root(env).is_none() {
        return Err(Error::NotInitialized);
    }
    if state::kyc_root_in_window(env, supplied) {
        Ok(())
    } else {
        Err(Error::StaleKycRoot)
    }
}

fn check_sanction_root(env: &Env, supplied: &Root) -> Result<(), Error> {
    if state::get_sanction_root(env).is_none() {
        return Err(Error::NotInitialized);
    }
    if state::sanction_root_in_window(env, supplied) {
        Ok(())
    } else {
        Err(Error::StaleSanctionRoot)
    }
}

fn check_assets_root(env: &Env, supplied: &Root) -> Result<(), Error> {
    if state::get_assets_root(env).is_none() {
        return Err(Error::NotInitialized);
    }
    if state::assets_root_in_window(env, supplied) {
        Ok(())
    } else {
        Err(Error::StaleAssetsRoot)
    }
}

/// Check that the prover-supplied `next_index` equals the stored leaf count,
/// encoded as a big-endian `Fr` scalar (the count occupies the low 8 bytes).
/// This pins the in-circuit `FrontierTransition` to the true append position
/// (invariants #11/#12) - the index is contract-supplied, never prover-chosen.
fn check_next_index(env: &Env, supplied: &Scalar) -> Result<(), Error> {
    let count = state::get_leaf_count(env).ok_or(Error::NotInitialized)?;
    let mut expected = [0u8; 32];
    expected[24..32].copy_from_slice(&count.to_be_bytes());
    if supplied.to_array() == expected {
        Ok(())
    } else {
        Err(Error::NextIndexMismatch)
    }
}

fn check_auditor_pk(env: &Env, supplied: &Scalar) -> Result<(), Error> {
    match state::get_auditor_pk(env) {
        Some(c) if &c == supplied => Ok(()),
        Some(_) => Err(Error::AuditorPkMismatch),
        None => Err(Error::NotInitialized),
    }
}

/// True if a scalar is the all-zero (null) sentinel - used for the
/// "no recipient"/"no change note" cases.
fn is_zero_scalar(s: &Scalar) -> bool {
    let zero = [0u8; 32];
    s.to_array() == zero
}
