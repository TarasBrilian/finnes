//! Contract error codes.
//!
//! Every fallible entrypoint returns `Result<T, Error>`. We never `unwrap()` or
//! `panic!` on untrusted input (proofs, public inputs, roots, ciphertexts) -
//! that path must produce an `Error` variant so callers get a typed failure and
//! the transaction reverts cleanly. See CLAUDE.md → Conventions.

use soroban_sdk::contracterror;

/// Finnes contract error codes.
///
/// Codes are stable: clients and the indexer match on the numeric value, so do
/// not renumber existing variants. Append new variants with new numbers.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    // --- lifecycle / auth ---
    /// `init` called more than once.
    AlreadyInitialized = 1,
    /// Entrypoint invoked before `init`.
    NotInitialized = 2,
    /// Caller is not the configured admin / issuer authority.
    Unauthorized = 3,

    // --- ordered transfer checks (invariant #9) ---
    /// Anchor commitment root is not within the recent-roots window.
    UnknownAnchorRoot = 10,
    /// A published nullifier has already been spent (double-spend).
    NullifierAlreadyUsed = 11,
    /// `frozen_root` in public inputs does not equal current state (strict).
    StaleFrozenRoot = 12,
    /// `kyc_root` is not within the recent-roots window.
    StaleKycRoot = 13,
    /// `sanction_root` is not within the recent-roots window.
    StaleSanctionRoot = 14,
    /// `assets_root` is not within the recent-roots window.
    StaleAssetsRoot = 15,
    /// `auditor_pk` in public inputs does not match stored state.
    AuditorPkMismatch = 16,
    /// Groth16 pairing-check failed (invalid proof for the given public inputs).
    InvalidProof = 17,

    // --- structural / decoding ---
    /// Public-input vector had the wrong length for the circuit.
    MalformedPublicInputs = 20,
    /// Proof or verifying-key bytes could not be decoded to curve points.
    MalformedProof = 21,
    /// Verifying key for the requested circuit is not configured.
    VerifyingKeyMissing = 22,
    /// VK `ic` length does not match the declared number of public inputs.
    VerifyingKeyArityMismatch = 23,
    /// `next_index` in public inputs does not equal the stored leaf count, so the
    /// circuit's tree transition would insert at the wrong append position
    /// (invariants #11/#12). Never accept a prover-chosen index.
    NextIndexMismatch = 24,

    // --- unshield / dvp specifics ---
    /// Transparent recipient on `unshield` is not authorised (KYC/non-sanctioned).
    RecipientNotAuthorised = 30,
    /// Required counterparty `require_auth` consent was absent for a DvP leg.
    ConsentMissing = 31,

    // --- admin: freeze / clawback ---
    /// Commitment is already present in the frozen set.
    AlreadyFrozen = 40,
    /// Both auditor and issuer signatures are required for this operation.
    DualAuthRequired = 41,

    // --- SAC token movement (FIN-010) ---
    /// No SAC contract address is registered for the proof's `asset_id`. The
    /// contract cannot hash on-chain (invariant #11), so it resolves the SAC for
    /// an `asset_id` from an admin-registered mirror of the assets registry; a
    /// missing entry means the asset was never `register_asset`'d.
    AssetNotRegistered = 50,
}
