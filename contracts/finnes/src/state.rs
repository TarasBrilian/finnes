//! Storage layout and typed accessors.
//!
//! ## Storage durability (Protocol 23 note)
//!
//! Fund-critical state - the nullifier set and the commitment-tree
//! frontier/root - lives in **persistent** storage. On Soroban, persistent
//! entries can expire (TTL), but under Protocol 23 archived persistent entries
//! are **auto-restored** on access (no manual `RestoreFootprint` for the common
//! path). We still bump TTL on every mutation so live state does not drift into
//! archival. NEVER store nullifiers in temporary storage: a temp entry can be
//! evicted and silently "forget" a spend, re-enabling a double-spend
//! (invariant #4). Config/VKs use instance storage (small, always-loaded).
//!
//! ## Nullifiers: one entry per nullifier
//!
//! Each nullifier is its own persistent keyed entry (`DataKey::Nullifier(nf)`),
//! checked by `has()` (existence), NOT appended to a growing blob. A blob would
//! cost O(n) to read/write and eventually exceed entry-size limits.

use soroban_sdk::{contracttype, Address, Env, Vec};

use crate::types::{Circuit, Commitment, Nullifier, Root, Scalar, VerifyingKey};

/// Size of the recent-roots ring buffer (windowed-root acceptance).
///
/// Anchors and the windowed compliance roots (kyc/sanction/assets) are accepted
/// if they appear anywhere in the last `RECENT_ROOTS_CAPACITY` published roots.
/// Larger window = more in-flight proofs survive a root change, at a small
/// storage cost. TODO: tune against expected block cadence / proving latency.
pub const RECENT_ROOTS_CAPACITY: u32 = 64;

/// TTL bump targets (in ledgers) for persistent entries. Placeholder values;
/// TODO: set from the deployed network's archival parameters.
pub const PERSISTENT_TTL_THRESHOLD: u32 = 17_280; // ~1 day at 5s ledgers
pub const PERSISTENT_TTL_EXTEND: u32 = 60_480; // ~7 days

/// All storage keys. `#[contracttype]` makes each variant a distinct ScVal key.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    // --- instance (config; small, loaded with the contract) ---
    /// Admin / deployer address (calls `init` and root-update admin fns).
    Admin,
    /// Auditor (regulator) view-key public key - the **read** authority.
    AuditorPk,
    /// Issuer authority - the **write** authority (freeze/clawback, root updates).
    IssuerAuthority,
    /// KYC-approved set root (membership). Windowed.
    KycRoot,
    /// Sanctioned set root (non-membership). Windowed.
    SanctionRoot,
    /// Authorized-assets registry root. Windowed.
    AssetsRoot,
    /// Issuer-managed frozen-commitment set root (non-membership). **Strict.**
    FrozenRoot,
    /// Current commitment-tree root (latest published).
    TreeRoot,
    /// Number of leaves inserted into the commitment tree so far (the next append
    /// index). Checked against the circuits' `next_index` public input so the
    /// in-circuit `FrontierTransition` inserts at the true position (#11/#12).
    LeafCount,
    /// Groth16 verifying key for a given circuit.
    Vk(Circuit),

    // --- persistent (fund-critical / unbounded) ---
    /// Existence marker for a spent nullifier. Value is unit `()`; presence ==
    /// spent. One entry per nullifier (invariant #4).
    Nullifier(Nullifier),
    /// Commitment-tree frontier (filled subtrees), `TREE_DEPTH` scalars.
    Frontier,
    /// Recent-roots ring buffer (commitment-tree roots) for windowed anchoring.
    RecentRoots,
    /// Membership marker for a commitment in the frozen set (existence check).
    /// Complements `FrozenRoot`: the contract stores the verbatim issuer-set root
    /// strictly, and also records which `cm`s were frozen for auditability.
    Frozen(Commitment),
}

// ---------------------------------------------------------------------------
// Instance config accessors (small, always-loaded).
// ---------------------------------------------------------------------------

pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&DataKey::Admin)
}

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&DataKey::Admin, admin);
}

pub fn get_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::Admin)
}

pub fn set_auditor_pk(env: &Env, pk: &Scalar) {
    env.storage().instance().set(&DataKey::AuditorPk, pk);
}

pub fn get_auditor_pk(env: &Env) -> Option<Scalar> {
    env.storage().instance().get(&DataKey::AuditorPk)
}

pub fn set_issuer_authority(env: &Env, issuer: &Address) {
    env.storage()
        .instance()
        .set(&DataKey::IssuerAuthority, issuer);
}

pub fn get_issuer_authority(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::IssuerAuthority)
}

pub fn set_kyc_root(env: &Env, r: &Root) {
    env.storage().instance().set(&DataKey::KycRoot, r);
}
pub fn get_kyc_root(env: &Env) -> Option<Root> {
    env.storage().instance().get(&DataKey::KycRoot)
}

pub fn set_sanction_root(env: &Env, r: &Root) {
    env.storage().instance().set(&DataKey::SanctionRoot, r);
}
pub fn get_sanction_root(env: &Env) -> Option<Root> {
    env.storage().instance().get(&DataKey::SanctionRoot)
}

pub fn set_assets_root(env: &Env, r: &Root) {
    env.storage().instance().set(&DataKey::AssetsRoot, r);
}
pub fn get_assets_root(env: &Env) -> Option<Root> {
    env.storage().instance().get(&DataKey::AssetsRoot)
}

pub fn set_frozen_root(env: &Env, r: &Root) {
    env.storage().instance().set(&DataKey::FrozenRoot, r);
}
pub fn get_frozen_root(env: &Env) -> Option<Root> {
    env.storage().instance().get(&DataKey::FrozenRoot)
}

pub fn set_tree_root(env: &Env, r: &Root) {
    env.storage().instance().set(&DataKey::TreeRoot, r);
}
pub fn get_tree_root(env: &Env) -> Option<Root> {
    env.storage().instance().get(&DataKey::TreeRoot)
}

/// Commitment-tree leaf count (the next append index). Instance storage: a small
/// `u64` always loaded with config. Seeded to 0 at `init` (empty tree) and
/// advanced by `advance_leaf_count` on every successful tree mutation.
pub fn set_leaf_count(env: &Env, count: u64) {
    env.storage().instance().set(&DataKey::LeafCount, &count);
}
pub fn get_leaf_count(env: &Env) -> Option<u64> {
    env.storage().instance().get(&DataKey::LeafCount)
}

/// Advance the leaf count by `n` newly-inserted leaves. Saturating add guards
/// against wraparound (the tree caps at 2^TREE_DEPTH long before u64 overflow).
pub fn advance_leaf_count(env: &Env, n: u32) {
    let cur = get_leaf_count(env).unwrap_or(0);
    set_leaf_count(env, cur.saturating_add(n as u64));
}

pub fn set_vk(env: &Env, circuit: Circuit, vk: &VerifyingKey) {
    env.storage().instance().set(&DataKey::Vk(circuit), vk);
}
pub fn get_vk(env: &Env, circuit: Circuit) -> Option<VerifyingKey> {
    env.storage().instance().get(&DataKey::Vk(circuit))
}

// ---------------------------------------------------------------------------
// Nullifier set (persistent, one entry per nullifier).
// ---------------------------------------------------------------------------

/// True if `nf` has already been spent.
pub fn nullifier_exists(env: &Env, nf: &Nullifier) -> bool {
    env.storage()
        .persistent()
        .has(&DataKey::Nullifier(nf.clone()))
}

/// Insert `nf` as spent and bump its TTL. Caller must have already checked it
/// does not exist (invariant #4 ordering is enforced in `lib.rs`).
pub fn insert_nullifier(env: &Env, nf: &Nullifier) {
    let key = DataKey::Nullifier(nf.clone());
    env.storage().persistent().set(&key, &());
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}

// ---------------------------------------------------------------------------
// Frozen-commitment markers (persistent existence set; admin-managed).
// ---------------------------------------------------------------------------

pub fn frozen_contains(env: &Env, cm: &Commitment) -> bool {
    env.storage().persistent().has(&DataKey::Frozen(cm.clone()))
}

pub fn insert_frozen(env: &Env, cm: &Commitment) {
    let key = DataKey::Frozen(cm.clone());
    env.storage().persistent().set(&key, &());
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}

// ---------------------------------------------------------------------------
// Frontier (persistent; filled-subtree array stored verbatim, no hashing).
// ---------------------------------------------------------------------------

pub fn set_frontier(env: &Env, frontier: &Vec<Scalar>) {
    let key = DataKey::Frontier;
    env.storage().persistent().set(&key, frontier);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}

pub fn get_frontier(env: &Env) -> Option<Vec<Scalar>> {
    env.storage().persistent().get(&DataKey::Frontier)
}

// ---------------------------------------------------------------------------
// Recent-roots ring buffer (persistent).
// ---------------------------------------------------------------------------

pub fn get_recent_roots(env: &Env) -> Option<Vec<Root>> {
    env.storage().persistent().get(&DataKey::RecentRoots)
}

pub fn set_recent_roots(env: &Env, roots: &Vec<Root>) {
    let key = DataKey::RecentRoots;
    env.storage().persistent().set(&key, roots);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}

/// Initialise the recent-roots buffer with a single seed root.
pub fn init_recent_roots(env: &Env, seed: &Root) {
    let mut roots: Vec<Root> = Vec::new(env);
    roots.push_back(seed.clone());
    set_recent_roots(env, &roots);
}

/// Convenience: instance-storage TTL bump (call after any mutation that touches
/// config so the always-loaded instance entry stays live).
pub fn bump_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}
