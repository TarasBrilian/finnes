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

use soroban_sdk::{contracttype, Address, BytesN, Env, Vec};

use crate::types::{Circuit, Commitment, IntentRecord, Nullifier, Root, Scalar, VerifyingKey};

/// Size of the recent-roots ring buffer (windowed-root acceptance).
///
/// Anchors and the windowed compliance roots (kyc/sanction/assets) are accepted
/// if they appear anywhere in the last `RECENT_ROOTS_CAPACITY` published roots.
/// Larger window = more in-flight proofs survive a root change, at a small
/// storage cost. TODO: tune against expected block cadence / proving latency.
pub const RECENT_ROOTS_CAPACITY: u32 = 64;

/// Recent-roots window for the WINDOWED compliance roots (kyc/sanction/assets).
/// They change rarely and benignly (invariant #6), so a short window is enough to
/// keep an in-flight proof valid across a root update while proving latency
/// elapses. `frozen_root` is deliberately NOT windowed (strict — the immediacy of
/// clawback). Bound separately from the commitment-tree anchor window above.
pub const COMPLIANCE_WINDOW_CAPACITY: u32 = 16;

/// Approx ledgers/day at the ~5s close cadence; the basis for the TTL bumps below.
pub const LEDGERS_PER_DAY: u32 = 17_280;

/// TTL bump targets (in ledgers), grounded in Soroban's rent model (FIN-011). On
/// every mutation we extend an entry whose remaining runway has fallen below
/// `*_THRESHOLD` out to `*_EXTEND`, so any entry touched within the extend horizon
/// never archives. Under Protocol 23 archived persistent entries auto-restore on
/// access, so these bounds are liveness/cost tuning, NOT a safety boundary
/// (nullifiers stay correct either way, invariant #4).
///
/// `*_EXTEND` MUST stay ≤ the deployed network's `max_entry_ttl` or the host
/// TRAPS the `extend_ttl` — which would brick EVERY mutating entrypoint (incl.
/// `init`). The 30-day extend below sits well under the standard Soroban network
/// persistent max (~6 months on testnet/futurenet/mainnet), so it is safe on the
/// usual targets; a custom/quickstart network with a smaller `max_entry_ttl` MUST
/// lower these. PRODUCTION should promote these to validated `InitConfig` params
/// checked against the live `max_entry_ttl` at init rather than compile-time consts.
pub const PERSISTENT_TTL_THRESHOLD: u32 = 7 * LEDGERS_PER_DAY; // bump when <7 days left
pub const PERSISTENT_TTL_EXTEND: u32 = 30 * LEDGERS_PER_DAY; // extend out to 30 days
/// Instance entry (config/VKs, always loaded with the contract). Same horizon.
pub const INSTANCE_TTL_THRESHOLD: u32 = 7 * LEDGERS_PER_DAY;
pub const INSTANCE_TTL_EXTEND: u32 = 30 * LEDGERS_PER_DAY;

/// Which commitment tree a tree-state key refers to (FIN-017). The MAIN tree holds
/// shielded notes (shield/transfer/unshield/dvp/mint_recovery); the ESCROW tree
/// holds intent-owned escrow notes (escrow_deposit → settle/refund). Per-tree
/// recent-roots windows give free domain separation: an escrow note's only valid
/// anchor is an escrow root, which is NOT in the main window, so
/// `confidential_transfer` can never consume it.
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tree {
    Main,
    Escrow,
}

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
    /// KYC-approved set root (membership). Latest value; window in `KycWindow`.
    KycRoot,
    /// Sanctioned set root (non-membership). Latest; window in `SanctionWindow`.
    SanctionRoot,
    /// Authorized-assets registry root. Latest; window in `AssetsWindow`.
    AssetsRoot,
    /// Recent-roots window (`Vec<Root>`) for windowed `kyc_root` acceptance (#6).
    KycWindow,
    /// Recent-roots window for windowed `sanction_root` acceptance (#6).
    SanctionWindow,
    /// Recent-roots window for windowed `assets_root` acceptance (#6).
    AssetsWindow,
    /// Issuer-managed frozen-commitment set root (non-membership). **Strict.**
    FrozenRoot,
    /// Current commitment-tree root (latest published), per tree (#11/#12, FIN-017).
    TreeRoot(Tree),
    /// Number of leaves inserted into the given commitment tree so far (the next
    /// append index). Checked against the circuits' `next_index` public input so the
    /// in-circuit `FrontierTransition` inserts at the true position (#11/#12).
    LeafCount(Tree),
    /// Groth16 verifying key for a given circuit.
    Vk(Circuit),
    /// Intent record for a production escrow-DvP settlement (FIN-017).
    Intent(BytesN<32>),

    // --- persistent (fund-critical / unbounded) ---
    /// Existence marker for a spent nullifier. Value is unit `()`; presence ==
    /// spent. One entry per nullifier (invariant #4).
    Nullifier(BytesN<32>),
    /// Commitment-tree frontier (filled subtrees), `TREE_DEPTH` scalars, per tree.
    Frontier(Tree),
    /// Recent-roots ring buffer (commitment-tree roots) for windowed anchoring, per tree.
    RecentRoots(Tree),
    /// Membership marker for a commitment in the frozen set (existence check).
    /// Complements `FrozenRoot`: the contract stores the verbatim issuer-set root
    /// strictly, and also records which `cm`s were frozen for auditability.
    Frozen(BytesN<32>),
    /// SAC contract `Address` for an `asset_id` (FIN-010). The contract performs
    /// no hashing (invariant #11), so it cannot recompute `Poseidon(sac_address)`
    /// to resolve the concrete token; instead the admin registers an
    /// `asset_id -> Address` mirror of the authorized-assets registry, and
    /// shield/unshield move the real SAC token through it.
    SacAddr(BytesN<32>),
    /// Concrete Stellar `Address` for a transparent `recipient` field (FIN-010).
    /// The demo account registry: the unshield circuit binds compliance to the
    /// field-encoded `recipient`; the contract maps it to the real payout address.
    TransparentAddr(BytesN<32>),
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

// Retained for the indexer/admin-view surface and future entrypoints; not yet
// read by a contract path.
#[allow(dead_code)]
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

// Windowed compliance roots (FIN-011, invariant #6). The setter records the
// latest value AND appends it to a small recent-roots window so a proof anchored
// to the immediately-prior root still validates while proving latency elapses;
// the checker accepts any root within that window. `init` seeds the window with
// one entry (the setter runs once); each admin update appends, evicting the
// oldest past `COMPLIANCE_WINDOW_CAPACITY`. `frozen_root` is NOT windowed.

/// Append `r` to a compliance-root window (instance storage; small, always loaded),
/// evicting oldest-first past capacity. De-dups against membership ANYWHERE in the
/// window, not just the tail: a root that is already accepted must not consume a
/// second slot, or a toggling update pattern (A → B → A) would fill the window
/// with duplicates and prematurely evict still-valid distinct roots.
fn push_compliance_window(env: &Env, key: DataKey, r: &Root) {
    let mut v: Vec<Root> = env
        .storage()
        .instance()
        .get(&key)
        .unwrap_or_else(|| Vec::new(env));
    // Already in the window ⇒ still accepted; nothing to do (no duplicate slot).
    for existing in v.iter() {
        if &existing == r {
            return;
        }
    }
    v.push_back(r.clone());
    while v.len() > COMPLIANCE_WINDOW_CAPACITY {
        v.remove(0);
    }
    env.storage().instance().set(&key, &v);
}

/// True if `candidate` appears anywhere in the compliance-root window at `key`.
fn compliance_window_contains(env: &Env, key: DataKey, candidate: &Root) -> bool {
    match env.storage().instance().get::<DataKey, Vec<Root>>(&key) {
        Some(v) => {
            for r in v.iter() {
                if &r == candidate {
                    return true;
                }
            }
            false
        }
        None => false,
    }
}

pub fn set_kyc_root(env: &Env, r: &Root) {
    env.storage().instance().set(&DataKey::KycRoot, r);
    push_compliance_window(env, DataKey::KycWindow, r);
}
pub fn get_kyc_root(env: &Env) -> Option<Root> {
    env.storage().instance().get(&DataKey::KycRoot)
}
/// Windowed acceptance for `kyc_root` (invariant #6).
pub fn kyc_root_in_window(env: &Env, candidate: &Root) -> bool {
    compliance_window_contains(env, DataKey::KycWindow, candidate)
}

pub fn set_sanction_root(env: &Env, r: &Root) {
    env.storage().instance().set(&DataKey::SanctionRoot, r);
    push_compliance_window(env, DataKey::SanctionWindow, r);
}
pub fn get_sanction_root(env: &Env) -> Option<Root> {
    env.storage().instance().get(&DataKey::SanctionRoot)
}
/// Windowed acceptance for `sanction_root` (invariant #6).
pub fn sanction_root_in_window(env: &Env, candidate: &Root) -> bool {
    compliance_window_contains(env, DataKey::SanctionWindow, candidate)
}

pub fn set_assets_root(env: &Env, r: &Root) {
    env.storage().instance().set(&DataKey::AssetsRoot, r);
    push_compliance_window(env, DataKey::AssetsWindow, r);
}
pub fn get_assets_root(env: &Env) -> Option<Root> {
    env.storage().instance().get(&DataKey::AssetsRoot)
}
/// Windowed acceptance for `assets_root` (invariant #6).
pub fn assets_root_in_window(env: &Env, candidate: &Root) -> bool {
    compliance_window_contains(env, DataKey::AssetsWindow, candidate)
}

pub fn set_frozen_root(env: &Env, r: &Root) {
    env.storage().instance().set(&DataKey::FrozenRoot, r);
}
pub fn get_frozen_root(env: &Env) -> Option<Root> {
    env.storage().instance().get(&DataKey::FrozenRoot)
}

pub fn set_tree_root(env: &Env, tree: Tree, r: &Root) {
    env.storage().instance().set(&DataKey::TreeRoot(tree), r);
}
pub fn get_tree_root(env: &Env, tree: Tree) -> Option<Root> {
    env.storage().instance().get(&DataKey::TreeRoot(tree))
}

/// Commitment-tree leaf count (the next append index), per tree. Instance storage:
/// a small `u64` always loaded with config. Seeded to 0 at `init` (empty tree) and
/// advanced by `advance_leaf_count` on every successful tree mutation.
pub fn set_leaf_count(env: &Env, tree: Tree, count: u64) {
    env.storage()
        .instance()
        .set(&DataKey::LeafCount(tree), &count);
}
pub fn get_leaf_count(env: &Env, tree: Tree) -> Option<u64> {
    env.storage().instance().get(&DataKey::LeafCount(tree))
}

/// Advance the leaf count by `n` newly-inserted leaves. Saturating add guards
/// against wraparound (the tree caps at 2^TREE_DEPTH long before u64 overflow).
pub fn advance_leaf_count(env: &Env, tree: Tree, n: u32) {
    let cur = get_leaf_count(env, tree).unwrap_or(0);
    set_leaf_count(env, tree, cur.saturating_add(n as u64));
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
// Asset / transparent-recipient registries (persistent; admin-managed mirror of
// the assets registry + demo account registry, FIN-010). Keyed entries so the
// always-loaded instance config does not grow with the asset/account count.
// ---------------------------------------------------------------------------

pub fn set_asset_sac(env: &Env, asset_id: &Scalar, sac: &Address) {
    let key = DataKey::SacAddr(asset_id.clone());
    env.storage().persistent().set(&key, sac);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}

pub fn get_asset_sac(env: &Env, asset_id: &Scalar) -> Option<Address> {
    env.storage()
        .persistent()
        .get(&DataKey::SacAddr(asset_id.clone()))
}

pub fn set_transparent_addr(env: &Env, recipient: &Scalar, addr: &Address) {
    let key = DataKey::TransparentAddr(recipient.clone());
    env.storage().persistent().set(&key, addr);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}

pub fn get_transparent_addr(env: &Env, recipient: &Scalar) -> Option<Address> {
    env.storage()
        .persistent()
        .get(&DataKey::TransparentAddr(recipient.clone()))
}

// ---------------------------------------------------------------------------
// Frontier (persistent; filled-subtree array stored verbatim, no hashing).
// ---------------------------------------------------------------------------

pub fn set_frontier(env: &Env, tree: Tree, frontier: &Vec<Scalar>) {
    let key = DataKey::Frontier(tree);
    env.storage().persistent().set(&key, frontier);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}

pub fn get_frontier(env: &Env, tree: Tree) -> Option<Vec<Scalar>> {
    env.storage().persistent().get(&DataKey::Frontier(tree))
}

// ---------------------------------------------------------------------------
// Recent-roots ring buffer (persistent), per tree.
// ---------------------------------------------------------------------------

pub fn get_recent_roots(env: &Env, tree: Tree) -> Option<Vec<Root>> {
    env.storage().persistent().get(&DataKey::RecentRoots(tree))
}

pub fn set_recent_roots(env: &Env, tree: Tree, roots: &Vec<Root>) {
    let key = DataKey::RecentRoots(tree);
    env.storage().persistent().set(&key, roots);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}

// ---------------------------------------------------------------------------
// Escrow-DvP intents (persistent, keyed by intent_id; FIN-017).
// ---------------------------------------------------------------------------

pub fn intent_exists(env: &Env, id: &BytesN<32>) -> bool {
    env.storage().persistent().has(&DataKey::Intent(id.clone()))
}

pub fn get_intent(env: &Env, id: &BytesN<32>) -> Option<IntentRecord> {
    env.storage().persistent().get(&DataKey::Intent(id.clone()))
}

pub fn set_intent(env: &Env, id: &BytesN<32>, record: &IntentRecord) {
    let key = DataKey::Intent(id.clone());
    env.storage().persistent().set(&key, record);
    env.storage()
        .persistent()
        .extend_ttl(&key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}

/// Initialise the recent-roots buffer with a single seed root.
pub fn init_recent_roots(env: &Env, tree: Tree, seed: &Root) {
    let mut roots: Vec<Root> = Vec::new(env);
    roots.push_back(seed.clone());
    set_recent_roots(env, tree, &roots);
}

/// Convenience: instance-storage TTL bump (call after any mutation that touches
/// config so the always-loaded instance entry stays live).
pub fn bump_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND);
}
