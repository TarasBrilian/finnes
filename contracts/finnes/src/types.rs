//! On-chain types for proofs, verifying keys, and public inputs.
//!
//! # CANONICAL PUBLIC-INPUT ORDERING - DO NOT REORDER
//!
//! The `to_scalars()` ordering for every circuit below MUST match
//! `docs/PUBLIC_IO.md` **exactly**, byte-for-byte field-for-field. That file is
//! the single source of truth and is mirrored across four surfaces:
//!   - `circuits/*.circom` `main` public-signal order,
//!   - this file (`PublicInputs::to_scalars()`),
//!   - the prover's `prover/src/witness.ts`,
//!   - the SDK helpers in `sdk/src/`.
//!
//! A mismatch surfaces as a bogus "invalid proof" (a Groth16 verify failure)
//! that looks like a crypto bug but is almost always ordering/layout drift.
//! Changing any ordering here requires a fresh phase-2 ceremony for that circuit
//! and a new `VerifyingKey` (CLAUDE.md → "When adding a new circuit…").
//!
//! Invariant #12: the Merkle transition is public-IO - `old_frontier` (in,
//! `D` elements, checked equal to state) and `new_frontier`/`new_root` (out,
//! stored verbatim). Root alone is insufficient.
//!
//! Invariant #5: auditor (and recipient) ciphertexts are carried as public
//! inputs (field-packed). Groth16 binds public inputs inherently, so the
//! contract NEVER hashes ciphertext blobs - it just feeds them into the verify.

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};

/// Merkle tree depth (filled-subtree frontier length).
///
/// MUST equal the circuits' depth. `D = 20` is LOCKED (FIN-001, docs/PUBLIC_IO.md
/// §"Tree"): capacity 2^20 ≈ 1.05M notes, demo-cheap to prove. Keep this constant
/// in lockstep with the circuits and `sdk/src/merkle.ts`; changing it is a
/// fresh-ceremony event, not a runtime parameter.
pub const TREE_DEPTH: u32 = 20;

/// A BLS12-381 scalar-field (`Fr`) element, big-endian, 32 bytes.
///
/// Every public input is a field element fed to the verifier as one G1
/// scalar-mul. Off-chain we use decimal strings for readability; at the contract
/// boundary everything is fixed-width bytes (CLAUDE.md → Field encoding).
pub type Scalar = BytesN<32>;

/// Commitment / nullifier / root - all are `Fr` elements on the wire.
pub type Commitment = BytesN<32>;
pub type Nullifier = BytesN<32>;
pub type Root = BytesN<32>;

/// A Groth16 proof: `(A ∈ G1, B ∈ G2, C ∈ G1)`.
///
/// Stored as compressed/uncompressed point bytes whose exact encoding is decided
/// by `verifier.rs` when it deserialises into host-fn `G1Affine`/`G2Affine`.
/// We keep raw `Bytes` here so the contract surface stays encoding-agnostic.
#[contracttype]
#[derive(Clone)]
pub struct Proof {
    /// G1 point `A`.
    pub a: Bytes,
    /// G2 point `B`.
    pub b: Bytes,
    /// G1 point `C`.
    pub c: Bytes,
}

/// Groth16 verifying key, one per circuit.
///
/// Mirrors the snarkjs VK export. `ic` has exactly `num_public + 1` G1 points
/// (the constant term plus one per public input); `verifier.rs` enforces that
/// arity against the supplied public-input vector (Error::VerifyingKeyArityMismatch).
#[contracttype]
#[derive(Clone)]
pub struct VerifyingKey {
    /// `alpha` in G1.
    pub alpha_g1: Bytes,
    /// `beta` in G2.
    pub beta_g2: Bytes,
    /// `gamma` in G2.
    pub gamma_g2: Bytes,
    /// `delta` in G2.
    pub delta_g2: Bytes,
    /// `IC` points in G1; length == number of public inputs + 1.
    pub ic: Vec<Bytes>,
}

/// `init` configuration bundle.
///
/// Soroban caps a contract function at 10 parameters, so the initial config is
/// passed as one struct rather than 13 positional args. `admin` and
/// `issuer_authority` are kept as **distinct** authorities (read vs write) even
/// if one operator holds both in the demo (invariant #14).
#[contracttype]
#[derive(Clone)]
pub struct InitConfig {
    pub admin: Address,
    pub issuer_authority: Address,
    pub auditor_pk: Scalar,
    pub kyc_root: Root,
    pub sanction_root: Root,
    pub assets_root: Root,
    pub frozen_root: Root,
    /// Empty-tree frontier seed; exactly `TREE_DEPTH` elements.
    pub initial_frontier: Vec<Scalar>,
    pub initial_root: Root,
    pub vk_shield: VerifyingKey,
    pub vk_transfer: VerifyingKey,
    pub vk_unshield: VerifyingKey,
    pub vk_dvp: VerifyingKey,
}

/// Identifies which circuit a proof belongs to (selects the VK and the
/// public-input layout). Stored in `DataKey::Vk(Circuit)`.
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Circuit {
    Shield,
    Transfer,
    Unshield,
    Dvp,
}

// ---------------------------------------------------------------------------
// PublicInputs - one struct per circuit. Each `to_scalars()` reproduces the
// exact index order documented in docs/PUBLIC_IO.md.
// ---------------------------------------------------------------------------

/// `transfer.circom` - 2-in / 2-out, single asset.
///
/// Index order (docs/PUBLIC_IO.md § transfer.circom):
/// ```text
///  0 anchor_root  1 kyc_root  2 sanction_root  3 assets_root  4 frozen_root
///  5 auditor_pk   6 nf_in_0   7 nf_in_1        8 cm_out_0     9 cm_out_1
/// 10 new_root    11 fee      12 next_index
/// 13..13+D-1   old_frontier[0..D-1]
///    ..+D       new_frontier[0..D-1]
///    ..+2·K_a   c_auditor    (c_auditor_0 ‖ c_auditor_1; BOTH mandatory, inv #5)
///    ..+2·K_r   c_recipient  (c_recipient_0 ‖ c_recipient_1)
/// ```
/// Total 73 public signals.
#[contracttype]
#[derive(Clone)]
pub struct TransferPublicInputs {
    pub anchor_root: Root,
    pub kyc_root: Root,
    pub sanction_root: Root,
    pub assets_root: Root,
    pub frozen_root: Root,
    pub auditor_pk: Scalar,
    pub nf_in_0: Nullifier,
    pub nf_in_1: Nullifier,
    pub cm_out_0: Commitment,
    pub cm_out_1: Commitment,
    pub new_root: Root,
    pub fee: Scalar,
    /// Current leaf count before insertion; the contract checks this equals the
    /// stored `leaf_count` so the circuit's `FrontierTransition` inserts at the
    /// true append index (invariants #11/#12). Never prover-controlled.
    pub next_index: Scalar,
    /// `old_frontier` - exactly `TREE_DEPTH` elements; checked equal to state.
    pub old_frontier: Vec<Scalar>,
    /// `new_frontier` - exactly `TREE_DEPTH` elements; stored verbatim.
    pub new_frontier: Vec<Scalar>,
    /// `c_auditor` = `c_auditor_0 ‖ c_auditor_1`, `2·K_a` packed field elements;
    /// EVERY output note (incl. the change note) carries a mandatory auditor
    /// ciphertext (invariant #5).
    pub c_auditor: Vec<Scalar>,
    /// `c_recipient` = `c_recipient_0 ‖ c_recipient_1`, `2·K_r` packed elements.
    pub c_recipient: Vec<Scalar>,
}

/// `shield.circom` - transparent → shielded (0 shielded inputs, 1 transparent).
///
/// Index order (docs/PUBLIC_IO.md § shield.circom):
/// ```text
///  0 asset_id  1 amount  2 kyc_root  3 assets_root  4 auditor_pk
///  5 cm_out_0  6 new_root  7 fee
///  8..8+D-1   old_frontier[0..D-1]
///    ..+D     new_frontier[0..D-1]
///    ..+K_a   c_auditor    ..+K_r c_recipient
/// ```
#[contracttype]
#[derive(Clone)]
pub struct ShieldPublicInputs {
    pub asset_id: Scalar,
    pub amount: Scalar,
    pub kyc_root: Root,
    pub assets_root: Root,
    pub auditor_pk: Scalar,
    pub cm_out_0: Commitment,
    pub new_root: Root,
    pub fee: Scalar,
    pub old_frontier: Vec<Scalar>,
    pub new_frontier: Vec<Scalar>,
    pub c_auditor: Vec<Scalar>,
    pub c_recipient: Vec<Scalar>,
}

/// `unshield.circom` - shielded → transparent (1+ shielded inputs, transparent out).
///
/// Index order (docs/PUBLIC_IO.md § unshield.circom):
/// ```text
///  0 anchor_root  1 kyc_root  2 sanction_root  3 assets_root  4 frozen_root
///  5 auditor_pk   6 nf_in_0   7 asset_id       8 amount       9 recipient
/// 10 cm_change_0 11 new_root 12 fee
/// 13..13+D-1  old_frontier[0..D-1]
///    ..+D     new_frontier[0..D-1]
///    ..+K_a   c_auditor    (for change note, if any)
/// ```
#[contracttype]
#[derive(Clone)]
pub struct UnshieldPublicInputs {
    pub anchor_root: Root,
    pub kyc_root: Root,
    pub sanction_root: Root,
    pub assets_root: Root,
    pub frozen_root: Root,
    pub auditor_pk: Scalar,
    pub nf_in_0: Nullifier,
    pub asset_id: Scalar,
    pub amount: Scalar,
    /// Transparent recipient - a field-encoded Stellar address used for the SAC
    /// `transfer`. The contract additionally checks recipient authorisation
    /// (invariant #19) before performing effects.
    pub recipient: Scalar,
    /// Optional change-note commitment; zero/null sentinel if none.
    pub cm_change_0: Commitment,
    pub new_root: Root,
    pub fee: Scalar,
    pub old_frontier: Vec<Scalar>,
    pub new_frontier: Vec<Scalar>,
    pub c_auditor: Vec<Scalar>,
}

/// `dvp.circom` - atomic two-asset settlement (DEMO: single combined proof).
///
/// Index order (docs/PUBLIC_IO.md § dvp.circom):
/// ```text
///  0 anchor_root  1 kyc_root  2 sanction_root  3 assets_root  4 frozen_root
///  5 auditor_pk   6 nf_legX_0 7 nf_legY_0      8 cm_out_X     9 cm_out_Y
/// 10 new_root    11 fee_X    12 fee_Y
/// 13..13+D-1  old_frontier[0..D-1]
///    ..+D     new_frontier[0..D-1]
///    ..+K_a   c_auditor_X  ..+K_a c_auditor_Y
///    ..+K_r   c_recipient_X ..+K_r c_recipient_Y
/// ```
#[contracttype]
#[derive(Clone)]
pub struct DvpPublicInputs {
    pub anchor_root: Root,
    pub kyc_root: Root,
    pub sanction_root: Root,
    pub assets_root: Root,
    pub frozen_root: Root,
    pub auditor_pk: Scalar,
    pub nf_leg_x_0: Nullifier,
    pub nf_leg_y_0: Nullifier,
    pub cm_out_x: Commitment,
    pub cm_out_y: Commitment,
    pub new_root: Root,
    pub fee_x: Scalar,
    pub fee_y: Scalar,
    pub old_frontier: Vec<Scalar>,
    pub new_frontier: Vec<Scalar>,
    pub c_auditor_x: Vec<Scalar>,
    pub c_auditor_y: Vec<Scalar>,
    pub c_recipient_x: Vec<Scalar>,
    pub c_recipient_y: Vec<Scalar>,
}

// ---------------------------------------------------------------------------
// to_scalars(): flatten each struct into the verifier's ordered scalar vector.
// The verifier consumes this vector positionally - index i pairs with vk.ic[i+1]
// - so the push order below IS the public-IO contract. Keep it identical to
// docs/PUBLIC_IO.md.
// ---------------------------------------------------------------------------

/// Append every element of `src` to `dst`, preserving order. Used for the
/// variable-length segments (frontiers, packed ciphertexts).
fn extend(dst: &mut Vec<Scalar>, src: &Vec<Scalar>) {
    for s in src.iter() {
        dst.push_back(s);
    }
}

impl TransferPublicInputs {
    /// Flatten to the canonical ordered scalar vector. See struct doc + PUBLIC_IO.md.
    pub fn to_scalars(&self, env: &Env) -> Vec<Scalar> {
        let mut v: Vec<Scalar> = Vec::new(env);
        v.push_back(self.anchor_root.clone()); // 0
        v.push_back(self.kyc_root.clone()); // 1
        v.push_back(self.sanction_root.clone()); // 2
        v.push_back(self.assets_root.clone()); // 3
        v.push_back(self.frozen_root.clone()); // 4
        v.push_back(self.auditor_pk.clone()); // 5
        v.push_back(self.nf_in_0.clone()); // 6
        v.push_back(self.nf_in_1.clone()); // 7
        v.push_back(self.cm_out_0.clone()); // 8
        v.push_back(self.cm_out_1.clone()); // 9
        v.push_back(self.new_root.clone()); // 10
        v.push_back(self.fee.clone()); // 11
        v.push_back(self.next_index.clone()); // 12
        extend(&mut v, &self.old_frontier); // 13 .. 13+D-1
        extend(&mut v, &self.new_frontier); //    .. +D
        extend(&mut v, &self.c_auditor); //    .. +2·K_a (note 0 ‖ note 1)
        extend(&mut v, &self.c_recipient); //    .. +2·K_r (note 0 ‖ note 1)
        v
    }
}

impl ShieldPublicInputs {
    /// Flatten to the canonical ordered scalar vector. See struct doc + PUBLIC_IO.md.
    pub fn to_scalars(&self, env: &Env) -> Vec<Scalar> {
        let mut v: Vec<Scalar> = Vec::new(env);
        v.push_back(self.asset_id.clone()); // 0
        v.push_back(self.amount.clone()); // 1
        v.push_back(self.kyc_root.clone()); // 2
        v.push_back(self.assets_root.clone()); // 3
        v.push_back(self.auditor_pk.clone()); // 4
        v.push_back(self.cm_out_0.clone()); // 5
        v.push_back(self.new_root.clone()); // 6
        v.push_back(self.fee.clone()); // 7
        extend(&mut v, &self.old_frontier); // 8 .. 8+D-1
        extend(&mut v, &self.new_frontier);
        extend(&mut v, &self.c_auditor);
        extend(&mut v, &self.c_recipient);
        v
    }
}

impl UnshieldPublicInputs {
    /// Flatten to the canonical ordered scalar vector. See struct doc + PUBLIC_IO.md.
    pub fn to_scalars(&self, env: &Env) -> Vec<Scalar> {
        let mut v: Vec<Scalar> = Vec::new(env);
        v.push_back(self.anchor_root.clone()); // 0
        v.push_back(self.kyc_root.clone()); // 1
        v.push_back(self.sanction_root.clone()); // 2
        v.push_back(self.assets_root.clone()); // 3
        v.push_back(self.frozen_root.clone()); // 4
        v.push_back(self.auditor_pk.clone()); // 5
        v.push_back(self.nf_in_0.clone()); // 6
        v.push_back(self.asset_id.clone()); // 7
        v.push_back(self.amount.clone()); // 8
        v.push_back(self.recipient.clone()); // 9
        v.push_back(self.cm_change_0.clone()); // 10
        v.push_back(self.new_root.clone()); // 11
        v.push_back(self.fee.clone()); // 12
        extend(&mut v, &self.old_frontier); // 13 .. 13+D-1
        extend(&mut v, &self.new_frontier);
        extend(&mut v, &self.c_auditor);
        v
    }
}

impl DvpPublicInputs {
    /// Flatten to the canonical ordered scalar vector. See struct doc + PUBLIC_IO.md.
    pub fn to_scalars(&self, env: &Env) -> Vec<Scalar> {
        let mut v: Vec<Scalar> = Vec::new(env);
        v.push_back(self.anchor_root.clone()); // 0
        v.push_back(self.kyc_root.clone()); // 1
        v.push_back(self.sanction_root.clone()); // 2
        v.push_back(self.assets_root.clone()); // 3
        v.push_back(self.frozen_root.clone()); // 4
        v.push_back(self.auditor_pk.clone()); // 5
        v.push_back(self.nf_leg_x_0.clone()); // 6
        v.push_back(self.nf_leg_y_0.clone()); // 7
        v.push_back(self.cm_out_x.clone()); // 8
        v.push_back(self.cm_out_y.clone()); // 9
        v.push_back(self.new_root.clone()); // 10
        v.push_back(self.fee_x.clone()); // 11
        v.push_back(self.fee_y.clone()); // 12
        extend(&mut v, &self.old_frontier); // 13 .. 13+D-1
        extend(&mut v, &self.new_frontier);
        extend(&mut v, &self.c_auditor_x);
        extend(&mut v, &self.c_auditor_y);
        extend(&mut v, &self.c_recipient_x);
        extend(&mut v, &self.c_recipient_y);
        v
    }
}
