//! Commitment-tree storage helpers - frontier/root bookkeeping and the
//! recent-roots ring buffer.
//!
//! # NO HASHING HERE (invariant #11 / #12)
//!
//! This module performs **no** Merkle hashing and **no** Poseidon. The tree
//! transition (`old_frontier → new_frontier, new_root`) is proved *in-circuit*;
//! the contract only:
//!   1. checks the supplied `old_frontier` equals stored state,
//!   2. stores the circuit-output `new_frontier` / `new_root` **verbatim**, and
//!   3. maintains a ring buffer of recent roots so in-flight proofs anchored to
//!      a slightly-stale root still validate (windowed acceptance).
//!
//! All hashing (commitments, nullifiers, Merkle path) lives in the circuit and
//! the JS/TS SDK - never in this Rust contract.

use soroban_sdk::{Env, Vec};

use crate::errors::Error;
use crate::state::{self, Tree, RECENT_ROOTS_CAPACITY};
use crate::types::{Root, Scalar, TREE_DEPTH};

/// Check that the prover-supplied `old_frontier` matches stored state exactly.
///
/// Invariant #12: `old_frontier` is a public input checked equal to state; the
/// proof is bound to it, so this equality + a valid proof together attest that
/// the new frontier/root is a sound successor of the current tree.
///
/// Length must be exactly `TREE_DEPTH`. On any mismatch returns
/// `Error::MalformedPublicInputs` (wrong length) - the equality failure itself
/// is surfaced as `false`/error by the caller's flow. We do not `unwrap`.
pub fn check_old_frontier(
    env: &Env,
    tree: Tree,
    old_frontier: &Vec<Scalar>,
) -> Result<bool, Error> {
    if old_frontier.len() != TREE_DEPTH {
        return Err(Error::MalformedPublicInputs);
    }
    let stored = match state::get_frontier(env, tree) {
        Some(f) => f,
        // No frontier yet means the contract is uninitialised for tree ops.
        None => return Err(Error::NotInitialized),
    };
    if stored.len() != old_frontier.len() {
        return Ok(false);
    }
    // Element-wise compare; BytesN<32> is Eq.
    for i in 0..stored.len() {
        if stored.get(i) != old_frontier.get(i) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Commit the circuit-output tree transition: store `new_frontier` and
/// `new_root` verbatim, push `new_root` into the recent-roots ring, and advance
/// the stored leaf count by `n_inserts` (the number of output commitments the
/// circuit folded in - shield=1, transfer=2, dvp=2, unshield change=1).
///
/// `n_inserts` MUST equal the `nInserts` the circuit's `FrontierTransition` used;
/// it keeps `LeafCount` in lockstep with the tree so the next tx's `next_index`
/// check is sound (invariants #11/#12).
///
/// Caller MUST have already (a) verified `old_frontier` equals state and (b)
/// verified the Groth16 proof, per the ordered flow in `lib.rs` (invariant #9).
pub fn apply_transition(
    env: &Env,
    tree: Tree,
    new_frontier: &Vec<Scalar>,
    new_root: &Root,
    n_inserts: u32,
) -> Result<(), Error> {
    if new_frontier.len() != TREE_DEPTH {
        return Err(Error::MalformedPublicInputs);
    }
    // Store verbatim - NO hashing.
    state::set_frontier(env, tree, new_frontier);
    state::set_tree_root(env, tree, new_root);
    push_recent_root(env, tree, new_root);
    state::advance_leaf_count(env, tree, n_inserts);
    Ok(())
}

/// True if `candidate` is within the recent-roots window (windowed anchoring).
///
/// Used for `anchor_root`. The compliance roots that are *windowed*
/// (kyc/sanction/assets) use their own freshness policy in `lib.rs`; this helper
/// is specifically the commitment-tree anchor window.
pub fn is_recent_root(env: &Env, tree: Tree, candidate: &Root) -> bool {
    match state::get_recent_roots(env, tree) {
        Some(roots) => {
            for r in roots.iter() {
                if &r == candidate {
                    return true;
                }
            }
            false
        }
        None => false,
    }
}

/// Push `root` onto the recent-roots ring buffer, evicting the oldest entry once
/// `RECENT_ROOTS_CAPACITY` is reached. Order is oldest-first; eviction drops
/// index 0.
fn push_recent_root(env: &Env, tree: Tree, root: &Root) {
    let mut roots = state::get_recent_roots(env, tree).unwrap_or_else(|| Vec::new(env));
    roots.push_back(root.clone());
    while roots.len() > RECENT_ROOTS_CAPACITY {
        roots.remove(0);
    }
    state::set_recent_roots(env, tree, &roots);
}
