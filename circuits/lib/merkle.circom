pragma circom 2.1.6;

// =============================================================================
// merkle.circom — Merkle gadgets over Poseidon-BLS
//   - MerkleInclusion        : leaf ∈ tree(root)            (KYC, input notes)
//   - MerkleNonMembership    : leaf ∉ sorted tree(root)     (sanctions, frozen)
//   - FrontierTransition     : old_frontier -> (new_frontier, new_root)
// =============================================================================
//
// SCAFFOLD. Path-selection wiring is concrete; hashing delegates to PoseidonBLS
// (TODO stub). The non-membership ordering predicate and the incremental-insert
// frontier update logic are TODO bodies.
//
// Compile with `--prime bls12381`.
//
// Tree depth D = 32 (PUBLIC_IO.md; TODO confirm capacity vs proving cost).
// 2-ary Merkle tree, node = Poseidon(left, right).
// =============================================================================

include "poseidon_bls.circom";
include "../node_modules/circomlib/circuits/comparators.circom"; // IsEqual / LessThan — field-agnostic bit gadgets only (NOT Poseidon)

// NOTE on the circomlib include above: ONLY field-agnostic helpers (Num2Bits,
// LessThan, IsEqual, Mux1) are used from circomlib. circomlib's Poseidon is
// FORBIDDEN here (BN254 constants). If the project vendors its own bit gadgets,
// repoint this include; the path must resolve under `--prime bls12381`.

// -----------------------------------------------------------------------------
// HashLR — node = Poseidon(left, right)
// -----------------------------------------------------------------------------
template HashLR() {
    signal input left;
    signal input right;
    signal output out;

    component h = PoseidonBLS(2);
    h.in[0] <== left;
    h.in[1] <== right;
    out <== h.out;
}

// -----------------------------------------------------------------------------
// MerkleInclusion(depth)
//   Proves `leaf` is included under `root` along `pathElements` with the
//   left/right ordering given by `pathIndices` (0 => sibling on right,
//   1 => sibling on left). Outputs the computed root for the caller to bind.
// -----------------------------------------------------------------------------
template MerkleInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];   // each constrained to be a bit
    signal input root;

    signal output computedRoot;

    component hashers[depth];
    // running hash up the tree
    signal cur[depth + 1];
    cur[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // pathIndices[i] must be boolean
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        hashers[i] = HashLR();
        // if pathIndices[i] == 0: (cur, sibling); else (sibling, cur)
        // left  = cur + idx*(sibling - cur)
        // right = sibling + idx*(cur - sibling)
        signal left;
        signal right;
        left  <== cur[i] + pathIndices[i] * (pathElements[i] - cur[i]);
        right <== pathElements[i] + pathIndices[i] * (cur[i] - pathElements[i]);
        hashers[i].left  <== left;
        hashers[i].right <== right;
        cur[i + 1] <== hashers[i].out;
    }

    computedRoot <== cur[depth];
    // bind to the asserted root
    root === computedRoot;
}

// -----------------------------------------------------------------------------
// MerkleNonMembership(depth)
//   Sorted-Merkle-tree non-membership (sanctions set AND frozen set; reused per
//   Security invariants #14 & #19). Proves `target` is NOT a leaf by exhibiting
//   an adjacent pair (lo, hi) that are stored, consecutive leaves with
//   lo < target < hi, and proving inclusion of that pair's node.
//
//   This is the SMT/sorted-list "range gap" technique. Exact leaf encoding
//   (single sorted-leaf SMT vs. consecutive-pair node) is a TODO to be pinned
//   together with the indexer's tree construction; the interface below assumes
//   a sorted pair witness.
// -----------------------------------------------------------------------------
template MerkleNonMembership(depth) {
    signal input target;            // the value asserted to be absent (e.g. owner_pk, cm)
    signal input lo;                // greatest stored leaf < target
    signal input hi;                // least stored leaf > target
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    // (1) ordering: lo < target < hi   (field-agnostic, but operands must be
    //     range-bounded for LessThan to be sound — see TODO).
    // TODO: enforce a domain bound (e.g. Num2Bits(252)) on lo/target/hi so the
    //       LessThan comparisons are sound over the BLS scalar field. Without a
    //       bit-width bound, LessThan can be gamed by wraparound.
    component ltLo = LessThan(252);
    ltLo.in[0] <== lo;
    ltLo.in[1] <== target;
    ltLo.out === 1;

    component ltHi = LessThan(252);
    ltHi.in[0] <== target;
    ltHi.in[1] <== hi;
    ltHi.out === 1;

    // (2) the (lo, hi) pair must be an actual adjacent leaf-node in the tree.
    // Leaf encoding for the gap node:
    //   gapLeaf = Poseidon(lo, hi)   (TODO: confirm encoding matches indexer)
    component gap = HashLR();
    gap.left  <== lo;
    gap.right <== hi;

    component incl = MerkleInclusion(depth);
    incl.leaf <== gap.out;
    for (var i = 0; i < depth; i++) {
        incl.pathElements[i] <== pathElements[i];
        incl.pathIndices[i]  <== pathIndices[i];
    }
    incl.root <== root;
    // TODO: additionally constrain (lo,hi) to be the canonical consecutive pair
    //       (no stored leaf strictly between them). In the sorted-pair-node
    //       encoding this is implied by the pair being a real leaf; document the
    //       exact invariant once the indexer's encoding is fixed.
}

// -----------------------------------------------------------------------------
// FrontierTransition(depth, nInserts)
//   Proves the incremental-Merkle-tree state transition for inserting
//   `nInserts` new leaves (the output commitments) at the current append index:
//
//        old_frontier  --insert(leaves)-->  (new_frontier, new_root)
//
//   `old_frontier` is a PUBLIC INPUT (checked == contract state upstream);
//   `new_frontier` and `new_root` are PUBLIC OUTPUTS the contract stores
//   VERBATIM — the contract performs NO hashing (Security invariant #11, #12).
//
//   Frontier = filled-subtrees array of `depth` field elements. `nextIndex` is
//   the current leaf count (witness) and determines the merge pattern.
// -----------------------------------------------------------------------------
template FrontierTransition(depth, nInserts) {
    signal input old_frontier[depth];
    signal input leaves[nInserts];      // output commitments, in insertion order
    signal input nextIndex;             // current number of leaves before insert (witness)

    signal output new_frontier[depth];
    signal output new_root;

    // zero/empty-subtree constants per level (Poseidon of empty subtrees).
    // TODO: precompute zeros[level] = Poseidon(zeros[level-1], zeros[level-1])
    //       with zeros[0] = EMPTY_LEAF, and either hardcode them as a generated
    //       include or compute them here. Must match the indexer & contract
    //       genesis exactly.
    signal zeros[depth];

    // TODO: implement incremental insertion:
    //   for each leaf j in 0..nInserts-1:
    //     idx = nextIndex + j
    //     walk levels 0..depth-1: if (idx >> level) is even, this node becomes a
    //       new filled-subtree at `level` (store in frontier) and stop climbing;
    //       else combine with old_frontier[level] via Poseidon and continue.
    //   After all inserts, fold remaining frontier + zeros up to the root.
    //
    // Bit decomposition of idx drives the even/odd selection; use Num2Bits on a
    // bounded width (>= depth). This is the most subtle gadget — it MUST agree
    // bit-for-bit with `contracts/finnes/src/merkle.rs` and the indexer's tree.
    //
    // PLACEHOLDER wiring so the template type-checks. NOT a sound transition —
    // replace before any ceremony. Outputs are deliberately set to non-final
    // placeholder values referencing inputs so the under-constraint is obvious.
    for (var lvl = 0; lvl < depth; lvl++) {
        zeros[lvl] <== 0;                       // TODO: real empty-subtree consts
        new_frontier[lvl] <== old_frontier[lvl]; // TODO: real updated frontier
    }
    // TODO: new_root <== fold(new_frontier, zeros)
    new_root <== leaves[0]; // PLACEHOLDER — replace with folded root.
}
