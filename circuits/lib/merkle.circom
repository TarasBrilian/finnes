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
include "bits.circom"; // VENDORED field-agnostic Num2Bits / LessThan / IsZero / IsEqual (NO circomlib, NO BN254)

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
    // per-level ordered children (declared at template scope — circom 2.2 forbids
    // signal declarations inside a loop body).
    signal left[depth];
    signal right[depth];
    cur[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // pathIndices[i] must be boolean
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        hashers[i] = HashLR();
        // if pathIndices[i] == 0: (cur, sibling); else (sibling, cur)
        // left  = cur + idx*(sibling - cur)
        // right = sibling + idx*(cur - sibling)
        left[i]  <== cur[i] + pathIndices[i] * (pathElements[i] - cur[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (cur[i] - pathElements[i]);
        hashers[i].left  <== left[i];
        hashers[i].right <== right[i];
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

    // --- empty-subtree constants: zeros[0]=0, zeros[l]=Poseidon(zeros[l-1],zeros[l-1])
    // Computed in-circuit (deterministic; equals sdk/src/merkle.ts emptyTreeZeros
    // and the contract genesis). Only levels 0..depth-1 are used by inserts.
    signal zeros[depth];
    component zhash[depth];              // zhash[0] unused (zeros[0] is the constant 0)
    zeros[0] <== 0;
    for (var l = 1; l < depth; l++) {
        zhash[l] = HashLR();
        zhash[l].left  <== zeros[l - 1];
        zhash[l].right <== zeros[l - 1];
        zeros[l] <== zhash[l].out;
    }

    // --- thread the frontier across the inserts.
    // fr[j] = frontier BEFORE insert j; fr[0]=old_frontier; fr[nInserts]=new_frontier.
    signal fr[nInserts + 1][depth];
    for (var l = 0; l < depth; l++) { fr[0][l] <== old_frontier[l]; }

    component idxBits[nInserts];
    component levelHash[nInserts][depth];
    signal cur[nInserts][depth + 1];    // running hash climbing the tree for insert j
    signal leftIn[nInserts][depth];
    signal rightIn[nInserts][depth];

    for (var j = 0; j < nInserts; j++) {
        // bit l of (nextIndex + j): even at level l => left child, odd => right child.
        // Num2Bits(depth) also range-bounds the append index to < 2^depth (no overflow).
        idxBits[j] = Num2Bits(depth);
        idxBits[j].in <== nextIndex + j;

        cur[j][0] <== leaves[j];
        for (var l = 0; l < depth; l++) {
            // Select the two hash inputs by the bit b = idxBits[j].out[l]:
            //   b==0 (left child):  left = cur,        right = zeros[l]
            //   b==1 (right child): left = fr[j][l],   right = cur
            leftIn[j][l]  <== cur[j][l] + idxBits[j].out[l] * (fr[j][l] - cur[j][l]);
            rightIn[j][l] <== zeros[l]  + idxBits[j].out[l] * (cur[j][l] - zeros[l]);

            levelHash[j][l] = HashLR();
            levelHash[j][l].left  <== leftIn[j][l];
            levelHash[j][l].right <== rightIn[j][l];
            cur[j][l + 1] <== levelHash[j][l].out;

            // frontier update: on a LEFT child (b==0) this node becomes the filled
            // subtree at level l; on a RIGHT child (b==1) the level is unchanged.
            fr[j + 1][l] <== fr[j][l] + (1 - idxBits[j].out[l]) * (cur[j][l] - fr[j][l]);
        }
    }

    for (var l = 0; l < depth; l++) { new_frontier[l] <== fr[nInserts][l]; }
    // current tree root after the final insert (empty positions folded as zeros).
    new_root <== cur[nInserts - 1][depth];
}
