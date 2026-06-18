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
// MerkleNonMembership(depth) — Indexed Merkle Tree (IMT) non-membership.
//   Sanctions set AND frozen set (reused per Security invariants #14 & #19;
//   FIN-001 chose IMT). Each set is an IMT whose leaves form a sorted linked
//   list: leaf = Poseidon(value, next_index, next_value, 0, 0) (arity 5 = t=6,
//   the next supported Poseidon width; the 2 zero slots pad value/next_index/
//   next_value up to a supported arity — see sdk/src/merkle.ts imtLeafHash).
//
//   `target` is absent iff there is a stored "low" leaf with
//       low_value < target  AND  (target < low_next_value OR low_next_value == 0)
//   where low_next_value == 0 marks `low` as the current maximum (the list tail).
//   Adjacency is INTRINSIC to the IMT: the low leaf's own next_value pointer
//   bounds the gap, so no extra "canonical consecutive pair" constraint is needed
//   (this is what the old sorted-pair encoding left as a dangling TODO).
//
//   Comparisons use the r-aware LessThanField (bits.circom): `target`,
//   `low_value`, `low_next_value` are raw Poseidon outputs that span the whole
//   scalar field, so a 252-bit LessThan would be UNSOUND. LessThanField binds
//   each operand to its canonical < r form first (fund-critical, invariant #14).
// -----------------------------------------------------------------------------
template MerkleNonMembership(depth) {
    signal input target;            // the value asserted to be absent (e.g. owner_pk, cm)
    signal input low_value;         // greatest stored value < target (the "low" leaf)
    signal input low_next_index;    // low leaf's next pointer (index) — part of the leaf hash
    signal input low_next_value;    // low leaf's next pointer (value); 0 == low is the maximum
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    // (1) low_value < target  (sound over the full field).
    component ltLow = LessThanField();
    ltLow.a <== low_value;
    ltLow.b <== target;
    ltLow.out === 1;

    // (2) target < low_next_value  OR  low_next_value == 0 (low leaf is the tail).
    component isMax = IsZero();
    isMax.in <== low_next_value;
    component ltHigh = LessThanField();
    ltHigh.a <== target;
    ltHigh.b <== low_next_value;
    // hiOk = ltHigh.out OR isMax.out  (assert exactly one branch holds).
    signal hiOk;
    hiOk <== 1 - (1 - ltHigh.out) * (1 - isMax.out);
    hiOk === 1;

    // (3) the low leaf must be a real leaf of the IMT under `root`.
    //   leaf = Poseidon(low_value, low_next_index, low_next_value, 0, 0)
    component leafH = PoseidonBLS(5);
    leafH.in[0] <== low_value;
    leafH.in[1] <== low_next_index;
    leafH.in[2] <== low_next_value;
    leafH.in[3] <== 0;
    leafH.in[4] <== 0;

    component incl = MerkleInclusion(depth);
    incl.leaf <== leafH.out;
    for (var i = 0; i < depth; i++) {
        incl.pathElements[i] <== pathElements[i];
        incl.pathIndices[i]  <== pathIndices[i];
    }
    incl.root <== root;
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
