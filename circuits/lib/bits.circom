pragma circom 2.1.6;

// =============================================================================
// bits.circom - vendored field-agnostic bit / comparator gadgets.
// =============================================================================
//
// Standard constructions (cf. circomlib bitify/comparators), VENDORED so the
// project carries NO circomlib dependency. Rationale (invariant #1): circomlib's
// default Poseidon uses BN254 constants and must never be pulled in; vendoring the
// handful of field-agnostic helpers we need keeps the circuit tree self-contained
// and BN254-free. These templates contain NO hardcoded field constants and NO
// Poseidon - they are sound under `--prime bls12381`.
//
// SOUNDNESS NOTE: `LessThan(n)` / `LessEqThan(n)` assume both operands lie in
// `[0, 2^n)` and require `n + 1` bits to decompose alias-free, so `n <= 252` over
// the BLS12-381 scalar field `r` (2^253 < r < 2^255). Comparing FULL-FIELD values
// (e.g. a raw Poseidon output, which can exceed 2^252) needs a dedicated
// r-aware comparator - see merkle.circom non-membership.
// =============================================================================

// Decompose `in` into `n` little-endian bits (out[0] = LSB). Constrains each bit
// boolean and the recomposition == in, so it also proves `in < 2^n`.
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1 = 0;
    var e2 = 1;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;   // boolean
        lc1 += out[i] * e2;
        e2 = e2 + e2;
    }
    lc1 === in;
}

// out = 1 iff in == 0, else 0. Works over any prime field.
template IsZero() {
    signal input in;
    signal output out;
    signal inv;
    inv <-- in != 0 ? 1 / in : 0;
    out <== -in * inv + 1;
    in * out === 0;
}

// out = 1 iff in[0] == in[1].
template IsEqual() {
    signal input in[2];
    signal output out;
    component isz = IsZero();
    isz.in <== in[1] - in[0];
    out <== isz.out;
}

// out = 1 iff in[0] < in[1], assuming both operands are in [0, 2^n) (n <= 252).
template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;
    component n2b = Num2Bits(n + 1);
    n2b.in <== in[0] + (1 << n) - in[1];
    out <== 1 - n2b.out[n];
}

// out = 1 iff in[0] <= in[1], assuming both operands are in [0, 2^n) (n <= 252).
template LessEqThan(n) {
    signal input in[2];
    signal output out;
    component lt = LessThan(n);
    lt.in[0] <== in[0];
    lt.in[1] <== in[1] + 1;
    out <== lt.out;
}

// =============================================================================
// r-aware FULL-FIELD comparison (sound over the entire [0, r), invariant #1).
// =============================================================================
// The vendored LessThan above is only sound for operands < 2^252. Non-membership
// targets (commitments, owner_pk) are raw Poseidon outputs that range over the
// whole scalar field and routinely exceed 2^252, so they need a comparator that
// is sound across [0, r). circomlib's AliasCheck/CompConstant are hardcoded to
// the BN254 modulus and unusable here; the gadgets below are r-aware.
// =============================================================================

// The BLS12-381 scalar field modulus minus one (r - 1). MUST equal
// sdk/src/poseidon.ts FR_MODULUS - 1 (asserted by the parity test). r ∈ [2^254,
// 2^255), so every field element fits in 255 bits.
function BLS_FR_MINUS_1() {
    return 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000;
}

// Assert the little-endian 255-bit array `bits` encodes an integer < r, i.e. it
// is the CANONICAL representation of a field element (no `value + r` alias). This
// is what makes a 255-bit bit-decomposition trustworthy for comparison.
//
// Method: lexicographic "bits <= r-1" from MSB to LSB. `eq[i]` tracks whether all
// higher bits equal r-1's; at any position where r-1 has a 0 bit, `bits` may not
// have a 1 while still equal-so-far (that would make the value > r-1).
template AliasCheckBLS() {
    signal input bits[255];
    var Km1 = BLS_FR_MINUS_1();
    signal eq[256];
    eq[255] <== 1; // vacuously equal above the top bit
    for (var i = 254; i >= 0; i--) {
        if (((Km1 >> i) & 1) == 1) {
            // r-1 has a 1 here: bits[i] may be 0 (value strictly less from here) or
            // 1 (still equal). eq carries only if bits[i] == 1.
            eq[i] <== eq[i + 1] * bits[i];
        } else {
            // r-1 has a 0 here: if still equal, bits[i] MUST be 0 (else value > r-1).
            eq[i + 1] * bits[i] === 0;
            eq[i] <== eq[i + 1] * (1 - bits[i]);
        }
    }
}

// Canonical 255-bit little-endian decomposition of a field element (out[0]=LSB).
// Unlike Num2Bits(255) (which would admit the non-canonical `in + r` alias),
// this binds the bits to be < r via AliasCheckBLS - sound over the full field.
template Num2BitsBLS() {
    signal input in;
    signal output bits[255];
    var lc = 0;
    var e2 = 1;
    for (var i = 0; i < 255; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
        lc += bits[i] * e2;
        e2 = e2 + e2;
    }
    lc === in;
    component ac = AliasCheckBLS();
    for (var i = 0; i < 255; i++) ac.bits[i] <== bits[i];
}

// out = 1 iff A < B, where A,B are given as n-bit little-endian arrays (index n-1
// is the MSB). Pure bit comparison - sound when the bit arrays are canonical.
template CompareBitsLT(n) {
    signal input a[n];
    signal input b[n];
    signal output out;
    signal lt[n + 1];
    signal gt[n + 1];
    signal aLess[n];
    signal aGt[n];
    signal nd[n];
    lt[n] <== 0;
    gt[n] <== 0;
    for (var i = n - 1; i >= 0; i--) {
        aLess[i] <== (1 - a[i]) * b[i]; // a_i=0, b_i=1
        aGt[i] <== a[i] * (1 - b[i]);   // a_i=1, b_i=0
        nd[i] <== (1 - lt[i + 1]) * (1 - gt[i + 1]); // not yet decided above i
        lt[i] <== lt[i + 1] + nd[i] * aLess[i];
        gt[i] <== gt[i + 1] + nd[i] * aGt[i];
    }
    out <== lt[0];
}

// out = 1 iff a < b for FULL-FIELD a,b ∈ [0, r). Sound: both operands are bound
// to their canonical 255-bit form, then compared bit-lexicographically.
template LessThanField() {
    signal input a;
    signal input b;
    signal output out;
    component da = Num2BitsBLS();
    da.in <== a;
    component db = Num2BitsBLS();
    db.in <== b;
    component cmp = CompareBitsLT(255);
    for (var i = 0; i < 255; i++) {
        cmp.a[i] <== da.bits[i];
        cmp.b[i] <== db.bits[i];
    }
    out <== cmp.out;
}
