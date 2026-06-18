pragma circom 2.1.6;

// =============================================================================
// bits.circom — vendored field-agnostic bit / comparator gadgets.
// =============================================================================
//
// Standard constructions (cf. circomlib bitify/comparators), VENDORED so the
// project carries NO circomlib dependency. Rationale (invariant #1): circomlib's
// default Poseidon uses BN254 constants and must never be pulled in; vendoring the
// handful of field-agnostic helpers we need keeps the circuit tree self-contained
// and BN254-free. These templates contain NO hardcoded field constants and NO
// Poseidon — they are sound under `--prime bls12381`.
//
// SOUNDNESS NOTE: `LessThan(n)` / `LessEqThan(n)` assume both operands lie in
// `[0, 2^n)` and require `n + 1` bits to decompose alias-free, so `n <= 252` over
// the BLS12-381 scalar field `r` (2^253 < r < 2^255). Comparing FULL-FIELD values
// (e.g. a raw Poseidon output, which can exceed 2^252) needs a dedicated
// r-aware comparator — see merkle.circom non-membership.
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
