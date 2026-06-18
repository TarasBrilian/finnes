pragma circom 2.1.6;

// =============================================================================
// note.circom — note commitment & nullifier derivation (Poseidon-BLS)
// =============================================================================
//
// SCAFFOLD. Template signatures and composition are concrete; the hash bodies
// delegate to PoseidonBLS (itself a TODO stub — see poseidon_bls.circom).
//
// Compile with `--prime bls12381` (compiler flag, not pragma).
//
// Note plaintext (PUBLIC_IO.md):  (asset_id, value, owner_pk, rho, r_note)
//
//   asset_id      = Poseidon(sac_address)
//   owner_pk      = Poseidon(owner_sk)
//   commitment cm = Poseidon(asset_id, value, owner_pk, rho, r_note)
//   nullifier  nf = Poseidon(rho, owner_sk)
//
// Only `cm` is public on-chain. Raw SAC units only — the circuit NEVER rescales
// by decimals (Security invariant #16).
// =============================================================================

include "poseidon_bls.circom";

// -----------------------------------------------------------------------------
// AssetId — asset_id = Poseidon(sac_address)
// Self-binding asset identity; computed in-circuit, never on-chain.
// -----------------------------------------------------------------------------
template AssetId() {
    signal input sac_address;
    signal output asset_id;

    component h = PoseidonBLS(1);
    h.in[0] <== sac_address;
    asset_id <== h.out;
}

// -----------------------------------------------------------------------------
// OwnerPk — owner_pk = Poseidon(owner_sk)
// -----------------------------------------------------------------------------
template OwnerPk() {
    signal input owner_sk;
    signal output owner_pk;

    component h = PoseidonBLS(1);
    h.in[0] <== owner_sk;
    owner_pk <== h.out;
}

// -----------------------------------------------------------------------------
// NoteCommitment — cm = Poseidon(asset_id, value, owner_pk, rho, r_note)
// -----------------------------------------------------------------------------
template NoteCommitment() {
    signal input asset_id;
    signal input value;
    signal input owner_pk;
    signal input rho;
    signal input r_note;
    signal output cm;

    component h = PoseidonBLS(5);
    h.in[0] <== asset_id;
    h.in[1] <== value;
    h.in[2] <== owner_pk;
    h.in[3] <== rho;
    h.in[4] <== r_note;
    cm <== h.out;
}

// -----------------------------------------------------------------------------
// Nullifier — nf = Poseidon(rho, owner_sk)
// Spend authority is bound by owner_sk; reveals nothing about which note spent.
// -----------------------------------------------------------------------------
template Nullifier() {
    signal input rho;
    signal input owner_sk;
    signal output nf;

    component h = PoseidonBLS(2);
    h.in[0] <== rho;
    h.in[1] <== owner_sk;
    nf <== h.out;
}

// -----------------------------------------------------------------------------
// SpentNote — full opening + ownership of an input note.
//
// Given the note plaintext and owner_sk, this:
//   (a) re-derives owner_pk = Poseidon(owner_sk) and CHECKS it equals the note's
//       owner_pk field (ownership / spend authority),
//   (b) recomputes the commitment `cm` (to be proved as a Merkle leaf upstream),
//   (c) derives the nullifier `nf`.
//
// 64-bit range check on `value` is the caller's responsibility (RangeCheck64 in
// the top-level circuit), kept there so the bit decomposition is visible at the
// conservation site (Security invariant #2).
// -----------------------------------------------------------------------------
template SpentNote() {
    // note plaintext
    signal input asset_id;
    signal input value;
    signal input owner_pk;
    signal input rho;
    signal input r_note;
    // spending key
    signal input owner_sk;

    signal output cm;
    signal output nf;

    // (a) ownership: owner_pk must equal Poseidon(owner_sk)
    component opk = OwnerPk();
    opk.owner_sk <== owner_sk;
    // TODO: this equality is the ownership constraint — keep it.
    owner_pk === opk.owner_pk;

    // (b) commitment
    component cmt = NoteCommitment();
    cmt.asset_id <== asset_id;
    cmt.value    <== value;
    cmt.owner_pk <== owner_pk;
    cmt.rho      <== rho;
    cmt.r_note   <== r_note;
    cm <== cmt.cm;

    // (c) nullifier
    component nul = Nullifier();
    nul.rho      <== rho;
    nul.owner_sk <== owner_sk;
    nf <== nul.nf;
}

// -----------------------------------------------------------------------------
// OutputNote — commitment for a freshly-minted output note.
// owner_pk is supplied directly (the recipient's pk; no owner_sk in witness for
// an output). value range-checked by the caller.
// -----------------------------------------------------------------------------
template OutputNote() {
    signal input asset_id;
    signal input value;
    signal input owner_pk;
    signal input rho;
    signal input r_note;
    signal output cm;

    component cmt = NoteCommitment();
    cmt.asset_id <== asset_id;
    cmt.value    <== value;
    cmt.owner_pk <== owner_pk;
    cmt.rho      <== rho;
    cmt.r_note   <== r_note;
    cm <== cmt.cm;
}
