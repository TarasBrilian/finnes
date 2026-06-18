// Parity harness: note commitment = Poseidon(asset_id,value,owner_pk,rho,r_note).
pragma circom 2.1.6;
include "../../lib/note.circom";
component main = NoteCommitment();
