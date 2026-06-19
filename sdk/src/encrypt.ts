/**
 * Note encryption for the auditor (mandatory) and the recipient (optional).
 *
 * Implements FIN-001 scheme A (LOCKED, docs/PUBLIC_IO.md "Ciphertext binding"):
 * an additive Poseidon keystream over the BLS12-381 scalar field. This mirrors
 * `circuits/lib/enc_check.circom` EXACTLY - same shared-secret derivation, same
 * per-slot domain separation, same packing - so an SDK-produced ciphertext
 * satisfies the in-circuit binding (parity gate: scripts/test-enc-parity.ts).
 *
 *   auditor_pk = Poseidon(k_view)
 *   shared     = Poseidon(k_view, rho_enc)        (rho_enc is the published nonce)
 *   ks_i       = Poseidon(shared, i)  for i = 1..4
 *   c[0]       = rho_enc
 *   c[i]       = pt[i-1] + ks_i  (mod r)
 *
 * Auditor ciphertext binds [value, asset_id, owner_pk, rho] (invariant #5,
 * mandatory). Recipient ciphertext binds [value, asset_id, rho, r_note] and is
 * keyed by a sender↔recipient pairwise secret (demo: OOB); it is non-mandatory
 * and exists for note discovery (sdk/src/scan.ts).
 *
 * SECURITY (invariant #8): plaintext note fields (`value`, `rho`, `r_note`),
 * `k_view`, and the pairwise key are secrets. NEVER log/persist/transmit them.
 */

import type { AuditorPublicKey, Ciphertext, Fr, Note } from './types.js';
import { poseidonBLS, toField } from './poseidon.js';

/** Packed ciphertext element counts (LOCKED, FIN-001). */
export const K_A = 5 as const;
export const K_R = 5 as const;

/** Randomness used to encrypt a note. SECRET - see invariant #8. */
export interface EncryptionRandomness {
  /** Published per-note nonce `rho_enc` in `[0, r)`; occupies ciphertext slot 0. */
  readonly rhoEnc: Fr;
}

/**
 * The auditor public key bound in-circuit: `auditor_pk = Poseidon(k_view)`.
 * `k_view` is the sender↔auditor shared key (SECRET); the returned value is the
 * public scalar stored in contract state and checked exactly on every transfer.
 */
export function auditorPkFromKey(kView: Fr): AuditorPublicKey {
  return { pk: poseidonBLS([toField(kView)]) };
}

/** Derive the per-note shared secret and the 4 keystream words (slots 1..4). */
function keystream(key: Fr, rhoEnc: Fr): [Fr, Fr, Fr, Fr] {
  const shared = poseidonBLS([toField(key), toField(rhoEnc)]);
  return [
    poseidonBLS([shared, 1n]),
    poseidonBLS([shared, 2n]),
    poseidonBLS([shared, 3n]),
    poseidonBLS([shared, 4n]),
  ];
}

/**
 * Encrypt a note to the auditor view key. MANDATORY for every output note
 * (invariant #5). `kView` is the sender↔auditor shared key; the resulting
 * `auditor_pk = Poseidon(kView)` must equal contract state.
 *
 * Layout: [rho_enc, value+ks1, asset_id+ks2, owner_pk+ks3, rho+ks4].
 */
export function encryptToAuditor(
  note: Note,
  kView: Fr,
  randomness: EncryptionRandomness,
): Ciphertext {
  const rhoEnc = toField(randomness.rhoEnc);
  const ks = keystream(kView, rhoEnc);
  return {
    fields: [
      rhoEnc,
      toField(toField(note.value) + ks[0]),
      toField(note.assetId + ks[1]),
      toField(note.ownerPk + ks[2]),
      toField(note.rho + ks[3]),
    ],
  };
}

/** The plaintext the auditor recovers from `c_auditor`. */
export interface AuditorPlaintext {
  readonly value: Fr;
  readonly assetId: Fr;
  readonly ownerPk: Fr;
  readonly rho: Fr;
}

/**
 * Auditor (regulator) decryption: recover the bound plaintext from `c_auditor`
 * using the shared key `kView`. Runs in the auditor trust zone (invariant #8).
 */
export function decryptAuditor(c: Ciphertext, kView: Fr): AuditorPlaintext {
  if (c.fields.length !== K_A) {
    throw new Error(`c_auditor must have ${K_A} fields, got ${c.fields.length}`);
  }
  const rhoEnc = c.fields[0]!;
  const ks = keystream(kView, rhoEnc);
  return {
    value: toField(c.fields[1]! - ks[0]),
    assetId: toField(c.fields[2]! - ks[1]),
    ownerPk: toField(c.fields[3]! - ks[2]),
    rho: toField(c.fields[4]! - ks[3]),
  };
}

/**
 * Encrypt a note to the recipient so they can discover it during scanning.
 * Optional (the auditor ciphertext is the mandatory one). `kPair` is the
 * sender↔recipient pairwise secret (demo: OOB-shared).
 *
 * Layout: [rho_enc, value+ks1, asset_id+ks2, rho+ks3, r_note+ks4]. `owner_pk` is
 * NOT packed - the recipient re-derives it from its own `owner_sk`.
 */
export function encryptToRecipient(
  note: Note,
  kPair: Fr,
  randomness: EncryptionRandomness,
): Ciphertext {
  const rhoEnc = toField(randomness.rhoEnc);
  const ks = keystream(kPair, rhoEnc);
  return {
    fields: [
      rhoEnc,
      toField(toField(note.value) + ks[0]),
      toField(note.assetId + ks[1]),
      toField(note.rho + ks[2]),
      toField(note.rNote + ks[3]),
    ],
  };
}

/** The plaintext the recipient recovers from `c_recipient` (sans `owner_pk`). */
export interface RecipientPlaintext {
  readonly value: Fr;
  readonly assetId: Fr;
  readonly rho: Fr;
  readonly rNote: Fr;
}

/**
 * Recipient decryption: recover [value, asset_id, rho, r_note] from
 * `c_recipient` using the pairwise key `kPair`. The caller re-derives `owner_pk`
 * from its own `owner_sk` to reconstruct the full note (sdk/src/scan.ts).
 */
export function decryptRecipient(c: Ciphertext, kPair: Fr): RecipientPlaintext {
  if (c.fields.length !== K_R) {
    throw new Error(`c_recipient must have ${K_R} fields, got ${c.fields.length}`);
  }
  const rhoEnc = c.fields[0]!;
  const ks = keystream(kPair, rhoEnc);
  return {
    value: toField(c.fields[1]! - ks[0]),
    assetId: toField(c.fields[2]! - ks[1]),
    rho: toField(c.fields[3]! - ks[2]),
    rNote: toField(c.fields[4]! - ks[3]),
  };
}
