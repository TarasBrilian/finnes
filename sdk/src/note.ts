/**
 * Note creation and derivation primitives (docs/PUBLIC_IO.md §"Primitives").
 *
 *   asset_id      = Poseidon(sac_address)
 *   owner_pk      = Poseidon(owner_sk)
 *   commitment cm = Poseidon(asset_id, value, owner_pk, rho, r_note)
 *   nullifier  nf = Poseidon(rho, owner_sk)
 *
 * All hashing is Poseidon over the BLS12-381 scalar field (see poseidon.ts).
 * Performed only in the SDK and the circuit — never on-chain (invariant #11).
 *
 * SECURITY (invariant #8): `owner_sk`, `rho`, `r_note`, and plaintext `value`
 * are secrets. NEVER log/persist/transmit them. The helpers here never emit
 * them; do not add logging that captures their arguments.
 */

import type {
  AssetId,
  Commitment,
  Fr,
  Note,
  Nullifier,
  OwnerPk,
  OwnerSk,
  RawAmount,
} from './types.js';
import { poseidonBLS, toField } from './poseidon.js';

/** Max raw value permitted by the 64-bit range check (invariant #2). */
export const MAX_NOTE_VALUE: bigint = (1n << 64n) - 1n;

/**
 * Encode a Stellar Asset Contract address into a field element for hashing.
 *
 * TODO(crypto): define the canonical, circuit-matching encoding of an SAC
 * address (a Stellar contract `C...` / StrKey) into one or more `Fr` elements
 * and feed it to Poseidon exactly as `circuits/lib/note.circom` does. Throws
 * until fixed — must not guess an encoding that disagrees with the circuit.
 */
export function sacAddressToField(_sacAddress: string): Fr {
  throw new Error(
    'TODO: sacAddressToField encoding undefined. Define the SAC-address → Fr ' +
      'encoding to match circuits/lib/note.circom before deriving asset_id.',
  );
}

/** `asset_id = Poseidon(sac_address)`. Self-binding asset identity (invariant #17). */
export function deriveAssetId(sacAddress: string): AssetId {
  return poseidonBLS([sacAddressToField(sacAddress)]);
}

/** `owner_pk = Poseidon(owner_sk)`. `owner_sk` is SECRET (invariant #8). */
export function deriveOwnerPk(ownerSk: OwnerSk): OwnerPk {
  return poseidonBLS([toField(ownerSk)]);
}

/**
 * `commitment = Poseidon(asset_id, value, owner_pk, rho, r_note)`.
 * Input order is normative and must match `circuits/lib/note.circom`.
 */
export function commitNote(note: Note): Commitment {
  if (note.value < 0n || note.value > MAX_NOTE_VALUE) {
    // Mirror the in-circuit 64-bit range check (invariant #2) at the SDK edge.
    throw new Error('note value out of 64-bit range (invariant #2)');
  }
  return poseidonBLS([
    note.assetId,
    toField(note.value),
    note.ownerPk,
    note.rho,
    note.rNote,
  ]);
}

/**
 * `nullifier = Poseidon(rho, owner_sk)`. Input order matches the circuit.
 * `owner_sk` is SECRET (invariant #8). Mandatory + single-use (invariant #4).
 */
export function deriveNullifier(rho: Fr, ownerSk: OwnerSk): Nullifier {
  return poseidonBLS([rho, toField(ownerSk)]);
}

/**
 * Construct a fresh note. Caller supplies the secrets (`value`, `rho`,
 * `r_note`) and the owner public key. `rho` / `r_note` should come from a CSPRNG.
 *
 * TODO(crypto): provide a `sampleNoteRandomness()` that draws `rho`/`r_note`
 * uniformly from `[0, r)` using a CSPRNG once a field-sampling util is added.
 */
export function createNote(params: {
  assetId: AssetId;
  value: RawAmount;
  ownerPk: OwnerPk;
  rho: Fr;
  rNote: Fr;
}): Note {
  if (params.value < 0n || params.value > MAX_NOTE_VALUE) {
    throw new Error('note value out of 64-bit range (invariant #2)');
  }
  return {
    assetId: params.assetId,
    value: params.value,
    ownerPk: params.ownerPk,
    rho: params.rho,
    rNote: params.rNote,
  };
}
