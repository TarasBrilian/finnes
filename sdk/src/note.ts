/**
 * Note creation and derivation primitives (docs/PUBLIC_IO.md §"Primitives").
 *
 *   asset_id      = Poseidon(sac_address)
 *   owner_pk      = Poseidon(owner_sk)
 *   commitment cm = Poseidon(asset_id, value, owner_pk, rho, r_note)
 *   nullifier  nf = Poseidon(rho, owner_sk)
 *
 * All hashing is Poseidon over the BLS12-381 scalar field (see poseidon.ts).
 * Performed only in the SDK and the circuit - never on-chain (invariant #11).
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
 * Encode an SAC address into the single field element fed to
 * `asset_id = Poseidon(sac_address)`. The circuit (`circuits/lib/note.circom`
 * `AssetId`) only ever sees this `Fr`; the string → `Fr` map lives off-circuit
 * here and in the contract's admin asset registry (`register_asset`), which must
 * stay in lockstep so an `asset_id` resolves to the same SAC everywhere.
 *
 * DEMO form (the only one accepted): a field-element literal — decimal or `0x…`
 * hex — exactly as `scripts/lib/*-scenario.ts` use it (`sac_address = 777n`).
 * Parsed verbatim and reduced mod `r`.
 *
 * PRODUCTION GAP — real Stellar StrKey (`C…`/`G…`) binding is deliberately NOT
 * implemented here (it THROWS), mirroring the deferred `recipient` encoding in
 * docs/PUBLIC_IO.md: a 32-byte address payload spans up to 2^256 > r, so a naive
 * big-endian-mod-`r` map is non-injective at the top (two addresses can alias to
 * one `asset_id`) AND skips StrKey version/CRC validation (a typo would silently
 * mint a wrong `asset_id` that desyncs from the contract registry). Production
 * binds the full address via two fields (hi/lo 16 bytes) or the SHA-256 host
 * function (invariant #11) — a fresh-ceremony change. Until then we fail loudly
 * rather than encode a possibly-wrong identity.
 */
export function sacAddressToField(sacAddress: string): Fr {
  const s = sacAddress.trim();
  if (s.length === 0) throw new Error('sacAddressToField: empty address');

  // Field-element literal (demo representation): decimal or 0x-hex.
  if (/^0x[0-9a-fA-F]+$/.test(s)) return toField(BigInt(s));
  if (/^[0-9]+$/.test(s)) return toField(BigInt(s));

  // Anything else (incl. a real C…/G… StrKey) is the production gap above.
  throw new Error(
    'sacAddressToField: only field-element literals (decimal/0x-hex) are supported ' +
      'in the demo. Real Stellar StrKey (C…/G…) binding is a production gap (split ' +
      'hi/lo or SHA-256; see docs/PUBLIC_IO.md) — not a naive mod-r reduction.',
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
