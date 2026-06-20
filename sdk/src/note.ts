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

/** RFC 4648 base32 alphabet used by Stellar StrKey (no padding in the 56-char form). */
const STRKEY_BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decode a Stellar StrKey (`G…`/`C…`, 56 base32 chars → 35 bytes). */
function decodeStrKey(s: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s) {
    const idx = STRKEY_BASE32.indexOf(ch);
    if (idx === -1) throw new Error('sacAddressToField: invalid StrKey character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/**
 * Encode an SAC address into the single field element fed to
 * `asset_id = Poseidon(sac_address)`. The circuit (`circuits/lib/note.circom`
 * `AssetId`) only ever sees this `Fr`; the string → `Fr` map lives off-circuit
 * here and in the contract's admin asset registry (`register_asset`), which must
 * stay in lockstep so an `asset_id` resolves to the same SAC everywhere.
 *
 * Two accepted forms:
 *   - a field-element literal (decimal or `0x…` hex) — the demo representation
 *     used by `scripts/lib/*-scenario.ts` (`sac_address = 777n`), parsed verbatim;
 *   - a real Stellar StrKey (`C…` contract / `G…` account, 56 base32 chars) — its
 *     32-byte payload (version byte + payload + CRC; payload = bytes[1..33]) is
 *     read big-endian into a bigint.
 *
 * PRODUCTION GAP (mirrors the `recipient` encoding in docs/PUBLIC_IO.md): a full
 * 32-byte payload spans up to 2^256 > r, so reducing it mod `r` is not injective
 * at the very top of the range. Production splits the address into two fields
 * (hi/lo 16 bytes) or binds it via the SHA-256 host function (the one on-chain
 * hash invariant #11 permits) — a fresh-ceremony change. The demo's contract IDs
 * are assumed to fit `< r`.
 */
export function sacAddressToField(sacAddress: string): Fr {
  const s = sacAddress.trim();
  if (s.length === 0) throw new Error('sacAddressToField: empty address');

  // Field-element literal (demo representation).
  if (/^0x[0-9a-fA-F]+$/.test(s)) return toField(BigInt(s));
  if (/^[0-9]+$/.test(s)) return toField(BigInt(s));

  // Real Stellar StrKey: 56 base32 chars → 35 bytes (1 version + 32 payload + 2 CRC).
  if (/^[A-Z2-7]{56}$/.test(s)) {
    const raw = decodeStrKey(s);
    let acc = 0n;
    for (const b of raw.slice(1, 33)) acc = (acc << 8n) | BigInt(b);
    return toField(acc);
  }

  throw new Error(
    'sacAddressToField: unrecognised SAC address; expected a decimal/0x-hex ' +
      'field element or a Stellar StrKey (C…/G…).',
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
