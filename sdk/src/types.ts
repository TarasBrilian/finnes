/**
 * Core domain types for the Finnes shielded-note (UTXO) model.
 *
 * Field encoding convention (see CLAUDE.md → Conventions, "Field encoding"):
 *   - All field-native quantities are represented off-chain as `bigint`
 *     (decimal-string-able for readability; hex/bytes only at the contract
 *     boundary). Every such value is an element of the BLS12-381 scalar field
 *     `r` — callers must keep values reduced mod `r`.
 *   - All token amounts are RAW SAC units as `bigint`. They are NEVER rescaled
 *     by decimals anywhere in the ZK layer (CLAUDE.md invariant #16). Decimals
 *     live only in the assets registry and the SDK display layer.
 *
 * SECURITY (CLAUDE.md invariant #8): the secret-bearing fields below
 * (`owner_sk`, `rho`, `r_note`, plaintext `value`, `auditor_sk`) must NEVER be
 * logged, persisted to shared storage, or sent to any backend service. They
 * exist only inside the client/institution trust zone.
 */

/** An element of the BLS12-381 scalar field `r`, kept reduced mod `r`. */
export type Fr = bigint;

/** Raw Stellar Asset Contract amount. Never rescaled by decimals in-circuit. */
export type RawAmount = bigint;

/**
 * Asset identity, self-binding: `asset_id = Poseidon(sac_address)`.
 * Computed in-circuit and in the SDK — never on-chain (invariant #11).
 */
export type AssetId = Fr;

/** Poseidon note commitment placed on-chain as a Merkle leaf. */
export type Commitment = Fr;

/** Poseidon nullifier published when spending a note (prevents double-spend). */
export type Nullifier = Fr;

/** A Merkle tree root (commitment tree, KYC, sanctions, assets, frozen). */
export type MerkleRoot = Fr;

/** A spending public key: `owner_pk = Poseidon(owner_sk)`. */
export type OwnerPk = Fr;

/**
 * A spending secret key. SECRET — see invariant #8. Never log/persist/transmit.
 * Branded so it cannot be accidentally passed where a public value is expected.
 */
export type OwnerSk = Fr & { readonly __brand: 'OwnerSk' };

/**
 * Note plaintext = (asset_id, value, owner_pk, rho, r_note).
 *
 * `value`, `rho`, and `r_note` are SECRET (invariant #8). `owner_pk` is derived
 * from the secret `owner_sk` but is itself not secret. Only the derived
 * `commitment` ever appears on-chain.
 */
export interface Note {
  /** `asset_id = Poseidon(sac_address)`. */
  readonly assetId: AssetId;
  /** Raw SAC units. SECRET. 64-bit range-checked in-circuit (invariant #2). */
  readonly value: RawAmount;
  /** Owner spending public key. */
  readonly ownerPk: OwnerPk;
  /** Per-note serial / nonce; SECRET. Feeds the nullifier `Poseidon(rho, owner_sk)`. */
  readonly rho: Fr;
  /** Commitment randomness (blinding); SECRET. */
  readonly rNote: Fr;
}

/**
 * An on-chain ciphertext blob, carried as field-packed PUBLIC INPUTS and bound
 * by the Groth16 proof (invariant #5). The contract stores it verbatim and
 * never hashes it.
 *
 * NOTE: The encryption scheme is a SCAFFOLD TODO (docs/PUBLIC_IO.md §"Ciphertext
 * binding"). The field packing (`fields`) and its length (`K_a` / `K_r`) are not
 * yet fixed; `raw` is an optional transport representation.
 */
export interface Ciphertext {
  /** Field-packed representation used as circuit public inputs (length K_a/K_r, TODO). */
  readonly fields: readonly Fr[];
  /** Optional raw byte transport representation (off-chain only). */
  readonly raw?: Uint8Array;
}

/** A note paired with the ciphertexts produced for it (auditor mandatory). */
export interface NoteCiphertexts {
  /** Mandatory regulator/auditor ciphertext (invariant #5 — never optional). */
  readonly cAuditor: Ciphertext;
  /** Recipient ciphertext (so the recipient can discover the note via scan). */
  readonly cRecipient?: Ciphertext;
}

/**
 * A leaf of the authorized-assets registry (invariant #17). Committed as
 * `assets_root`. `per_tx_limit_raw` is a WITNESS, never a per-asset public input
 * (exposing it would fingerprint the otherwise-hidden asset).
 */
export interface AssetRegistryLeaf {
  /** `asset_id = Poseidon(sac_address)`. */
  readonly assetId: AssetId;
  /** Stellar Asset Contract address (the self-binding preimage of `asset_id`). */
  readonly sacAddress: string;
  /** Display decimals — SDK/registry only; NEVER enters the ZK layer. */
  readonly decimals: number;
  /** Per-asset transfer limit in raw SAC units (witness; enforced via membership). */
  readonly perTxLimitRaw: RawAmount;
}

/** A Merkle inclusion path: sibling hashes + the leaf's path index bits. */
export interface MerklePath {
  /** Sibling at each level, from leaf to root (length = tree depth `D`). */
  readonly siblings: readonly Fr[];
  /** Path bits, from leaf to root: 0 = current node is left child, 1 = right. */
  readonly pathBits: readonly (0 | 1)[];
  /** Leaf index this path proves (0-based). */
  readonly leafIndex: number;
}

/**
 * The commitment-tree frontier (filled subtrees), `D` field elements
 * (invariant #12). `old_frontier` is a public input; `new_frontier`/`new_root`
 * are public outputs the contract stores verbatim.
 */
export type Frontier = readonly Fr[];

/** The compliance/state roots matched against contract state on every transfer. */
export interface StateRoots {
  /** Recent commitment-tree root the proof is anchored to (windowed). */
  readonly anchorRoot: MerkleRoot;
  /** KYC-approved set, membership (windowed). */
  readonly kycRoot: MerkleRoot;
  /** Sanctioned set, non-membership (windowed). */
  readonly sanctionRoot: MerkleRoot;
  /** Authorized-assets registry root (windowed). */
  readonly assetsRoot: MerkleRoot;
  /** Issuer-managed frozen-commitment set, non-membership (STRICT — invariant #6). */
  readonly frozenRoot: MerkleRoot;
}

/**
 * Auditor (regulator) view public key. Representation is a SCAFFOLD TODO until
 * the encryption scheme is fixed (docs/PUBLIC_IO.md: "auditor_pk_* TODO").
 */
export interface AuditorPublicKey {
  /** Single field-element placeholder; may expand to `_x`/`_y` once scheme fixed. */
  readonly pk: Fr;
}

/** The four top-level circuits, each with its own VK and public-IO layout. */
export type CircuitId = 'shield' | 'transfer' | 'unshield' | 'dvp';
