/**
 * @finnes/sdk - public surface.
 *
 * Client SDK for the Finnes confidential RWA settlement protocol: shielded-note
 * management, Poseidon-BLS commitments/nullifiers, off-chain Merkle helpers,
 * note encryption, wallet scanning, and ordered public-input assembly that
 * mirrors docs/PUBLIC_IO.md.
 *
 * STATUS: Poseidon-BLS (FIN-002), note + Merkle gadgets (FIN-003), note
 * encryption + scanning (FIN-004), and the SAC-address encoding + auditor
 * disclosure path (FIN-014) are implemented and circuit↔SDK parity-tested.
 * `sacAddressToField`/`deriveAssetId` now encode a field-element literal or a
 * Stellar StrKey (see note.ts for the documented production gap).
 *
 * SECURITY (invariant #8): secrets (owner_sk, rho, r_note, plaintext values,
 * auditor_sk) live only in the client trust zone - never logged or persisted.
 */

export * from './types.js';

export {
  BLS12_381_SCALAR_FIELD_MODULUS,
  FR_MODULUS,
  POSEIDON_BLS_PARAMS,
  POSEIDON_BLS_TEST_VECTOR,
  poseidonBLS,
  toField,
} from './poseidon.js';

export {
  MAX_NOTE_VALUE,
  commitNote,
  createNote,
  deriveAssetId,
  deriveNullifier,
  deriveOwnerPk,
  sacAddressToField,
} from './note.js';

export {
  EMPTY_LEAF,
  IncrementalMerkleTree,
  TREE_DEPTH,
  applyFrontierTransition,
  assetsLeafHash,
  emptyTreeZeros,
  hashNode,
  imtLeafHash,
  verifyInclusionPath,
} from './merkle.js';

export type {
  AuditorPlaintext,
  EncryptionRandomness,
  RecipientPlaintext,
} from './encrypt.js';
export {
  K_A,
  K_R,
  auditorPkFromKey,
  decryptAuditor,
  decryptRecipient,
  encryptToAuditor,
  encryptToRecipient,
} from './encrypt.js';

export type { DiscoveredNote, OnChainCiphertext, ViewingContext } from './scan.js';
export { scanForOwnedNotes, tryDecryptNote } from './scan.js';

export type {
  AuditorObservedNote,
  AuditorObservedTx,
  DisclosedNote,
  DisclosedTransaction,
  DisclosureResolvers,
} from './disclose.js';
export { discloseNote, discloseTransaction, formatRawAmount } from './disclose.js';

export type {
  CircomWitness,
  DvpWitnessDerived,
  DvpWitnessInput,
  DvpWitnessResult,
  ImtLowLeaf,
  ShieldWitnessDerived,
  ShieldWitnessInput,
  ShieldWitnessResult,
  TransferWitnessDerived,
  TransferWitnessInput,
  TransferWitnessResult,
  UnshieldWitnessDerived,
  UnshieldWitnessInput,
  UnshieldWitnessResult,
} from './witness.js';
export {
  buildDvpWitness,
  buildShieldWitness,
  buildTransferWitness,
  buildUnshieldWitness,
} from './witness.js';

export type { PublicInputVector } from './publicInputs.js';
export {
  buildDvpPublicInputs,
  buildShieldPublicInputs,
  buildTransferPublicInputs,
  buildUnshieldPublicInputs,
} from './publicInputs.js';
