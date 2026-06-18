/**
 * @finnes/sdk — public surface.
 *
 * Client SDK for the Finnes confidential RWA settlement protocol: shielded-note
 * management, Poseidon-BLS commitments/nullifiers, off-chain Merkle helpers,
 * note encryption, wallet scanning, and ordered public-input assembly that
 * mirrors docs/PUBLIC_IO.md.
 *
 * SCAFFOLD: cryptographic bodies are `// TODO:` stubs that THROW. Nothing here
 * performs real crypto yet. See each module header for the TODOs.
 *
 * SECURITY (invariant #8): secrets (owner_sk, rho, r_note, plaintext values,
 * auditor_sk) live only in the client trust zone — never logged or persisted.
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
  emptyTreeZeros,
  hashNode,
  verifyInclusionPath,
} from './merkle.js';

export type { EncryptionRandomness } from './encrypt.js';
export { encryptToAuditor, encryptToRecipient } from './encrypt.js';

export type { DiscoveredNote, OnChainCiphertext, ViewingContext } from './scan.js';
export { scanForOwnedNotes, tryDecryptNote } from './scan.js';

export type { PublicInputVector } from './publicInputs.js';
export {
  buildDvpPublicInputs,
  buildShieldPublicInputs,
  buildTransferPublicInputs,
  buildUnshieldPublicInputs,
} from './publicInputs.js';
