/**
 * @finnes/prover - off-chain Groth16 prover (SnarkJS, BLS12-381).
 *
 * Runs INSIDE the client/institution trust zone (browser WASM or a self-hosted
 * node). SINGLE-TENANT - never a shared multi-tenant backend service. The witness
 * (owner_sk, rho, r_note, plaintext values, encryption randomness) must never be
 * logged, persisted, or transmitted (CLAUDE.md invariant #8).
 *
 * SCAFFOLD: proving is not yet wired end-to-end. Witness signal names and the
 * ciphertext/frontier packing depend on circuit internals not yet finalised - see
 * the `TODO(circuit)` / `TODO(setup)` / `TODO(sdk)` markers across the module.
 */

export type {
  CircuitArtifacts,
  CircuitName,
  FieldElement,
  MerklePath,
  Note,
  ProofBundle,
  Witness,
} from "./types.js";

export {
  PUBLIC_IO_ORDER,
  assembleShieldWitness,
  assembleTransferWitness,
  assembleUnshieldWitness,
  assembleDvpWitness,
} from "./witness.js";
export type {
  CommonPublicInputs,
  ShieldWitnessInput,
  TransferWitnessInput,
  UnshieldWitnessInput,
  DvpWitnessInput,
  DvpLeg,
} from "./witness.js";

export { prove, proveCircuit, defaultArtifacts } from "./prove.js";

export { verifyLocal, verifyLocalFromFile } from "./verifyLocal.js";
export type { VerifyingKey } from "./verifyLocal.js";
