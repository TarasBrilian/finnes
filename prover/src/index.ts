/**
 * @finnes/prover - off-chain Groth16 prover (SnarkJS, BLS12-381).
 *
 * Runs INSIDE the client/institution trust zone (browser WASM or a self-hosted
 * node). SINGLE-TENANT - never a shared multi-tenant backend service. The witness
 * (owner_sk, rho, r_note, plaintext values, encryption randomness) must never be
 * logged, persisted, or transmitted (CLAUDE.md invariant #8).
 *
 * TRANSFER is wired end-to-end (FIN-006/007/008): build the witness with
 * `buildTransferWitness` (re-exported from `@finnes/sdk`), `prove()` it against
 * the BLS12-381 `.wasm`/`.zkey`, and `verifyLocal()` against `vk_transfer.json`.
 * shield / unshield / dvp remain scaffolds until their circom lands.
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

// Transfer witness builder + ordered public-input assembly: single source of
// truth in @finnes/sdk (docs/PUBLIC_IO.md). Re-exported here so prover consumers
// have one import surface (FIN-008 / FIN-022 - no duplicated PUBLIC_IO order).
export { buildTransferWitness } from "@finnes/sdk";
export type {
  CircomWitness,
  ImtLowLeaf,
  TransferWitnessInput,
  TransferWitnessResult,
} from "@finnes/sdk";
export {
  buildDvpPublicInputs,
  buildShieldPublicInputs,
  buildTransferPublicInputs,
  buildUnshieldPublicInputs,
} from "@finnes/sdk";

export {
  assembleShieldWitness,
  assembleUnshieldWitness,
  assembleDvpWitness,
} from "./witness.js";
export type {
  CommonPublicInputs,
  ShieldWitnessInput,
  UnshieldWitnessInput,
  DvpWitnessInput,
  DvpLeg,
} from "./witness.js";

export { prove, proveCircuit, defaultArtifacts } from "./prove.js";

export { verifyLocal, verifyLocalFromFile } from "./verifyLocal.js";
export type { VerifyingKey } from "./verifyLocal.js";
