/**
 * Core prover types for Finnes.
 *
 * SECURITY (CLAUDE.md invariant #8 — "Never log or persist secrets"):
 *   `Witness` carries `owner_sk`, `rho`, `r_note`, plaintext note `value`, and
 *   encryption randomness. NONE of these may ever be logged, serialised to disk,
 *   or sent over the network. The prover runs INSIDE the client/institution trust
 *   zone (single-tenant — never a shared multi-tenant service). See `prove.ts`.
 */

import type { Groth16Proof, PublicSignals } from "snarkjs";

/**
 * Field element off-chain encoding. Per CLAUDE.md "Conventions": decimal-string
 * representation off-chain for readability; hex/bytes only at the contract
 * boundary. SnarkJS consumes decimal strings (or bigint-coercible values).
 */
export type FieldElement = string;

/** The four top-level circuits, each with its own VK / proving key. */
export type CircuitName = "shield" | "transfer" | "unshield" | "dvp";

/**
 * Plaintext shielded note.
 *
 * Primitives (docs/PUBLIC_IO.md → "Primitives"):
 *   asset_id      = Poseidon(sac_address)
 *   owner_pk      = Poseidon(owner_sk)
 *   commitment cm = Poseidon(asset_id, value, owner_pk, rho, r_note)
 *   nullifier  nf = Poseidon(rho, owner_sk)
 *
 * SECRET FIELDS: `value`, `rho`, `r_note` (and the derived/raw `owner_sk` held
 * elsewhere). Treat the whole object as secret — never log it.
 */
export interface Note {
  /** Poseidon(sac_address); raw SAC asset identity (self-binding). */
  asset_id: FieldElement;
  /** Raw SAC units. 64-bit range-checked in-circuit (invariant #2). NEVER log. */
  value: FieldElement;
  /** Poseidon(owner_sk). */
  owner_pk: FieldElement;
  /** Per-note nullifier seed. SECRET — NEVER log. */
  rho: FieldElement;
  /** Commitment blinding randomness. SECRET — NEVER log. */
  r_note: FieldElement;
}

/**
 * A Merkle path used for inclusion / non-inclusion proofs.
 * `siblings` length must equal the tree depth `D` (docs/PUBLIC_IO.md → Tree: D = 32, TODO confirm).
 * `pathIndices` are the left/right (0/1) bits at each level.
 */
export interface MerklePath {
  siblings: FieldElement[];
  pathIndices: number[];
}

/**
 * The full private + public witness handed to SnarkJS `fullProve`.
 *
 * This is the SnarkJS circuit-input object: a flat map of signal-name -> value
 * (or arrays). The concrete signal names depend on circuit internals not yet
 * finalised (see witness.ts TODOs). We keep it as an index signature plus the
 * stable, documented public-IO fields.
 *
 * SECURITY: this object embeds every secret. It must never leave the client zone.
 */
export interface Witness {
  [signal: string]: FieldElement | FieldElement[] | number | number[];
}

/**
 * The output of a successful proof: exactly what the relayer/frontend submits to
 * the Soroban contract. `publicSignals` ordering is normative — it MUST match
 * docs/PUBLIC_IO.md for the circuit (see witness.ts).
 *
 * Contains NO secrets: only commitments, nullifiers, roots, ciphertexts, and the
 * proof. Safe to transmit.
 */
export interface ProofBundle {
  proof: Groth16Proof;
  publicSignals: PublicSignals;
}

/**
 * Per-circuit artifact locations. Defaults follow the `setup/build/<circuit>/`
 * convention (see prove.ts). Configurable so a self-hosted prover can point at
 * its own ceremony output.
 */
export interface CircuitArtifacts {
  /** Path to `<circuit>.wasm` (the witness-generator WASM from circom). */
  wasmPath: string;
  /** Path to `<circuit>.zkey` (the proving key from the phase-2 ceremony). */
  zkeyPath: string;
  /** Optional path to an exported `vk_<circuit>.json` for local sanity checks. */
  vkeyPath?: string;
}
