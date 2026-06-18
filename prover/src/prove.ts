/**
 * Groth16 proving wrapper around SnarkJS for Finnes.
 *
 * Real SnarkJS API shape:
 *   const { proof, publicSignals } = await groth16.fullProve(input, wasmPath, zkeyPath);
 *
 * Curve is BLS12-381 (CLAUDE.md invariant #1) — the `.wasm` and `.zkey` MUST be
 * the bls12381 artifacts from `circuits:build` + `setup:ceremony`. SnarkJS infers
 * the curve from the zkey; passing a BN254 zkey here would be a serious bug.
 *
 * TRUST ZONE (ARCHITECTURE.md → ZK / Backend; CLAUDE.md invariant #8):
 *   This runs INSIDE the client/institution zone (browser WASM or a self-hosted
 *   node). It is SINGLE-TENANT — never a shared, multi-tenant backend service,
 *   because that would leak the witness across tenants. The witness embeds
 *   owner_sk, rho, r_note, plaintext values, and encryption randomness; none of
 *   it may be logged, persisted, or sent anywhere except into the local prover.
 */

import { groth16 } from "snarkjs";

import type {
  CircuitArtifacts,
  CircuitName,
  ProofBundle,
  Witness,
} from "./types.js";

/**
 * Default artifact layout: `setup/build/<circuit>/<circuit>.{wasm,zkey}` and the
 * exported verifying key at `setup/build/<circuit>/vk_<circuit>.json`. Paths are
 * resolved relative to `baseDir` (defaults to `setup/build`).
 *
 * Configurable so a self-hosted institutional prover can point at its own
 * ceremony output without code changes.
 */
export function defaultArtifacts(
  circuit: CircuitName,
  baseDir = "setup/build",
): CircuitArtifacts {
  const dir = `${baseDir}/${circuit}`;
  return {
    wasmPath: `${dir}/${circuit}.wasm`,
    zkeyPath: `${dir}/${circuit}.zkey`,
    vkeyPath: `${dir}/vk_${circuit}.json`,
  };
}

/**
 * Generate a Groth16 proof for an already-assembled witness.
 *
 * SECURITY: never log `witness`. We deliberately do NOT wrap this in a try/catch
 * that stringifies the input — a thrown SnarkJS error must not be augmented with
 * witness contents. If you add logging, log only `circuit` and artifact PATHS,
 * never the `witness` object or any field of it.
 *
 * @returns a {@link ProofBundle} — proof + ordered public signals, safe to submit.
 *          The public-signal ORDER is determined by the circuit and MUST match
 *          docs/PUBLIC_IO.md (see witness.ts `PUBLIC_IO_ORDER`).
 */
export async function prove(
  witness: Witness,
  artifacts: CircuitArtifacts,
): Promise<ProofBundle> {
  // groth16.fullProve(input, wasmPath, zkeyPath) → { proof, publicSignals }
  const { proof, publicSignals } = await groth16.fullProve(
    // SnarkJS accepts the flat signal-name → value map directly.
    witness as Parameters<typeof groth16.fullProve>[0],
    artifacts.wasmPath,
    artifacts.zkeyPath,
  );

  return { proof, publicSignals };
}

/**
 * Convenience: resolve default artifact paths for `circuit` and prove.
 *
 * TODO(setup): the `.wasm` / `.zkey` must exist (produced by `npm run
 * circuits:build` + `npm run setup:ceremony`). This wrapper does not validate
 * their presence or that they are the BLS12-381 artifacts — surface a clear error
 * upstream if proving fails to load them.
 */
export async function proveCircuit(
  circuit: CircuitName,
  witness: Witness,
  baseDir?: string,
): Promise<ProofBundle> {
  return prove(witness, defaultArtifacts(circuit, baseDir));
}
