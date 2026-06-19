/**
 * Local sanity verification (optional).
 *
 * This is NOT the production verification path - on-chain, the Soroban contract
 * verifies the Groth16 proof via BLS12-381 host functions against the embedded VK
 * (CLAUDE.md invariant #9). This helper exists purely so a prover can locally
 * confirm "the proof I just produced actually verifies against the exported VK"
 * before paying network fees / submitting.
 *
 * Real SnarkJS API shape:
 *   const ok = await groth16.verify(vKey, publicSignals, proof);
 *
 * `vKey` is the exported `vk_<circuit>.json` (a JSON object, already parsed).
 * It must be the BLS12-381 verifying key matching the proving key used in prove().
 *
 * SECURITY: `publicSignals` and `proof` contain NO secrets (only commitments,
 * nullifiers, roots, ciphertexts), so this is safe. The verifying key is public.
 */

import { readFile } from "node:fs/promises";

import { groth16 } from "snarkjs";

import type { ProofBundle } from "./types.js";

/** A parsed SnarkJS Groth16 verifying key (exported `vk_<circuit>.json`). */
export type VerifyingKey = Record<string, unknown>;

/**
 * Verify a {@link ProofBundle} against an in-memory verifying key.
 * @returns true iff the proof is valid for the given public signals.
 */
export async function verifyLocal(
  vKey: VerifyingKey,
  bundle: ProofBundle,
): Promise<boolean> {
  return groth16.verify(vKey, bundle.publicSignals, bundle.proof);
}

/**
 * Load an exported verifying key JSON from disk and verify a bundle against it.
 *
 * TODO(setup): `vkeyPath` defaults come from `defaultArtifacts().vkeyPath`
 * (`setup/build/<circuit>/vk_<circuit>.json`). Ensure the ceremony exported it.
 */
export async function verifyLocalFromFile(
  vkeyPath: string,
  bundle: ProofBundle,
): Promise<boolean> {
  const vKey = JSON.parse(await readFile(vkeyPath, "utf8")) as VerifyingKey;
  return verifyLocal(vKey, bundle);
}
