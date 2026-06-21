'use client';

/**
 * In-browser Groth16 proving (FIN-027, option 2, client-side snarkjs).
 *
 * Runs `groth16.fullProve` entirely in the browser, loading the circuit `.wasm`
 * (witness generator) and `.zkey` (proving key) from static URLs (config.ts →
 * ARTIFACT_BASE). The WITNESS NEVER LEAVES THIS TAB (invariant #8): proving is
 * client-side; only the resulting proof + public signals (public data) are
 * returned for submission.
 *
 * The `.zkey` are large (shield 31MB / unshield 64MB / transfer 110MB) and are
 * served as static files the operator places under frontend/public/artifacts/
 * (gitignored, demo-only per invariant #10). The browser fetches them on demand.
 */

import { groth16 } from 'snarkjs';

import { artifactUrls, type CircuitName } from './config.js';
import { frToHex, proofToHost, type HostProof, type SnarkProof } from './host-bytes.js';

export interface BrowserProof {
  /** Host-byte proof (a/c 96B, b 192B hex) ready for the contract. */
  readonly hostProof: HostProof;
  /** Public signals as decimal strings (snarkjs order). */
  readonly publicSignals: string[];
  /** Each public signal as 32-byte big-endian hex (contract arg form). */
  readonly publicHex: string[];
}

/**
 * Prove a circuit in the browser from a fully-assembled witness (flat circom
 * input record). Returns the host-byte proof + public signals (no secret).
 *
 * @throws if the artifacts can't be fetched (operator must place them under
 *   public/artifacts/<circuit>/) or the witness is unsatisfiable.
 */
export async function proveInBrowser(
  circuit: CircuitName,
  witness: Record<string, unknown>,
): Promise<BrowserProof> {
  const { wasmUrl, zkeyUrl } = artifactUrls(circuit);
  // snarkjs types the witness as its narrower `CircuitInput`; our flat circom
  // record (incl. nested `string[][]` signals) is a valid superset at runtime, so
  // cast to the exact param type (mirrors prover/src/prove.ts).
  const { proof, publicSignals } = await groth16.fullProve(
    witness as Parameters<typeof groth16.fullProve>[0],
    wasmUrl,
    zkeyUrl,
  );
  // snarkjs's Groth16Proof uses general `string[]`; `SnarkProof` is the fixed
  // 3-element tuple shape proofToHost consumes (groth16 always emits that shape).
  return {
    hostProof: proofToHost(proof as unknown as SnarkProof),
    publicSignals,
    publicHex: publicSignals.map((s) => frToHex(s)),
  };
}
