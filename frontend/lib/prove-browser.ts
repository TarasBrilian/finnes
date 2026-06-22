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

  // Preflight the proving key. The #1 failure on a git-based deploy (e.g. Vercel)
  // is a MISSING .zkey: they are gitignored and too large to ride the deploy, so
  // the URL 404s and snarkjs reads the HTML error page as a zkey, surfacing the
  // opaque "Invalid File format". A cheap HEAD turns that into an actionable error.
  // Skipped silently if HEAD is blocked (CORS / unsupported) so a correctly-served
  // external host is never falsely rejected — fullProve then does the real fetch.
  let head: Response | undefined;
  try {
    head = await fetch(zkeyUrl, { method: 'HEAD' });
  } catch {
    /* CORS preflight / HEAD unsupported: fall through to fullProve */
  }
  if (head) {
    const ct = head.headers.get('content-type') ?? '';
    if (head.status === 404 || head.status === 403 || ct.includes('text/html')) {
      throw new Error(
        `proving key not served: ${zkeyUrl} (HTTP ${head.status}). The .zkey are ` +
          `gitignored and too large for a git deploy. Host them on external storage ` +
          `(Cloudflare R2 / S3 / a GitHub Release, with CORS + HTTP range enabled) and ` +
          `set NEXT_PUBLIC_ZKEY_BASE (or NEXT_PUBLIC_ZKEY_URL_${circuit.toUpperCase()}); ` +
          `for local dev place it under frontend/public/artifacts/${circuit}/.`,
      );
    }
  }
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
