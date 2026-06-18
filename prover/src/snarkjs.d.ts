/**
 * Minimal ambient type declarations for `snarkjs`.
 *
 * `snarkjs` ships no bundled `.d.ts` and there is no `@types/snarkjs`, so we
 * declare the narrow surface the prover uses. This keeps strict TS happy without
 * pulling in `any` across the module.
 *
 * TODO(types): if `@types/snarkjs` (or first-party types) become available, delete
 * this file and import the real types. Verify the runtime API shape against the
 * installed snarkjs version: `groth16.fullProve(input, wasmPath, zkeyPath)` and
 * `groth16.verify(vKey, publicSignals, proof)`.
 */
declare module "snarkjs" {
  /** A Groth16 proof object as produced by SnarkJS (pi_a / pi_b / pi_c / protocol / curve). */
  export interface Groth16Proof {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  }

  /** Ordered public signals (decimal strings). Order is normative — see docs/PUBLIC_IO.md. */
  export type PublicSignals = string[];

  /** Circuit input: flat map of signal-name → value(s). Carries the (secret) witness. */
  export type CircuitInput = Record<
    string,
    string | string[] | number | number[] | bigint | bigint[]
  >;

  export interface Groth16 {
    fullProve(
      input: CircuitInput,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{ proof: Groth16Proof; publicSignals: PublicSignals }>;

    verify(
      vKey: unknown,
      publicSignals: PublicSignals,
      proof: Groth16Proof,
    ): Promise<boolean>;
  }

  export const groth16: Groth16;
}
