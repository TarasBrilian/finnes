/**
 * Browser-safe snarkjs proof → Soroban host-byte hex conversion (FIN-027).
 *
 * A pure-JS port of scripts/lib/vk-host.ts's frToHex/g1ToHex/g2ToHex (no Node
 * `Buffer`), so the frontend can convert a client-side snarkjs proof + public
 * signals into the EXACT uncompressed big-endian encoding the BLS12-381 host
 * functions consume (the same `verifier.rs` decodes):
 *   Fr (32B):  be(scalar, 32)
 *   G1 (96B):  be(X, 48) ‖ be(Y, 48)
 *   G2 (192B): be(X_c1, 48) ‖ be(X_c0, 48) ‖ be(Y_c1, 48) ‖ be(Y_c0, 48)
 *     (snarkjs stores Fp2 as [c0, c1]; the host wants c1 FIRST, we swap.)
 *
 * Output is hex (no `0x`), the form the stellar-sdk ScVal builders take for
 * BytesN<32>/Bytes. PUBLIC data only (a proof reveals nothing secret).
 */

/** Big-endian fixed-width (len bytes) hex of a decimal/bigint string. */
function be(dec: string | bigint, len: number): string {
  const hex = BigInt(dec).toString(16);
  if (hex.length > len * 2) throw new Error(`value 0x${hex} exceeds ${len} bytes`);
  return hex.padStart(len * 2, '0');
}

/** Fr scalar (decimal string) → 32-byte big-endian hex. */
export function frToHex(dec: string | bigint): string {
  return be(dec, 32);
}

/** snarkjs G1 `[x, y, "1"]` → 96-byte host-encoded hex `be(X)‖be(Y)`. */
export function g1ToHex(p: [string, string, string]): string {
  return be(p[0], 48) + be(p[1], 48);
}

/** snarkjs G2 `[[x_c0,x_c1],[y_c0,y_c1],["1","0"]]` → 192-byte host hex (c1 ‖ c0). */
export function g2ToHex(p: [[string, string], [string, string], [string, string]]): string {
  return be(p[0][1], 48) + be(p[0][0], 48) + be(p[1][1], 48) + be(p[1][0], 48);
}

/** A snarkjs Groth16 proof (the shape `groth16.fullProve` returns). */
export interface SnarkProof {
  readonly pi_a: [string, string, string];
  readonly pi_b: [[string, string], [string, string], [string, string]];
  readonly pi_c: [string, string, string];
}

/** Host-byte proof: a/c are 96-byte G1 hex, b is 192-byte G2 hex. */
export interface HostProof {
  readonly a: string;
  readonly b: string;
  readonly c: string;
}

/** Convert a snarkjs proof to the contract's host-byte `Proof`. */
export function proofToHost(proof: SnarkProof): HostProof {
  return { a: g1ToHex(proof.pi_a), b: g2ToHex(proof.pi_b), c: g1ToHex(proof.pi_c) };
}
