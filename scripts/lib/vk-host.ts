// snarkjs verifying key → Soroban host-byte encoding (FIN-015).
//
// Converts a snarkjs `vk_*.json` into the EXACT uncompressed big-endian point
// serialization the BLS12-381 host functions consume (the same encoding
// `verifier.rs` decodes and `gen-verifier-fixture.ts` emits for the cargo tests):
//   - G1 (96 bytes):  be(X,48) ‖ be(Y,48)
//   - G2 (192 bytes): be(X_c1,48) ‖ be(X_c0,48) ‖ be(Y_c1,48) ‖ be(Y_c0,48)
//     (snarkjs stores Fp2 as [c0, c1]; the host wants c1 FIRST — we swap.)
//   - Fr (32 bytes):  be(scalar,32)
//
// Output values are hex strings (no `0x`), the form the InitConfig JSON feeds to
// the contract's `VerifyingKey { alpha_g1, beta_g2, gamma_g2, delta_g2, ic[] }`.
//
// PUBLIC data only (a verifying key reveals nothing secret, invariant #8).

/** Big-endian fixed-width bytes of a decimal/bigint string. */
function be(dec: string | bigint, len: number): Uint8Array {
  let hex = BigInt(dec).toString(16);
  if (hex.length > len * 2) throw new Error(`value 0x${hex} exceeds ${len} bytes`);
  hex = hex.padStart(len * 2, '0');
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

function cat(...parts: Uint8Array[]): Uint8Array {
  return Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));
}

function toHex(u8: Uint8Array): string {
  return Buffer.from(u8).toString('hex');
}

/** Fr scalar (decimal string) → 32-byte big-endian hex. */
export function frToHex(dec: string | bigint): string {
  return toHex(be(dec, 32));
}

/** snarkjs G1 `[x, y, "1"]` → 96-byte host-encoded hex. */
export function g1ToHex(p: [string, string, string]): string {
  return toHex(cat(be(p[0], 48), be(p[1], 48)));
}

/** snarkjs G2 `[[x_c0,x_c1],[y_c0,y_c1],["1","0"]]` → 192-byte host hex (c1 ‖ c0). */
export function g2ToHex(p: [[string, string], [string, string], [string, string]]): string {
  return toHex(cat(be(p[0][1], 48), be(p[0][0], 48), be(p[1][1], 48), be(p[1][0], 48)));
}

/** The contract's `VerifyingKey` fields, host-encoded as hex strings. */
export interface HostVerifyingKey {
  readonly alpha_g1: string;
  readonly beta_g2: string;
  readonly gamma_g2: string;
  readonly delta_g2: string;
  readonly ic: readonly string[];
}

/** Convert a parsed snarkjs vk JSON to the contract's host-byte `VerifyingKey`. */
export function vkToHost(vk: {
  protocol?: string;
  curve?: string;
  nPublic?: number;
  vk_alpha_1: [string, string, string];
  vk_beta_2: [[string, string], [string, string], [string, string]];
  vk_gamma_2: [[string, string], [string, string], [string, string]];
  vk_delta_2: [[string, string], [string, string], [string, string]];
  IC: [string, string, string][];
}): HostVerifyingKey {
  if (vk.curve && vk.curve !== 'bls12381') {
    throw new Error(`vk curve ${vk.curve} != bls12381 (invariant #1)`);
  }
  if (vk.protocol && vk.protocol !== 'groth16') {
    throw new Error(`vk protocol ${vk.protocol} != groth16`);
  }
  if (typeof vk.nPublic === 'number' && vk.IC.length !== vk.nPublic + 1) {
    throw new Error(`vk IC arity ${vk.IC.length} != nPublic+1 ${vk.nPublic + 1}`);
  }
  return {
    alpha_g1: g1ToHex(vk.vk_alpha_1),
    beta_g2: g2ToHex(vk.vk_beta_2),
    gamma_g2: g2ToHex(vk.vk_gamma_2),
    delta_g2: g2ToHex(vk.vk_delta_2),
    ic: vk.IC.map(g1ToHex),
  };
}

/** An empty placeholder VK (e.g. for `dvp`, whose circuit is not yet built). */
export const EMPTY_HOST_VK: HostVerifyingKey = {
  alpha_g1: '',
  beta_g2: '',
  gamma_g2: '',
  delta_g2: '',
  ic: [],
};
