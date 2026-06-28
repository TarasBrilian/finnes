/**
 * Encoding helpers at the DB/RPC/API boundaries.
 *
 * - On-chain 32-byte field values arrive as Buffers (from `scValToNative`).
 * - The DB stores them as raw `BYTEA` (Buffer).
 * - The HTTP API serves them as lowercase 64-char hex, no `0x` (matches the
 *   frontend's existing `toBig(hex)` / `liveNoteNullifier` convention).
 * - The in-memory Merkle tree (from `@finnes/sdk`) works in `bigint`.
 */

import { Buffer } from 'node:buffer';

export type Hex = string;

export const toHex = (b: Buffer | Uint8Array): Hex => Buffer.from(b).toString('hex');

export function fromHex(h: Hex): Buffer {
  const clean = h.startsWith('0x') ? h.slice(2) : h;
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error(`not hex: ${h}`);
  return Buffer.from(clean.padStart(64, '0'), 'hex');
}

export function bufToBig(b: Buffer | Uint8Array): bigint {
  const hex = Buffer.from(b).toString('hex');
  return hex.length ? BigInt('0x' + hex) : 0n;
}

export const bigToBuf = (x: bigint): Buffer => fromHex(x.toString(16));

/** A bigint (from the SDK Merkle tree) → lowercase 64-char hex for the API. */
export const bigToHex = (x: bigint): Hex => x.toString(16).padStart(64, '0');

export const isZeroBuf = (b: Buffer | Uint8Array): boolean =>
  Buffer.from(b).every((x) => x === 0);
