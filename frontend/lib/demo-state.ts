'use client';

/**
 * Frontend port of scripts/lib/demo-state.ts, the deterministic compliance state
 * the deployed contract was init'd with (FIN-027). Exposes the enrolled demo bank
 * identities (with their KYC inclusion paths) and the authorized assets (with
 * their registry paths), so the write-path can assemble a REAL witness that the
 * contract accepts. Built with the same @finnes/sdk Poseidon/Merkle the prover and
 * circuit use, at the production depth, so its roots equal the on-chain init roots
 * (verified: `demoComplianceRoots` parity).
 *
 * SECURITY (invariant #8): the per-account `ownerSk` and the auditor `k_view` are
 * THROWAWAY demo constants, identical to scripts/lib/demo-state.ts (kept in
 * lockstep). A random session key is NOT enrolled here, so any real write must act
 * as one of these enrolled identities, the demo's stand-in for admin KYC
 * enrollment (the in-circuit KYC check is never dropped).
 */

import type { Fr, MerklePath, OwnerSk } from '@finnes/sdk';
import {
  assetsLeafHash,
  auditorPkFromKey,
  deriveAssetId,
  deriveOwnerPk,
  FR_MODULUS,
  imtLeafHash,
  IncrementalMerkleTree,
  sacAddressToField,
  TREE_DEPTH,
} from '@finnes/sdk';

export const IMT_MAX: Fr = FR_MODULUS - 1n;

/** The fixed demo auditor view key; `auditor_pk = Poseidon(k_view)`. */
export const DEMO_AUDITOR_VIEW_KEY: Fr = 777_000_001n;

export interface DemoAccountSpec {
  readonly label: string;
  readonly ownerSk: bigint;
}
/** Enrolled demo institutions (lockstep with scripts/lib/demo-state.ts). */
export const DEMO_ACCOUNTS: readonly DemoAccountSpec[] = [
  { label: 'Meridian Capital (Bank A)', ownerSk: 1001n },
  { label: 'Cendrawasih Bank (Bank B)', ownerSk: 1002n },
  { label: 'Garuda Sekuritas (Bank C)', ownerSk: 1003n },
];

export interface DemoAssetSpec {
  readonly label: string;
  readonly sacAddress: string;
  readonly decimals: number;
  readonly perTxLimitRaw: bigint;
}
export const DEMO_ASSETS: readonly DemoAssetSpec[] = [
  { label: 'TBOND-2031 (tokenized bond)', sacAddress: '777', decimals: 7, perTxLimitRaw: 10_000_000n },
  { label: 'eUSD (confidential cash)', sacAddress: '888', decimals: 7, perTxLimitRaw: 50_000_000n },
];

export interface EnrolledAccount {
  readonly label: string;
  readonly ownerSk: OwnerSk;
  readonly ownerPk: Fr;
  readonly kycPath: MerklePath;
}
export interface RegisteredAsset {
  readonly label: string;
  readonly assetId: Fr;
  readonly sacAddress: string;
  readonly decimals: number;
  readonly perTxLimitRaw: bigint;
  readonly assetsPath: MerklePath;
}

export interface DemoState {
  readonly auditorPk: Fr;
  readonly kycRoot: Fr;
  readonly sanctionRoot: Fr;
  readonly assetsRoot: Fr;
  readonly frozenRoot: Fr;
  readonly sanctionLowPath: MerklePath;
  readonly frozenLowPath: MerklePath;
  readonly accounts: readonly EnrolledAccount[];
  readonly assets: readonly RegisteredAsset[];
}

function emptyImt(): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(TREE_DEPTH);
  t.insert(imtLeafHash(0n, 1n, IMT_MAX));
  t.insert(imtLeafHash(IMT_MAX, 0n, 0n));
  return t;
}

let cached: DemoState | undefined;

/** Build (and memoise) the full demo state at the production depth. */
export function demoState(): DemoState {
  if (cached) return cached;

  const kyc = new IncrementalMerkleTree(TREE_DEPTH);
  const ownerPks = DEMO_ACCOUNTS.map((a) => deriveOwnerPk(a.ownerSk as unknown as OwnerSk));
  ownerPks.forEach((pk) => kyc.insert(pk));
  const accounts: EnrolledAccount[] = DEMO_ACCOUNTS.map((a, i) => ({
    label: a.label,
    ownerSk: a.ownerSk as unknown as OwnerSk,
    ownerPk: ownerPks[i]!,
    kycPath: kyc.inclusionPath(i),
  }));

  const assetsTree = new IncrementalMerkleTree(TREE_DEPTH);
  DEMO_ASSETS.forEach((a) =>
    assetsTree.insert(
      assetsLeafHash(deriveAssetId(a.sacAddress), sacAddressToField(a.sacAddress), BigInt(a.decimals), a.perTxLimitRaw),
    ),
  );
  const assets: RegisteredAsset[] = DEMO_ASSETS.map((a, i) => ({
    label: a.label,
    assetId: deriveAssetId(a.sacAddress),
    sacAddress: a.sacAddress,
    decimals: a.decimals,
    perTxLimitRaw: a.perTxLimitRaw,
    assetsPath: assetsTree.inclusionPath(i),
  }));

  const sanction = emptyImt();
  const frozen = emptyImt();

  cached = {
    auditorPk: auditorPkFromKey(DEMO_AUDITOR_VIEW_KEY).pk,
    kycRoot: kyc.root(),
    sanctionRoot: sanction.root(),
    assetsRoot: assetsTree.root(),
    frozenRoot: frozen.root(),
    sanctionLowPath: sanction.inclusionPath(0),
    frozenLowPath: frozen.inclusionPath(0),
    accounts,
    assets,
  };
  return cached;
}

/** The empty-IMT head low-leaf witness `{0 → MAX}` for sanction/frozen non-membership. */
export const HEAD_LOW = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };
