// Demo compliance-state builder (FIN-015).
//
// Produces the OFF-CHAIN state the post-deploy `init` + the prover + the frontend
// consume: the four compliance roots (kyc / sanction / assets / frozen), the
// auditor public key, and the empty commitment-tree seed (initial frontier/root).
// It is the "mock KYC enrollment" admin step (ARCHITECTURE.md → Backend/API): the
// in-circuit KYC membership check STAYS (invariant: never drop it); enrollment is
// this hand-run admin script over demo accounts, with no real identity provider.
//
// Pure SDK computation — fully runnable offline, independent of the D=20 ceremony
// and of any deployed contract. Built with the SAME Poseidon/Merkle/IMT primitives
// the circuit and prover use, so the roots it emits are exactly what a proof must
// anchor to.
//
// SECURITY (invariant #8): the per-account spending keys and the auditor view key
// below are THROWAWAY DEMO constants (like scripts/lib/*-scenario.ts), never real
// keys. `toPublicState()` serializes PUBLIC values ONLY — derived `owner_pk`s,
// roots, `auditor_pk`, asset metadata — never an `owner_sk` or `k_view`.

import {
  IncrementalMerkleTree,
  assetsLeafHash,
  imtLeafHash,
  verifyInclusionPath,
  TREE_DEPTH,
} from '../../sdk/src/merkle.js';
import { deriveAssetId, deriveOwnerPk, sacAddressToField } from '../../sdk/src/note.js';
import { auditorPkFromKey } from '../../sdk/src/encrypt.js';
import { FR_MODULUS } from '../../sdk/src/poseidon.js';
import type { Fr, MerklePath, OwnerSk } from '../../sdk/src/types.js';

/** IMT tail sentinel: a value above every real entry (head-bracket upper bound). */
export const IMT_MAX = FR_MODULUS - 1n;

/** A demo institution enrolled into `kyc_root`. `ownerSk` is a DEMO secret. */
export interface DemoAccount {
  readonly label: string;
  /** DEMO spending secret (throwaway). Never serialized (invariant #8). */
  readonly ownerSk: bigint;
}

/** A demo authorized asset (a leaf of the assets registry). */
export interface DemoAsset {
  readonly label: string;
  /** Field-literal SAC address (the demo representation; `asset_id = Poseidon`). */
  readonly sacAddress: string;
  readonly decimals: number;
  readonly perTxLimitRaw: bigint;
}

// IMPORTANT — keep these demo identity constants in lockstep with
// `frontend/lib/demo-data.ts` (DEMO_AUDITOR_VIEW_KEY, the bank `ownerSk`s, and the
// asset `sacAddress`es): this script enrolls them into `kyc_root` and derives the
// `auditor_pk` the contract `init` stores, while the frontend regulator/scan use
// the same constants to encrypt/decrypt. If they drift, the on-chain `auditor_pk`
// won't match the frontend's view key (invariant #5) and the demo goes incoherent.
// (A cross-file parity gate is deferred until the frontend UI refactor settles to
// avoid coupling this script to an in-flux file.)

/** DEMO auditor view key `k_view` (throwaway). `auditor_pk = Poseidon(k_view)`. */
export const DEMO_AUDITOR_VIEW_KEY: Fr = 777_000_001n;

/** The institutions enrolled in the demo (the issuer/admin pre-enrolls these). */
export const DEMO_ACCOUNTS: readonly DemoAccount[] = [
  { label: 'Meridian Capital (Bank A)', ownerSk: 1001n },
  { label: 'Cendrawasih Bank (Bank B)', ownerSk: 1002n },
  { label: 'Garuda Sekuritas (Bank C)', ownerSk: 1003n },
];

/** An account that is NOT enrolled — used to prove the KYC gate actually gates. */
export const DEMO_OUTSIDER: DemoAccount = { label: 'Unenrolled Co.', ownerSk: 9009n };

/** The authorized assets in the demo registry. */
export const DEMO_ASSETS: readonly DemoAsset[] = [
  { label: 'TBOND-2031 (tokenized bond)', sacAddress: '777', decimals: 7, perTxLimitRaw: 10_000_000n },
  { label: 'eUSD (confidential cash)', sacAddress: '888', decimals: 7, perTxLimitRaw: 50_000_000n },
];

export interface EnrolledAccount {
  readonly label: string;
  readonly ownerPk: Fr;
  readonly kycLeafIndex: number;
  /** Inclusion path proving `ownerPk` ∈ `kycRoot` (for the prover's witness). */
  readonly kycPath: MerklePath;
}

export interface RegisteredAsset {
  readonly label: string;
  readonly assetId: Fr;
  readonly sacAddress: string;
  readonly decimals: number;
  readonly perTxLimitRaw: bigint;
  readonly assetsLeafIndex: number;
  readonly assetsPath: MerklePath;
}

export interface DemoComplianceState {
  readonly treeDepth: number;
  readonly auditorPk: Fr;
  readonly kycRoot: Fr;
  readonly sanctionRoot: Fr;
  readonly assetsRoot: Fr;
  readonly frozenRoot: Fr;
  /**
   * Inclusion path of the empty-IMT head low-leaf `{0 → MAX}` in `sanctionRoot` /
   * `frozenRoot`. With this path + the bracket `0 < target < MAX`, the prover (and
   * the gate) proves NON-membership of any real `owner_pk`/`cm` against the empty
   * set, exactly as the in-circuit `MerkleNonMembership` gadget does.
   */
  readonly sanctionLowPath: MerklePath;
  readonly frozenLowPath: MerklePath;
  /** Empty commitment-tree seed for `init` (initial_frontier / initial_root). */
  readonly initialRoot: Fr;
  readonly initialFrontier: readonly Fr[];
  readonly accounts: readonly EnrolledAccount[];
  readonly assets: readonly RegisteredAsset[];
}

/** The empty-IMT head low-leaf `{value:0, nextIndex:1, nextValue:MAX}` (index 0). */
export const EMPTY_IMT_LOW_LEAF: () => Fr = () => imtLeafHash(0n, 1n, IMT_MAX);

/** Build an empty-set IMT (only the `{0 → MAX}` head bracket): everyone is absent. */
function emptyImt(depth: number): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(depth);
  t.insert(imtLeafHash(0n, 1n, IMT_MAX));
  t.insert(imtLeafHash(IMT_MAX, 0n, 0n));
  return t;
}

/**
 * Build the full demo compliance state at the given tree depth (default the
 * production `TREE_DEPTH = 20`). All roots are real Poseidon/Merkle outputs.
 */
export function buildDemoComplianceState(depth: number = TREE_DEPTH): DemoComplianceState {
  // KYC tree: enroll every demo account's owner_pk (membership, invariant #6).
  // Insert ALL leaves first, THEN derive each inclusion path against the final
  // tree (a path taken mid-insert would be stale once a later leaf changes the
  // siblings). Each pk must fall in (0, IMT_MAX) so it is bracketable for the
  // sanctions/frozen non-membership proofs below.
  const kyc = new IncrementalMerkleTree(depth);
  const ownerPks = DEMO_ACCOUNTS.map((a) => deriveOwnerPk(a.ownerSk as unknown as OwnerSk));
  ownerPks.forEach((pk) => {
    if (pk <= 0n || pk >= IMT_MAX) {
      throw new Error('demo owner_pk outside (0, IMT_MAX); adjust the demo seed');
    }
    kyc.insert(pk);
  });
  const accounts: EnrolledAccount[] = DEMO_ACCOUNTS.map((a, i) => ({
    label: a.label,
    ownerPk: ownerPks[i]!,
    kycLeafIndex: i,
    kycPath: kyc.inclusionPath(i),
  }));

  // Assets registry: one leaf per authorized asset. Insert ALL leaves first, then
  // derive each inclusion path against the final tree. The leaf's `sac_address`
  // field and `asset_id`'s preimage go through the SAME canonical encoding
  // (`sacAddressToField`) so they cannot diverge (`asset_id = Poseidon(sac_field)`).
  const assetsTree = new IncrementalMerkleTree(depth);
  const sacFields = DEMO_ASSETS.map((a) => sacAddressToField(a.sacAddress));
  const assetIds = DEMO_ASSETS.map((a) => deriveAssetId(a.sacAddress));
  DEMO_ASSETS.forEach((a, i) => {
    assetsTree.insert(
      assetsLeafHash(assetIds[i]!, sacFields[i]!, BigInt(a.decimals), a.perTxLimitRaw),
    );
  });
  const assets: RegisteredAsset[] = DEMO_ASSETS.map((a, i) => ({
    label: a.label,
    assetId: assetIds[i]!,
    sacAddress: a.sacAddress,
    decimals: a.decimals,
    perTxLimitRaw: a.perTxLimitRaw,
    assetsLeafIndex: i,
    assetsPath: assetsTree.inclusionPath(i),
  }));

  // Sanctions + frozen: empty sets (non-membership for everyone) at demo start.
  // The head low-leaf path lets the prover/gate prove a real target is absent.
  const sanction = emptyImt(depth);
  const frozen = emptyImt(depth);

  // Empty commitment tree: the seed `init` stores as initial_frontier / initial_root.
  const commitment = new IncrementalMerkleTree(depth);

  return {
    treeDepth: depth,
    auditorPk: auditorPkFromKey(DEMO_AUDITOR_VIEW_KEY).pk,
    kycRoot: kyc.root(),
    sanctionRoot: sanction.root(),
    assetsRoot: assetsTree.root(),
    frozenRoot: frozen.root(),
    sanctionLowPath: sanction.inclusionPath(0),
    frozenLowPath: frozen.inclusionPath(0),
    initialRoot: commitment.root(),
    initialFrontier: commitment.frontier(),
    accounts,
    assets,
  };
}

/** True iff `ownerPk` is enrolled in `kycRoot` (membership verifies). */
export function verifyEnrolled(state: DemoComplianceState, account: EnrolledAccount): boolean {
  return verifyInclusionPath(account.ownerPk, account.kycPath, state.kycRoot);
}

/**
 * True iff `target` is provably ABSENT from an empty IMT with root `root` and head
 * low-leaf path `lowPath` — the exact non-membership the in-circuit gadget checks:
 * the head low-leaf `{0 → MAX}` is in the tree AND `0 < target < MAX`, so the leaf
 * brackets `target` (no node equals it). Used for sanctions + frozen sets.
 */
export function verifyAbsent(target: Fr, root: Fr, lowPath: MerklePath): boolean {
  return (
    target > 0n &&
    target < IMT_MAX &&
    verifyInclusionPath(EMPTY_IMT_LOW_LEAF(), lowPath, root)
  );
}

/**
 * Serialize the PUBLIC compliance state to a plain JSON-able object (decimal
 * strings). NEVER includes a spending key or the auditor view key (invariant #8).
 * This is what `init` (roots + auditor_pk + initial frontier/root) and the
 * frontend/prover config consume.
 */
export function toPublicState(state: DemoComplianceState): Record<string, unknown> {
  return {
    treeDepth: state.treeDepth,
    auditorPk: state.auditorPk.toString(),
    roots: {
      kycRoot: state.kycRoot.toString(),
      sanctionRoot: state.sanctionRoot.toString(),
      assetsRoot: state.assetsRoot.toString(),
      frozenRoot: state.frozenRoot.toString(),
      initialRoot: state.initialRoot.toString(),
    },
    initialFrontier: state.initialFrontier.map((f) => f.toString()),
    accounts: state.accounts.map((a) => ({
      label: a.label,
      ownerPk: a.ownerPk.toString(),
      kycLeafIndex: a.kycLeafIndex,
    })),
    assets: state.assets.map((a) => ({
      label: a.label,
      assetId: a.assetId.toString(),
      sacAddress: a.sacAddress,
      decimals: a.decimals,
      perTxLimitRaw: a.perTxLimitRaw.toString(),
      assetsLeafIndex: a.assetsLeafIndex,
    })),
  };
}
