// Shared demo-scenario builder for the DvP circuit (FIN-016).
//
// Constructs a complete, consistent TWO-LEG atomic settlement witness:
//   leg X: party A spends an asset-X note -> B   (owner_sk = A)
//   leg Y: party B spends an asset-Y note -> A   (owner_sk = B)
// Two DIFFERENT assets, two DIFFERENT spending keys, one combined proof (DEMO
// only, invariant #15). Builds the Merkle structures both legs anchor to (anchor
// commitment tree, KYC tree, sanctions IMT, frozen IMT, assets registry) and calls
// the SDK witness builder. Depth-parametric (fast gate at depth 6; production D=20).
//
// SECURITY (invariant #8): throwaway demo secrets only; never reuse.

import {
  IncrementalMerkleTree,
  assetsLeafHash,
  imtLeafHash,
} from '../../sdk/src/merkle.js';
import { commitNote, deriveOwnerPk } from '../../sdk/src/note.js';
import { auditorPkFromKey } from '../../sdk/src/encrypt.js';
import { poseidonBLS, FR_MODULUS } from '../../sdk/src/poseidon.js';
import { buildDvpWitness, type ImtLowLeaf } from '../../sdk/src/witness.js';
import type { CircomWitness } from '../../sdk/src/witness.js';
import type { Fr, MerklePath, Note, OwnerSk } from '../../sdk/src/types.js';

const ownerPkOf = (sk: bigint): Fr => deriveOwnerPk(sk as unknown as OwnerSk);
export const IMT_MAX = FR_MODULUS - 1n;

export interface DvpScenarioOpts {
  /** Output values [legX_to_B, legY_to_A]. Default [1000, 500] (= inputs, fee 0). */
  outVals?: [Fr, Fr];
  /** Per-asset limit baked into BOTH registry leaves. Default 10_000_000. */
  perTxLimitRaw?: Fr;
  /** Model leg X's spent commitment as a MEMBER of the frozen set (rejection fixture). */
  frozenMemberLegX?: boolean;
}

export interface DvpScenario {
  /** Complete circom input record for `Dvp(depth, 5, 5)`. */
  witness: CircomWitness;
  /** Spent-note commitments [legX, legY], for negative-fixture construction. */
  cmIn: [Fr, Fr];
}

function buildImt(depth: number, specs: ImtLowLeaf[]): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(depth);
  specs.forEach((l) => t.insert(imtLeafHash(l.value, l.nextIndex, l.nextValue)));
  return t;
}

/** Build a valid (or, via opts, deliberately invalid) DvP witness at `depth`. */
export function buildDvpScenario(depth: number, opts: DvpScenarioOpts = {}): DvpScenario {
  const outVals = opts.outVals ?? [1000n, 500n];
  const perTxLimitRaw = opts.perTxLimitRaw ?? 10_000_000n;

  // Two assets (asset_id self-binds to Poseidon(sac_address)).
  const sacX = 777n;
  const sacY = 888n;
  const assetX = poseidonBLS([sacX]);
  const assetY = poseidonBLS([sacY]);
  const decimals = 7n;

  // Two parties.
  const skA = 42n;
  const skB = 77n;
  const pkA = ownerPkOf(skA);
  const pkB = ownerPkOf(skB);

  // Leg X: A spends an asset-X note (1000) -> B. Leg Y: B spends an asset-Y note (500) -> A.
  const inX: Note = { assetId: assetX, value: 1000n, ownerPk: pkA, rho: 1001n, rNote: 2001n };
  const inY: Note = { assetId: assetY, value: 500n, ownerPk: pkB, rho: 1002n, rNote: 2002n };
  const outX: Note = { assetId: assetX, value: outVals[0], ownerPk: pkB, rho: 3001n, rNote: 4001n };
  const outY: Note = { assetId: assetY, value: outVals[1], ownerPk: pkA, rho: 3002n, rNote: 4002n };
  const cmInX = commitNote(inX);
  const cmInY = commitNote(inY);

  // Targets must lie in (0, IMT_MAX) for the head-bracket non-membership to hold.
  for (const t of [pkA, pkB, cmInX, cmInY]) {
    if (t <= 0n || t >= IMT_MAX) throw new Error('demo target outside (0, MAX); adjust seeds');
  }

  // Anchor commitment tree: both spent notes already inserted (leg X at 0, Y at 1).
  const anchor = new IncrementalMerkleTree(depth);
  anchor.insert(cmInX);
  anchor.insert(cmInY);

  // KYC tree: each leg's recipient is enrolled (B for leg X, A for leg Y).
  const kyc = new IncrementalMerkleTree(depth);
  kyc.insert(pkB); // index 0 — leg X recipient
  kyc.insert(pkA); // index 1 — leg Y recipient

  // Sanctions IMT: empty (head {0 -> MAX} brackets every recipient pk).
  const sanc = buildImt(depth, [
    { value: 0n, nextIndex: 1n, nextValue: IMT_MAX },
    { value: IMT_MAX, nextIndex: 0n, nextValue: 0n },
  ]);
  const sancHead: ImtLowLeaf = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };

  // Frozen IMT: empty by default; optionally model leg X's cm as a MEMBER.
  let frozen: IncrementalMerkleTree;
  let frozenLowX: ImtLowLeaf;
  let frozenPathX: MerklePath;
  if (opts.frozenMemberLegX) {
    frozen = buildImt(depth, [
      { value: 0n, nextIndex: 1n, nextValue: cmInX },
      { value: cmInX, nextIndex: 2n, nextValue: IMT_MAX },
      { value: IMT_MAX, nextIndex: 0n, nextValue: 0n },
    ]);
    // The only candidate low leaf for cmInX has next_value == cmInX, so the
    // `target < next` ordering check fails → non-membership is unprovable.
    frozenLowX = { value: 0n, nextIndex: 1n, nextValue: cmInX };
    frozenPathX = frozen.inclusionPath(0);
  } else {
    frozen = buildImt(depth, [
      { value: 0n, nextIndex: 1n, nextValue: IMT_MAX },
      { value: IMT_MAX, nextIndex: 0n, nextValue: 0n },
    ]);
    frozenLowX = sancHead;
    frozenPathX = frozen.inclusionPath(0);
  }
  const frozenLowY: ImtLowLeaf = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };
  const frozenPathY = frozen.inclusionPath(0);

  // Authorized-assets registry: one leaf per asset.
  const assets = new IncrementalMerkleTree(depth);
  assets.insert(assetsLeafHash(assetX, sacX, decimals, perTxLimitRaw)); // index 0 — leg X
  assets.insert(assetsLeafHash(assetY, sacY, decimals, perTxLimitRaw)); // index 1 — leg Y

  const kView = 5n;
  const auditorPk = auditorPkFromKey(kView).pk;

  const { witness } = buildDvpWitness({
    anchorRoot: anchor.root(),
    kycRoot: kyc.root(),
    sanctionRoot: sanc.root(),
    assetsRoot: assets.root(),
    frozenRoot: frozen.root(),
    auditorPk,
    kView,
    oldFrontier: anchor.frontier(),
    nextIndex: anchor.size,
    inNotes: [inX, inY],
    ownerSk: [skA, skB],
    inPaths: [anchor.inclusionPath(0), anchor.inclusionPath(1)],
    outNotes: [outX, outY],
    frozenLow: [frozenLowX, frozenLowY],
    frozenPaths: [frozenPathX, frozenPathY],
    sacAddress: [sacX, sacY],
    decimals: [decimals, decimals],
    perTxLimitRaw: [perTxLimitRaw, perTxLimitRaw],
    assetsPaths: [assets.inclusionPath(0), assets.inclusionPath(1)],
    kycPaths: [kyc.inclusionPath(0), kyc.inclusionPath(1)],
    sanctionLow: [sancHead, sancHead],
    sanctionPaths: [sanc.inclusionPath(0), sanc.inclusionPath(0)],
    fee: [0n, 0n],
    kPair: [7n, 11n],
    rhoEncAuditor: [5101n, 5102n],
    rhoEncRecipient: [6101n, 6102n],
  });

  return { witness, cmIn: [cmInX, cmInY] };
}
