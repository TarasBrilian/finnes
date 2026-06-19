// Shared demo-scenario builder for the confidential transfer circuit.
//
// Constructs a complete, consistent 2-in / 2-out single-asset transfer witness by
// building the five Merkle structures the circuit anchors to (anchor commitment
// tree, KYC tree, sanctions IMT, frozen IMT, assets registry) and calling the SDK
// witness builder. Depth-parametric so the SAME scenario drives both the fast
// witness-acceptance gate (depth 6, scripts/test-transfer-witness.ts) and the
// end-to-end prove/verify against the production D=20 artifacts
// (scripts/test-prove-transfer.ts).
//
// SECURITY (invariant #8): the returned witness embeds demo secrets. These are
// throwaway constants for tests, never real keys; do not reuse them.

import {
  IncrementalMerkleTree,
  assetsLeafHash,
  imtLeafHash,
} from '../../sdk/src/merkle.js';
import { commitNote, deriveOwnerPk } from '../../sdk/src/note.js';
import { auditorPkFromKey } from '../../sdk/src/encrypt.js';
import { poseidonBLS, FR_MODULUS } from '../../sdk/src/poseidon.js';
import { buildTransferWitness, type ImtLowLeaf } from '../../sdk/src/witness.js';
import type { CircomWitness } from '../../sdk/src/witness.js';
import type { Fr, MerklePath, Note, OwnerSk } from '../../sdk/src/types.js';

const ownerPkOf = (sk: bigint): Fr => deriveOwnerPk(sk as unknown as OwnerSk);
/** IMT tail sentinel: a value above every real entry (head-bracket upper bound). */
export const IMT_MAX = FR_MODULUS - 1n;

export interface TransferScenarioOpts {
  /** Output note values [recipient, change]. Default [700, 300] (Σ = inputs). */
  outVals?: [Fr, Fr];
  /** Per-asset limit baked into the registry leaf. Default 10_000_000. */
  perTxLimitRaw?: Fr;
  /** Model cm_in[0] as a MEMBER of the frozen set (for the rejection fixture). */
  frozenMemberInput0?: boolean;
}

export interface TransferScenario {
  /** Complete circom input record for `Transfer(depth, 5, 5)`. */
  witness: CircomWitness;
  /** Input-note commitments, exposed for negative-fixture construction. */
  cmIn: [Fr, Fr];
}

function buildImt(depth: number, specs: ImtLowLeaf[]): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(depth);
  specs.forEach((l) => t.insert(imtLeafHash(l.value, l.nextIndex, l.nextValue)));
  return t;
}

/**
 * Build a valid (or, via `opts`, a deliberately invalid) transfer witness at the
 * given tree depth. The default produces a fully consistent, accepting witness.
 */
export function buildTransferScenario(
  depth: number,
  opts: TransferScenarioOpts = {},
): TransferScenario {
  const outVals = opts.outVals ?? [700n, 300n];
  const perTxLimitRaw = opts.perTxLimitRaw ?? 10_000_000n;

  // Asset (asset_id self-binds to Poseidon(sac_address)).
  const sacAddress = 777n;
  const assetId = poseidonBLS([sacAddress]);
  const decimals = 7n;

  // Parties.
  const ownerSk = 42n;
  const ownerPkSender = ownerPkOf(ownerSk);
  const recipientPk = ownerPkOf(99n);

  // Input notes (both owned by the sender): 600 + 400 = 1000 raw units.
  const inNotes: [Note, Note] = [
    { assetId, value: 600n, ownerPk: ownerPkSender, rho: 1001n, rNote: 2001n },
    { assetId, value: 400n, ownerPk: ownerPkSender, rho: 1002n, rNote: 2002n },
  ];
  const cmIn: [Fr, Fr] = [commitNote(inNotes[0]), commitNote(inNotes[1])];

  // Output notes: note 0 -> recipient, note 1 -> change back to sender.
  const outNotes: [Note, Note] = [
    { assetId, value: outVals[0], ownerPk: recipientPk, rho: 3001n, rNote: 4001n },
    { assetId, value: outVals[1], ownerPk: ownerPkSender, rho: 3002n, rNote: 4002n },
  ];

  // Targets must be in (0, IMT_MAX) for the head-bracket to hold.
  for (const t of [recipientPk, cmIn[0], cmIn[1]]) {
    if (t <= 0n || t >= IMT_MAX) throw new Error('demo target outside (0, MAX); adjust seeds');
  }

  // Anchor commitment tree: the two spent notes are already inserted.
  const anchor = new IncrementalMerkleTree(depth);
  anchor.insert(cmIn[0]);
  anchor.insert(cmIn[1]);
  const inPaths: [MerklePath, MerklePath] = [anchor.inclusionPath(0), anchor.inclusionPath(1)];

  // KYC tree: the recipient pk is enrolled (kyc_leaf == out_owner_pk[0]).
  const kyc = new IncrementalMerkleTree(depth);
  kyc.insert(recipientPk);

  // Sanctions IMT: head {0 -> MAX} brackets the recipient pk (absent).
  const sanc = buildImt(depth, [
    { value: 0n, nextIndex: 1n, nextValue: IMT_MAX },
    { value: IMT_MAX, nextIndex: 0n, nextValue: 0n },
  ]);
  const sanctionLow: ImtLowLeaf = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };

  // Frozen IMT.
  let frozenTree: IncrementalMerkleTree;
  let frozenLow: [ImtLowLeaf, ImtLowLeaf];
  let frozenPaths: [MerklePath, MerklePath];
  if (opts.frozenMemberInput0) {
    // Model cm_in[0] as a MEMBER of the frozen set: in the sorted list
    // 0 < cmIn0 < MAX, cmIn0 is a node, so non-membership of cmIn0 is unprovable
    // (its only candidate low leaf has next_value == cmIn0, failing target < next).
    frozenTree = buildImt(depth, [
      { value: 0n, nextIndex: 1n, nextValue: cmIn[0] },
      { value: cmIn[0], nextIndex: 2n, nextValue: IMT_MAX },
      { value: IMT_MAX, nextIndex: 0n, nextValue: 0n },
    ]);
    const low0: ImtLowLeaf = { value: 0n, nextIndex: 1n, nextValue: cmIn[0] };
    // input 1: bracket cm_in[1] correctly so ONLY input 0 fails.
    let low1: ImtLowLeaf;
    let path1: MerklePath;
    if (cmIn[1] < cmIn[0]) {
      low1 = { value: 0n, nextIndex: 1n, nextValue: cmIn[0] };
      path1 = frozenTree.inclusionPath(0);
    } else {
      low1 = { value: cmIn[0], nextIndex: 2n, nextValue: IMT_MAX };
      path1 = frozenTree.inclusionPath(1);
    }
    frozenLow = [low0, low1];
    frozenPaths = [frozenTree.inclusionPath(0), path1];
  } else {
    frozenTree = buildImt(depth, [
      { value: 0n, nextIndex: 1n, nextValue: IMT_MAX },
      { value: IMT_MAX, nextIndex: 0n, nextValue: 0n },
    ]);
    const low: ImtLowLeaf = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };
    frozenLow = [low, low];
    frozenPaths = [frozenTree.inclusionPath(0), frozenTree.inclusionPath(0)];
  }

  // Authorized-assets registry: a single leaf for this asset.
  const assets = new IncrementalMerkleTree(depth);
  assets.insert(assetsLeafHash(assetId, sacAddress, decimals, perTxLimitRaw));

  // Encryption keying.
  const kView = 5n;
  const auditorPk = auditorPkFromKey(kView).pk;

  const { witness } = buildTransferWitness({
    ownerSk,
    inNotes,
    inPaths,
    anchorRoot: anchor.root(),
    outNotes,
    kycLeaf: recipientPk,
    kycPath: kyc.inclusionPath(0),
    kycRoot: kyc.root(),
    sanctionLow,
    sanctionPath: sanc.inclusionPath(0),
    sanctionRoot: sanc.root(),
    frozenLow,
    frozenPaths,
    frozenRoot: frozenTree.root(),
    sacAddress,
    decimals,
    perTxLimitRaw,
    assetsPath: assets.inclusionPath(0),
    assetsRoot: assets.root(),
    oldFrontier: anchor.frontier(),
    nextIndex: anchor.size,
    fee: 0n,
    auditorPk,
    kView,
    kPair: [7n, 11n],
    rhoEncAuditor: [5101n, 5102n],
    rhoEncRecipient: [6101n, 6102n],
  });

  return { witness, cmIn };
}
