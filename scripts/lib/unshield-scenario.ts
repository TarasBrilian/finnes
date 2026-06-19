// Shared demo-scenario builder for the unshield (shielded -> transparent) circuit.
//
// Builds the four Merkle structures the circuit anchors to (anchor commitment
// tree, recipient KYC tree, sanctions IMT, frozen IMT) plus the assets registry,
// then calls the SDK witness builder. Depth-parametric so the SAME scenario drives
// the fast witness-acceptance gate (depth 6, scripts/test-unshield-witness.ts) and
// (later) an end-to-end prove against demo artifacts.
//
// SECURITY (invariant #8): the returned witness embeds demo secrets. These are
// throwaway constants for tests, never real keys; do not reuse them.

import { IncrementalMerkleTree, assetsLeafHash, imtLeafHash } from '../../sdk/src/merkle.js';
import { commitNote, deriveOwnerPk } from '../../sdk/src/note.js';
import { auditorPkFromKey } from '../../sdk/src/encrypt.js';
import { poseidonBLS, FR_MODULUS } from '../../sdk/src/poseidon.js';
import { buildUnshieldWitness, type ImtLowLeaf } from '../../sdk/src/witness.js';
import type { CircomWitness } from '../../sdk/src/witness.js';
import type { Fr, MerklePath, Note, OwnerSk } from '../../sdk/src/types.js';

const ownerPkOf = (sk: bigint): Fr => deriveOwnerPk(sk as unknown as OwnerSk);
/** IMT tail sentinel: a value above every real entry. */
export const IMT_MAX = FR_MODULUS - 1n;

export interface UnshieldScenarioOpts {
  /** Exact spend (no change note): amount == in_value, has_change = 0. */
  noChange?: boolean;
  /** Per-asset limit baked into the registry leaf. Default 10_000_000. */
  perTxLimitRaw?: Fr;
  /** Amount leaving (default 700; change = in_value - amount - fee). */
  amount?: Fr;
  /** Model cm_in as a MEMBER of the frozen set (rejection fixture, #19b). */
  frozenMemberInput?: boolean;
  /** Model the transparent recipient as SANCTIONED (rejection fixture, #19a). */
  recipientSanctioned?: boolean;
}

export interface UnshieldScenario {
  witness: CircomWitness;
  cmIn: Fr;
}

function buildImt(depth: number, specs: ImtLowLeaf[]): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(depth);
  specs.forEach((l) => t.insert(imtLeafHash(l.value, l.nextIndex, l.nextValue)));
  return t;
}

/**
 * Build a valid (or, via `opts`, deliberately invalid) unshield witness at the
 * given depth. Default: 1000-unit input, 700 leaving to a KYC'd recipient, 300
 * change back to the sender.
 */
export function buildUnshieldScenario(
  depth: number,
  opts: UnshieldScenarioOpts = {},
): UnshieldScenario {
  const perTxLimitRaw = opts.perTxLimitRaw ?? 10_000_000n;
  const inValue = 1000n;
  const amount = opts.amount ?? (opts.noChange ? inValue : 700n);
  const fee = 0n;
  const changeValue = inValue - amount - fee;

  // Asset (asset_id self-binds to Poseidon(sac_address)).
  const sacAddress = 777n;
  const assetId = poseidonBLS([sacAddress]);
  const decimals = 7n;

  // Spender + transparent recipient (a public address-field, KYC-enrolled).
  const ownerSk = 42n;
  const ownerPk = ownerPkOf(ownerSk);
  const recipient = 555n;

  const inNote: Note = { assetId, value: inValue, ownerPk, rho: 1001n, rNote: 2001n };
  const cmIn = commitNote(inNote);

  for (const t of [recipient, cmIn]) {
    if (t <= 0n || t >= IMT_MAX) throw new Error('demo target outside (0, MAX); adjust seeds');
  }

  // Anchor commitment tree: the spent note is already inserted at index 0.
  const anchor = new IncrementalMerkleTree(depth);
  anchor.insert(cmIn);
  const inPath = anchor.inclusionPath(0);

  // Recipient KYC tree: recipient enrolled.
  const kyc = new IncrementalMerkleTree(depth);
  kyc.insert(recipient);

  // Sanctions IMT: head {0 -> MAX} brackets recipient (absent), unless we model
  // the recipient as sanctioned (then its low leaf's next_value == recipient).
  let sanc: IncrementalMerkleTree;
  let sanctionLow: ImtLowLeaf;
  if (opts.recipientSanctioned) {
    sanc = buildImt(depth, [
      { value: 0n, nextIndex: 1n, nextValue: recipient },
      { value: recipient, nextIndex: 2n, nextValue: IMT_MAX },
      { value: IMT_MAX, nextIndex: 0n, nextValue: 0n },
    ]);
    sanctionLow = { value: 0n, nextIndex: 1n, nextValue: recipient }; // target == next_value => fails
  } else {
    sanc = buildImt(depth, [
      { value: 0n, nextIndex: 1n, nextValue: IMT_MAX },
      { value: IMT_MAX, nextIndex: 0n, nextValue: 0n },
    ]);
    sanctionLow = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };
  }

  // Frozen IMT: head {0 -> MAX} brackets cm_in (absent), unless we model cm_in as
  // frozen (then its low leaf's next_value == cm_in, so non-membership fails).
  let frozen: IncrementalMerkleTree;
  let frozenLow: ImtLowLeaf;
  if (opts.frozenMemberInput) {
    frozen = buildImt(depth, [
      { value: 0n, nextIndex: 1n, nextValue: cmIn },
      { value: cmIn, nextIndex: 2n, nextValue: IMT_MAX },
      { value: IMT_MAX, nextIndex: 0n, nextValue: 0n },
    ]);
    frozenLow = { value: 0n, nextIndex: 1n, nextValue: cmIn };
  } else {
    frozen = buildImt(depth, [
      { value: 0n, nextIndex: 1n, nextValue: IMT_MAX },
      { value: IMT_MAX, nextIndex: 0n, nextValue: 0n },
    ]);
    frozenLow = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };
  }

  // Authorized-assets registry.
  const assets = new IncrementalMerkleTree(depth);
  assets.insert(assetsLeafHash(assetId, sacAddress, decimals, perTxLimitRaw));

  const kView = 5n;
  const auditorPk = auditorPkFromKey(kView).pk;

  const changeNote: Note | undefined = opts.noChange
    ? undefined
    : { assetId, value: changeValue, ownerPk, rho: 3002n, rNote: 4002n };

  const { witness } = buildUnshieldWitness({
    inNote,
    ownerSk,
    inPath,
    anchorRoot: anchor.root(),
    frozenLow,
    frozenPath: frozen.inclusionPath(0),
    frozenRoot: frozen.root(),
    recipient,
    kycPath: kyc.inclusionPath(0),
    kycRoot: kyc.root(),
    sanctionLow,
    sanctionPath: sanc.inclusionPath(0),
    sanctionRoot: sanc.root(),
    amount,
    changeNote,
    sacAddress,
    decimals,
    perTxLimitRaw,
    assetsPath: assets.inclusionPath(0),
    assetsRoot: assets.root(),
    oldFrontier: anchor.frontier(),
    nextIndex: anchor.size,
    fee,
    auditorPk,
    kView,
    kPair: 7n,
    rhoEncAuditor: 5101n,
    rhoEncRecipient: 6101n,
  });

  return { witness, cmIn };
}
