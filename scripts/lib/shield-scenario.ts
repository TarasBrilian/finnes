// Shared demo-scenario builder for the shield (transparent -> shielded) circuit.
//
// Constructs a complete, consistent 1-output shield witness by building the two
// Merkle structures the circuit anchors to (depositor KYC tree, assets registry)
// and calling the SDK witness builder. Depth-parametric so the SAME scenario
// drives both the fast witness-acceptance gate (depth 6,
// scripts/test-shield-witness.ts) and the end-to-end prove/verify against the
// depth-4 demo artifacts (scripts/test-prove-shield.ts).
//
// SECURITY (invariant #8): the returned witness embeds demo secrets. These are
// throwaway constants for tests, never real keys; do not reuse them.

import { IncrementalMerkleTree, assetsLeafHash } from '../../sdk/src/merkle.js';
import { deriveOwnerPk } from '../../sdk/src/note.js';
import { auditorPkFromKey } from '../../sdk/src/encrypt.js';
import { poseidonBLS } from '../../sdk/src/poseidon.js';
import { buildShieldWitness } from '../../sdk/src/witness.js';
import type { CircomWitness } from '../../sdk/src/witness.js';
import type { Fr, Note, OwnerSk } from '../../sdk/src/types.js';

export interface ShieldScenarioOpts {
  /** Per-asset limit baked into the registry leaf. Default 10_000_000. */
  perTxLimitRaw?: Fr;
  /** Deposited amount (also the minted note value). Default 700. */
  amount?: Fr;
}

export interface ShieldScenario {
  /** Complete circom input record for `Shield(depth, 5, 5)`. */
  witness: CircomWitness;
}

/**
 * Build a valid (or, via `opts`, a deliberately invalid) shield witness at the
 * given tree depth. The default produces a fully consistent, accepting witness.
 */
export function buildShieldScenario(depth: number, opts: ShieldScenarioOpts = {}): ShieldScenario {
  const perTxLimitRaw = opts.perTxLimitRaw ?? 10_000_000n;
  const amount = opts.amount ?? 700n;

  // Asset (asset_id self-binds to Poseidon(sac_address)).
  const sacAddress = 777n;
  const assetId = poseidonBLS([sacAddress]);
  const decimals = 7n;

  // Owner of the minted note (must be KYC-approved to shield).
  const ownerPk = deriveOwnerPk(99n as unknown as OwnerSk);
  const outNote: Note = { assetId, value: amount, ownerPk, rho: 3001n, rNote: 4001n };

  // KYC tree: the owner pk is enrolled.
  const kyc = new IncrementalMerkleTree(depth);
  kyc.insert(ownerPk);

  // Authorized-assets registry: a single leaf for this asset.
  const assets = new IncrementalMerkleTree(depth);
  assets.insert(assetsLeafHash(assetId, sacAddress, decimals, perTxLimitRaw));

  // Empty commitment tree: shield inserts the first leaf at index 0.
  const anchor = new IncrementalMerkleTree(depth);

  const kView = 5n;
  const auditorPk = auditorPkFromKey(kView).pk;

  const { witness } = buildShieldWitness({
    outNote,
    kycPath: kyc.inclusionPath(0),
    kycRoot: kyc.root(),
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
    kPair: 7n,
    rhoEncAuditor: 5101n,
    rhoEncRecipient: 6101n,
  });

  return { witness };
}
