// Full transfer-circuit acceptance gate (FIN-006). Builds a complete, consistent
// 2-in / 2-out transfer witness with the SDK witness builder
// (sdk/src/witness.ts), drives circuits/test/transfer/transfer_test.circom
// (Transfer at depth 6), and asserts the CLAUDE.md test rule: a valid witness is
// accepted, and >= 1 failing witness per constraint class is rejected:
//   - unbalanced value (per-asset conservation, invariant #3),
//   - bad Merkle path (input inclusion under anchor_root),
//   - missing auditor ciphertext (invariant #5),
//   - frozen note (frozen-set non-membership, invariant #14),
//   - over-limit value (assets registry per-tx limit, invariant #17),
//   - tampered new_root (frontier transition, invariant #12),
//   - wrong spending key (ownership / nullifier, invariant #4).
// Run: `npx tsx scripts/test-transfer-witness.ts` (npm run transfer:witness).

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

import {
  IncrementalMerkleTree,
  assetsLeafHash,
  imtLeafHash,
} from '../sdk/src/merkle.js';
import { commitNote, deriveOwnerPk } from '../sdk/src/note.js';
import { auditorPkFromKey } from '../sdk/src/encrypt.js';
import { poseidonBLS, FR_MODULUS } from '../sdk/src/poseidon.js';
import { buildTransferWitness, type ImtLowLeaf } from '../sdk/src/witness.js';
import type { CircomWitness } from '../sdk/src/witness.js';
import type { Fr, MerklePath, Note, OwnerSk } from '../sdk/src/types.js';

const DEPTH = 6;
const NAME = 'transfer_test';
const BUILD = 'circuits/build/transfer_test';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'pipe'] });
}
sh(
  `circom circuits/test/transfer/${NAME}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`,
);

// Use `snarkjs wtns calculate` (not circom's generate_witness.js, which is a
// CommonJS script that fails under this package's `"type": "module"`). Witness
// calculation throws iff a constraint is violated.
function witnessOk(input: CircomWitness): boolean {
  writeFileSync(`${BUILD}/${NAME}.input.json`, JSON.stringify(input));
  try {
    sh(
      `npx --no-install snarkjs wtns calculate ${BUILD}/${NAME}_js/${NAME}.wasm ${BUILD}/${NAME}.input.json ${BUILD}/${NAME}.wtns`,
    );
    return true;
  } catch {
    return false;
  }
}

let failed = false;
function expect(label: string, ok: boolean): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
}

// ---------------------------------------------------------------------------
// Scenario construction: build all five trees the circuit anchors to (anchor,
// KYC, sanctions IMT, frozen IMT, assets registry) and assemble the witness.
// ---------------------------------------------------------------------------
const ownerPkOf = (sk: bigint): Fr => deriveOwnerPk(sk as unknown as OwnerSk);
const MAX = FR_MODULUS - 1n; // IMT tail sentinel: a value above every real entry.

interface ImtSpec {
  value: Fr;
  nextIndex: Fr;
  nextValue: Fr;
}
function buildImt(specs: ImtSpec[]): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(DEPTH);
  specs.forEach((l) => t.insert(imtLeafHash(l.value, l.nextIndex, l.nextValue)));
  return t;
}

interface ScenarioOpts {
  outVals?: [Fr, Fr];
  perTxLimitRaw?: Fr;
  frozenMemberInput0?: boolean;
}

function buildScenario(opts: ScenarioOpts = {}): CircomWitness {
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

  // Targets must be in the open interval (0, MAX) for the head-bracket to hold.
  for (const t of [recipientPk, cmIn[0], cmIn[1]]) {
    if (t <= 0n || t >= MAX) throw new Error('demo target outside (0, MAX); adjust seeds');
  }

  // Anchor commitment tree: the two spent notes are already inserted.
  const anchor = new IncrementalMerkleTree(DEPTH);
  anchor.insert(cmIn[0]);
  anchor.insert(cmIn[1]);
  const anchorRoot = anchor.root();
  const oldFrontier = anchor.frontier();
  const nextIndex = anchor.size; // 2
  const inPaths: [MerklePath, MerklePath] = [anchor.inclusionPath(0), anchor.inclusionPath(1)];

  // KYC tree: the recipient pk is enrolled (kyc_leaf == out_owner_pk[0]).
  const kyc = new IncrementalMerkleTree(DEPTH);
  kyc.insert(recipientPk);
  const kycRoot = kyc.root();
  const kycPath = kyc.inclusionPath(0);

  // Sanctions IMT: head {0 -> MAX} brackets the recipient pk (absent).
  const sanc = buildImt([
    { value: 0n, nextIndex: 1n, nextValue: MAX },
    { value: MAX, nextIndex: 0n, nextValue: 0n },
  ]);
  const sanctionRoot = sanc.root();
  const sanctionLow: ImtLowLeaf = { value: 0n, nextIndex: 1n, nextValue: MAX };
  const sanctionPath = sanc.inclusionPath(0);

  // Frozen IMT.
  let frozenTree: IncrementalMerkleTree;
  let frozenLow: [ImtLowLeaf, ImtLowLeaf];
  let frozenPaths: [MerklePath, MerklePath];
  if (opts.frozenMemberInput0) {
    // Model cm_in[0] as a MEMBER of the frozen set: the sorted list 0 < cmIn0 <
    // MAX makes cmIn0 a node, so non-membership of cmIn0 is unprovable (its only
    // candidate low leaf has next_value == cmIn0, so target < next_value fails).
    frozenTree = buildImt([
      { value: 0n, nextIndex: 1n, nextValue: cmIn[0] },
      { value: cmIn[0], nextIndex: 2n, nextValue: MAX },
      { value: MAX, nextIndex: 0n, nextValue: 0n },
    ]);
    // input 0: head leaf (cannot bracket the member) -> rejection.
    const low0: ImtLowLeaf = { value: 0n, nextIndex: 1n, nextValue: cmIn[0] };
    // input 1: bracket cm_in[1] correctly so ONLY input 0 fails.
    let low1: ImtLowLeaf;
    let path1: MerklePath;
    if (cmIn[1] < cmIn[0]) {
      low1 = { value: 0n, nextIndex: 1n, nextValue: cmIn[0] };
      path1 = frozenTree.inclusionPath(0);
    } else {
      low1 = { value: cmIn[0], nextIndex: 2n, nextValue: MAX };
      path1 = frozenTree.inclusionPath(1);
    }
    frozenLow = [low0, low1];
    frozenPaths = [frozenTree.inclusionPath(0), path1];
  } else {
    frozenTree = buildImt([
      { value: 0n, nextIndex: 1n, nextValue: MAX },
      { value: MAX, nextIndex: 0n, nextValue: 0n },
    ]);
    const low: ImtLowLeaf = { value: 0n, nextIndex: 1n, nextValue: MAX };
    frozenLow = [low, low];
    frozenPaths = [frozenTree.inclusionPath(0), frozenTree.inclusionPath(0)];
  }
  const frozenRoot = frozenTree.root();

  // Authorized-assets registry: a single leaf for this asset.
  const assets = new IncrementalMerkleTree(DEPTH);
  assets.insert(assetsLeafHash(assetId, sacAddress, decimals, perTxLimitRaw));
  const assetsRoot = assets.root();
  const assetsPath = assets.inclusionPath(0);

  // Encryption keying.
  const kView = 5n;
  const auditorPk = auditorPkFromKey(kView).pk;

  const { witness } = buildTransferWitness({
    ownerSk,
    inNotes,
    inPaths,
    anchorRoot,
    outNotes,
    kycLeaf: recipientPk,
    kycPath,
    kycRoot,
    sanctionLow,
    sanctionPath,
    sanctionRoot,
    frozenLow,
    frozenPaths,
    frozenRoot,
    sacAddress,
    decimals,
    perTxLimitRaw,
    assetsPath,
    assetsRoot,
    oldFrontier,
    nextIndex,
    fee: 0n,
    auditorPk,
    kView,
    kPair: [7n, 11n],
    rhoEncAuditor: [5101n, 5102n],
    rhoEncRecipient: [6101n, 6102n],
  });
  return witness;
}

/** Deep-clone a witness record (all values are JSON-safe strings/arrays). */
function clone(w: CircomWitness): CircomWitness {
  return JSON.parse(JSON.stringify(w)) as CircomWitness;
}

// ---------------------------------------------------------------------------
// Positive case: a fully consistent witness MUST satisfy every constraint.
// ---------------------------------------------------------------------------
const pass = buildScenario();
expect('valid 2-in/2-out transfer witness accepted', witnessOk(pass) === true);

// ---------------------------------------------------------------------------
// Negative cases: one per constraint class, each MUST be rejected.
// ---------------------------------------------------------------------------

// 1. Per-asset conservation (#3): outputs sum to 1001 != inputs 1000.
expect(
  'unbalanced value rejected (conservation #3)',
  witnessOk(buildScenario({ outVals: [700n, 301n] })) === false,
);

// 2. Input inclusion: tamper a sibling on input 0's Merkle path.
{
  const w = clone(pass);
  const paths = w.in_path_elements as string[][];
  paths[0][0] = (BigInt(paths[0][0]) + 1n).toString();
  expect('bad Merkle path rejected (input inclusion)', witnessOk(w) === false);
}

// 3. Mandatory auditor ciphertext (#5): zero out output 0's auditor ciphertext.
{
  const w = clone(pass);
  (w.c_auditor as string[][])[0] = ['0', '0', '0', '0', '0'];
  expect('missing auditor ciphertext rejected (invariant #5)', witnessOk(w) === false);
}

// 4. Frozen-set non-membership (#14): spend a note that IS in the frozen set.
expect(
  'frozen note rejected (frozen non-membership #14)',
  witnessOk(buildScenario({ frozenMemberInput0: true })) === false,
);

// 5. Per-tx limit (#17): output value 700 exceeds a per_tx_limit_raw of 500.
expect(
  'over-limit value rejected (assets per-tx limit #17)',
  witnessOk(buildScenario({ perTxLimitRaw: 500n })) === false,
);

// 6. Frontier transition (#12): tamper the public new_root.
{
  const w = clone(pass);
  w.new_root = (BigInt(w.new_root as string) + 1n).toString();
  expect('tampered new_root rejected (frontier transition #12)', witnessOk(w) === false);
}

// 7. Ownership / nullifier (#4): wrong spending key (owner_pk != Poseidon(sk)).
{
  const w = clone(pass);
  w.owner_sk = '43';
  expect('wrong spending key rejected (ownership/nullifier #4)', witnessOk(w) === false);
}

if (failed) {
  console.error('\nTRANSFER WITNESS GATE FAILED - a constraint is missing or the SDK builder drifted.');
  process.exit(1);
}
console.log(
  '\nTRANSFER WITNESS OK - valid witness accepted; every constraint class rejects a bad witness.',
);
