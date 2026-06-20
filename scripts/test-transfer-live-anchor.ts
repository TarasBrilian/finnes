// Anchor-parity gate for the FIN-025 live transfer — proves the off-chain indexer
// stand-in (scripts/lib/live-notes.ts) reconstructs the SAME tree the deployed
// contract actually stored, so the transfer's anchor_root / old_frontier /
// next_index will match on-chain state (lib.rs is_recent_root / check_old_frontier
// / check_next_index). This is the "does it match FIN-025 + live state" regression.
//
// It checks against setup/build/shield-args.json (the genesis shield's verified
// on-chain public inputs) WITHOUT needing the Railway zkey or any chain access:
//   - the 1-note reconstructed root == the on-chain genesis `new_root`,
//   - shield #2's `old_frontier` == the on-chain post-genesis `new_frontier`,
//   - the empty-tree seed == the genesis `old_frontier` (init parity),
//   - the transfer anchors to the 2-note root at next_index 2,
//   - every compliance root in the witness is the LIVE init root (frozen STRICT),
//   - output note 0 = recipient (Bank B), note 1 = change (Bank A).
//
// Run: npm run transfer:live:anchor

import { readFileSync } from 'node:fs';

import { IncrementalMerkleTree } from '../sdk/src/merkle.js';
import { commitNote } from '../sdk/src/note.js';
import {
  DEPTH,
  GENESIS_NOTE,
  LIVE_STATE,
  reconstructAnchorTree,
  toCmHex,
} from './lib/live-notes.js';
import { buildLiveTransferWitness } from './lib/transfer-live.js';

const args = JSON.parse(readFileSync('setup/build/shield-args.json', 'utf8')) as {
  pi: { cm_out_0: string; new_root: string; old_frontier: string[]; new_frontier: string[] };
};
const onchainGenesisCm = args.pi.cm_out_0;
const onchainPostGenesisRoot = args.pi.new_root;
const onchainGenesisOldFrontier = args.pi.old_frontier;
const onchainPostGenesisFrontier = args.pi.new_frontier;

let fail = false;
const ok = (label: string, cond: boolean): void => {
  if (!cond) fail = true;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`);
};

// Indexer parity: the reconstructed genesis commitment equals the on-chain one.
ok(
  `indexer parity: commitNote(GENESIS_NOTE) == on-chain cm_out_0 (${onchainGenesisCm.slice(0, 12)}…)`,
  toCmHex(commitNote(GENESIS_NOTE)) === onchainGenesisCm,
);

// Step 2 tree mechanics: a 1-note reconstruction must reproduce the on-chain root
// AND the on-chain post-genesis frontier (so shield #2 passes check_old_frontier).
const t1 = new IncrementalMerkleTree(DEPTH);
t1.insert(commitNote(GENESIS_NOTE));
ok(
  `tree mechanics: 1-note reconstructed root == on-chain genesis new_root (${onchainPostGenesisRoot.slice(0, 10)}…)`,
  toCmHex(t1.root()) === onchainPostGenesisRoot,
);
ok(
  'step1: shield #2 old_frontier == on-chain post-genesis new_frontier',
  JSON.stringify(t1.frontier().map(toCmHex)) === JSON.stringify(onchainPostGenesisFrontier),
);

// Init seed parity: the genesis on-chain old_frontier is the empty-tree frontier.
const empty = new IncrementalMerkleTree(DEPTH);
ok(
  'init parity: genesis old_frontier on-chain == empty-tree frontier (init seed)',
  JSON.stringify(empty.frontier().map(toCmHex)) === JSON.stringify(onchainGenesisOldFrontier),
);

// Step 3 anchor: the transfer anchors to the 2-note tree at next_index 2.
const { meta, witness } = buildLiveTransferWitness();
const w = witness as Record<string, string | string[] | string[][]>;
ok(
  'step3: transfer anchor_root == reconstructed 2-note root',
  toCmHex(meta.anchorRoot) === toCmHex(reconstructAnchorTree().root()),
);
ok('step3: transfer next_index == 2 (leaf_count after 2 shields)', meta.nextIndex === 2);

// Live-root parity: the witness anchors to the init roots, not a self-built set.
const st = LIVE_STATE;
ok('roots: kyc_root == init kycRoot', w.kyc_root === st.kycRoot.toString());
ok('roots: sanction_root == init sanctionRoot', w.sanction_root === st.sanctionRoot.toString());
ok('roots: assets_root == init assetsRoot', w.assets_root === st.assetsRoot.toString());
ok('roots: frozen_root == init frozenRoot (STRICT on-chain)', w.frozen_root === st.frozenRoot.toString());
ok('roots: auditor_pk == init auditorPk', w.auditor_pk === st.auditorPk.toString());

// recipient + change semantics (FIN-025: "two shielded notes → recipient + change").
const owners = w.out_owner_pk as string[];
ok(
  'outputs: note0 owner == recipient (Bank B), note1 owner == sender/change (Bank A)',
  owners[0] === st.accounts[1]!.ownerPk.toString() && owners[1] === st.accounts[0]!.ownerPk.toString(),
);

console.log(
  '\n' + (fail ? 'ANCHOR PARITY FAILED.' : 'ANCHOR PARITY PASSED — reconstruction matches on-chain state; FIN-025 steps 1-3 wired correctly.'),
);
process.exit(fail ? 1 : 0);
