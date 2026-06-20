// Demo compliance-state gate (FIN-015).
//
// Asserts the mock-KYC-enrollment admin state is internally consistent and leaks
// no secret: every enrolled account proves membership in kyc_root, a non-enrolled
// account is absent (the gate actually gates), each asset proves membership in
// assets_root, auditor_pk = Poseidon(k_view), the sanction/frozen sets are empty,
// and the serialized PUBLIC state contains no owner_sk / k_view (invariant #8).
//
// Pure SDK computation — no chain, no ceremony. Run: npm run demo:state

import {
  assetsLeafHash,
  emptyTreeZeros,
  verifyInclusionPath,
} from '../sdk/src/merkle.js';
import { deriveOwnerPk } from '../sdk/src/note.js';
import { poseidonBLS } from '../sdk/src/poseidon.js';
import type { OwnerSk } from '../sdk/src/types.js';

import {
  buildDemoComplianceState,
  toPublicState,
  verifyAbsent,
  verifyEnrolled,
  DEMO_AUDITOR_VIEW_KEY,
  DEMO_OUTSIDER,
} from './lib/demo-state.js';

let failed = false;
function expect(label: string, ok: boolean): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
}

const state = buildDemoComplianceState(); // D = 20

// 1. Every enrolled account proves membership against the final kyc_root.
for (const acc of state.accounts) {
  expect(`KYC membership verifies: ${acc.label}`, verifyEnrolled(state, acc));
}

// 2. A non-enrolled account cannot prove KYC membership: it is not in the enrolled
//    set, and it does not verify against kyc_root via ANY enrolled account's path
//    (so it cannot borrow a valid path) — the gate genuinely gates.
const outsiderPk = deriveOwnerPk(DEMO_OUTSIDER.ownerSk as unknown as OwnerSk);
expect(
  'unenrolled account is absent from the enrolled set',
  !state.accounts.some((a) => a.ownerPk === outsiderPk),
);
expect(
  'unenrolled account does not verify against kyc_root',
  !state.accounts.some((a) => verifyInclusionPath(outsiderPk, a.kycPath, state.kycRoot)),
);

// 3. auditor_pk == Poseidon(k_view) (bound in-circuit, matched by the contract).
expect('auditor_pk == Poseidon(k_view)', state.auditorPk === poseidonBLS([DEMO_AUDITOR_VIEW_KEY]));

// 4. Each asset proves membership against assets_root (self-binding asset_id).
for (const a of state.assets) {
  const leaf = assetsLeafHash(a.assetId, BigInt(a.sacAddress), BigInt(a.decimals), a.perTxLimitRaw);
  expect(`assets membership verifies: ${a.label}`, verifyInclusionPath(leaf, a.assetsPath, state.assetsRoot));
}

// 5. NON-membership actually VERIFIES: a real enrolled owner_pk is provably ABSENT
//    from the empty sanctions AND frozen sets (constructs the in-circuit gadget's
//    proof, not just a root comparison), and fails against a wrong root.
const target = state.accounts[0]!.ownerPk;
expect('sanctions non-membership verifies (real target absent)', verifyAbsent(target, state.sanctionRoot, state.sanctionLowPath));
expect('frozen non-membership verifies (real target absent)', verifyAbsent(target, state.frozenRoot, state.frozenLowPath));
expect('non-membership FAILS against a wrong root', !verifyAbsent(target, state.kycRoot, state.sanctionLowPath));

// 6. Empty commitment-tree seed equals the canonical SDK empty-tree zeros — the
//    convention the contract genesis (`init`) + the first transfer's `old_frontier`
//    must mirror (invariant #12). Length-only would pass for any 20-element array.
const zeros = emptyTreeZeros(state.treeDepth);
expect(
  'initial_frontier == emptyTreeZeros[0..D-1]',
  state.initialFrontier.length === state.treeDepth && state.initialFrontier.every((f, i) => f === zeros[i]),
);
expect('initial_root == emptyTreeZeros[D]', state.initialRoot === zeros[state.treeDepth]);

// 7. The serialized PUBLIC state leaks no secret (invariant #8). Exhaustive
//    key-allowlist on EVERY branch (not a denylist, and stronger than a substring
//    value-scan which false-positives on short secrets inside large field decimals):
//    a serialized secret would have to live under an unexpected key, which fails here.
const pub = toPublicState(state) as {
  roots: Record<string, unknown>;
  accounts: Record<string, unknown>[];
  assets: Record<string, unknown>[];
  [k: string]: unknown;
};
const keysOf = (o: Record<string, unknown>): string => Object.keys(o).sort().join(',');
expect(
  'top-level keys are exactly the public set',
  keysOf(pub) === 'accounts,assets,auditorPk,initialFrontier,roots,treeDepth',
);
expect('roots keys are exactly the five public roots', keysOf(pub.roots) === 'assetsRoot,frozenRoot,initialRoot,kycRoot,sanctionRoot');
expect('each account exposes only {label, ownerPk, kycLeafIndex}', pub.accounts.every((a) => keysOf(a) === 'kycLeafIndex,label,ownerPk'));
expect(
  'each asset exposes only public metadata (no secret field)',
  pub.assets.every((a) => keysOf(a) === 'assetId,assetsLeafIndex,decimals,label,perTxLimitRaw,sacAddress'),
);

if (failed) {
  console.error('\nDEMO STATE GATE FAILED — enrollment is inconsistent or leaks a secret.');
  process.exit(1);
}
console.log('\nDEMO STATE OK — KYC enrollment consistent, gate gates, no secret leaked.');
