// Regulator disclosure of the REAL on-chain confidential transfer (FIN-025 capstone).
//
// Takes the two auditor ciphertexts + commitments AS SUBMITTED on-chain (from
// setup/build/transfer-args.json — the exact public inputs the verified proof
// bound) and decrypts BOTH output notes with the auditor view key: the recipient
// note (Bank B, 1500) and the change note (Bank A, 500). The public saw two opaque
// commitments + two nullifiers; the regulator sees amount/asset/party for each —
// invariant #5 proven end-to-end on live transfer data.
//
// SECURITY (invariant #8): k_view is the AUDITOR secret; runs only in the auditor
// zone. Run: npx tsx scripts/disclose-transfer-live.ts

import { readFileSync } from 'node:fs';

import { discloseNote } from '../sdk/src/disclose.js';
import { DEMO_AUDITOR_VIEW_KEY, buildDemoComplianceState } from './lib/demo-state.js';

const args = JSON.parse(readFileSync('setup/build/transfer-args.json', 'utf8')) as {
  pi: { cm_out_0: string; cm_out_1: string; c_auditor: string[] };
};

const st = buildDemoComplianceState(20);
const labelByPk = new Map(st.accounts.map((a) => [a.ownerPk, a.label] as const));
const resolvers = {
  asset: (id: bigint) => {
    const a = st.assets.find((x) => x.assetId === id);
    return a ? { label: a.label, decimals: a.decimals } : undefined;
  },
  party: (pk: bigint) => labelByPk.get(pk),
};

// c_auditor is the concatenated 2·K_a vector: note 0 = fields[0..4], note 1 = [5..9].
const cAud = args.pi.c_auditor.map((h) => BigInt('0x' + h));
const outputs = [
  { role: 'recipient' as const, cm: BigInt('0x' + args.pi.cm_out_0), ct: cAud.slice(0, 5) },
  { role: 'change' as const, cm: BigInt('0x' + args.pi.cm_out_1), ct: cAud.slice(5, 10) },
];

console.log('REGULATOR DISCLOSURE — confidential transfer (on-chain)\n');
let failed = false;
const disclosedValues: bigint[] = [];
for (const o of outputs) {
  const d = discloseNote(
    { commitment: o.cm, cAuditor: { fields: o.ct } },
    DEMO_AUDITOR_VIEW_KEY,
    resolvers,
    'output',
  );
  disclosedValues.push(d.value);
  const party = d.party ?? '0x' + d.ownerPk.toString(16).slice(0, 12);
  console.log(`  ${o.role.padEnd(9)}: value ${d.value.toString().padStart(5)} raw · ${d.assetLabel ?? d.assetId.toString()} · ${party}`);
  if (!d.valueInRange) {
    console.log('    ^ value OUT OF RANGE — wrong view key (honest failure, never a faked reveal)');
    failed = true;
  }
}

// Acceptance: recipient 1500 + change 500 == 2000 (the value of the spent inputs).
const sum = disclosedValues.reduce((a, b) => a + b, 0n);
const okSum = sum === 2000n;
console.log(`\n  checks: Σout==Σin(2000) ${okSum ? 'PASS' : 'FAIL'} · both notes decrypt in-range ${failed ? 'FAIL' : 'PASS'}`);
if (!okSum || failed) process.exit(1);
