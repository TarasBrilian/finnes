// Regulator disclosure of the PARTIAL unshield's change note (FIN-026 1-insert).
//
// The exact-spend unshield had no change note (all-zero ciphertexts). The partial
// unshield mints a change note that — like every output note — carries a MANDATORY
// auditor ciphertext (invariant #5). This decrypts it from the on-chain
// `c_auditor` (in setup/build/unshield2-args.json) to full plaintext, proving the
// auditor sees the change leg even when the transparent leg is public.
//
// SECURITY (invariant #8): k_view is the AUDITOR secret. Run:
//   npx tsx scripts/disclose-partial-unshield-live.ts

import { readFileSync } from 'node:fs';

import { discloseNote } from '../sdk/src/disclose.js';
import { DEMO_AUDITOR_VIEW_KEY, buildDemoComplianceState } from './lib/demo-state.js';

const args = JSON.parse(readFileSync('setup/build/unshield2-args.json', 'utf8')) as {
  pi: { cm_change_0: string; amount: string; c_auditor: string[] };
};

const st = buildDemoComplianceState(20);
const labelByPk = new Map(st.accounts.map((a) => [a.ownerPk, a.label] as const));

const cmChange = BigInt('0x' + args.pi.cm_change_0);
if (cmChange === 0n) {
  console.error('FAIL: cm_change_0 == 0 — this is an exact spend, not the 1-insert partial unshield');
  process.exit(1);
}

const disclosed = discloseNote(
  { commitment: cmChange, cAuditor: { fields: args.pi.c_auditor.map((h) => BigInt('0x' + h)) } },
  DEMO_AUDITOR_VIEW_KEY,
  {
    asset: (id) => {
      const a = st.assets.find((x) => x.assetId === id);
      return a ? { label: a.label, decimals: a.decimals } : undefined;
    },
    party: (pk) => labelByPk.get(pk),
  },
  'change',
);

console.log('REGULATOR DISCLOSURE — partial unshield change note (on-chain)\n');
console.log('  transparent leg (public):', BigInt('0x' + args.pi.amount).toString(), 'raw left the shielded domain');
console.log('  change note (decrypted)  :', disclosed.value.toString(), 'raw ·', disclosed.assetLabel ?? disclosed.assetId.toString(), '·', disclosed.party ?? ('0x' + disclosed.ownerPk.toString(16).slice(0, 12)));

const okValue = disclosed.value === 500n;
const okOwner = labelByPk.has(disclosed.ownerPk);
console.log(`\n  checks: change==500 ${okValue ? 'PASS' : 'FAIL'} · owner enrolled ${okOwner ? 'PASS' : 'FAIL'} · in-range ${disclosed.valueInRange ? 'PASS' : 'FAIL'}`);
if (!okValue || !okOwner || !disclosed.valueInRange) process.exit(1);
