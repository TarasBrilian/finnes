// Regulator disclosure of the REAL on-chain shielded note (FIN-015 capstone).
//
// Takes the auditor ciphertext + commitment AS SUBMITTED on-chain (from
// setup/build/shield-args.json, the exact public inputs the verified proof bound)
// and decrypts it with the auditor view key to full plaintext — the "public sees
// an opaque commitment, the regulator sees everything" payoff. Proves invariant #5
// end-to-end against live on-chain data.
//
// SECURITY (invariant #8): k_view is the AUDITOR secret; runs only in the auditor
// zone. Run: `npx tsx scripts/disclose-shield-live.ts`.

import { readFileSync } from 'node:fs';

import { discloseNote } from '../sdk/src/disclose.js';
import { DEMO_AUDITOR_VIEW_KEY, buildDemoComplianceState } from './lib/demo-state.js';

const args = JSON.parse(readFileSync('setup/build/shield-args.json', 'utf8')) as {
  pi: { cm_out_0: string; c_auditor: string[] };
};

const cm = BigInt('0x' + args.pi.cm_out_0);
const cAuditor = args.pi.c_auditor.map((h) => BigInt('0x' + h));

const st = buildDemoComplianceState(20);
const labelByPk = new Map(st.accounts.map((a) => [a.ownerPk, a.label] as const));
const labelByAsset = new Map(st.assets.map((a) => [a.assetId, a.label] as const));

const disclosed = discloseNote(
  { commitment: cm, cAuditor: { fields: cAuditor } },
  DEMO_AUDITOR_VIEW_KEY,
  {
    asset: (id) => {
      const a = st.assets.find((x) => x.assetId === id);
      return a ? { label: a.label, decimals: a.decimals } : undefined;
    },
    party: (pk) => labelByPk.get(pk),
  },
);

console.log('REGULATOR DISCLOSURE of the on-chain shielded note');
console.log('  commitment :', '0x' + args.pi.cm_out_0);
console.log('  value      :', disclosed.value.toString(), 'raw');
console.log('  asset      :', disclosed.assetLabel ?? disclosed.assetId.toString(), `(asset_id ${disclosed.assetId.toString().slice(0, 12)}…)`);
console.log('  owner      :', disclosed.party ?? ('0x' + disclosed.ownerPk.toString(16).slice(0, 12)), `(owner_pk ${disclosed.ownerPk.toString().slice(0, 12)}…)`);
console.log('  rho        :', disclosed.rho.toString().slice(0, 16) + '…');

// Sanity: the recovered value must be the 1000 we shielded; asset must be TBOND.
const okValue = disclosed.value === 1000n;
const okAsset = labelByAsset.get(disclosed.assetId)?.startsWith('TBOND') ?? false;
const okOwner = labelByPk.has(disclosed.ownerPk);
console.log(`\n  checks: value==1000 ${okValue ? 'PASS' : 'FAIL'} · asset==TBOND ${okAsset ? 'PASS' : 'FAIL'} · owner enrolled ${okOwner ? 'PASS' : 'FAIL'}`);
if (!okValue || !okAsset || !okOwner) process.exit(1);
