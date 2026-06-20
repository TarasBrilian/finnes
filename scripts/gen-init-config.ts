// Generate the post-deploy `init` config (FIN-015).
//
// Combines the off-chain compliance state (`setup/build/demo-state.json`, from
// `npm run enroll:demo`) with the host-byte verifying keys (from the D=20
// ceremony, `setup/build/<c>/vk_<c>.json`) into the contract's `InitConfig`,
// serialized as the JSON the `stellar contract invoke ... init` CLI consumes.
//
// All values are PUBLIC (roots, auditor_pk, VKs) — no secret (invariant #8).
// `dvp` gets an EMPTY placeholder VK (its circuit is not built yet, FIN-016);
// `init` only stores the VKs, so this is fine until DvP lands.
//
// admin / issuer come from env (ADMIN_ADDRESS / ISSUER_ADDRESS); set them to the
// real Testnet accounts before running `init`. Writes setup/build/init-config.json.
//
// Run: npm run init:config

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { vkToHost, frToHex, EMPTY_HOST_VK, type HostVerifyingKey } from './lib/vk-host.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const BUILD = resolve(HERE, '../setup/build');
const STATE = resolve(BUILD, 'demo-state.json');
const OUT = resolve(BUILD, 'init-config.json');

const PLACEHOLDER_ADDR = 'G_SET_ME_TO_A_REAL_TESTNET_ACCOUNT';
const admin = process.env.ADMIN_ADDRESS ?? PLACEHOLDER_ADDR;
const issuer = process.env.ISSUER_ADDRESS ?? PLACEHOLDER_ADDR;

if (!existsSync(STATE)) {
  console.error(`MISSING ${STATE} — run 'npm run enroll:demo' first.`);
  process.exit(1);
}
const state = JSON.parse(readFileSync(STATE, 'utf8')) as {
  treeDepth: number;
  auditorPk: string;
  roots: { kycRoot: string; sanctionRoot: string; assetsRoot: string; frozenRoot: string; initialRoot: string };
  initialFrontier: string[];
};

/** Load + host-encode a circuit's VK, or the empty placeholder if absent. */
function loadVk(circuit: string): HostVerifyingKey {
  const p = resolve(BUILD, circuit, `vk_${circuit}.json`);
  if (!existsSync(p)) {
    console.warn(`  WARN: ${p} missing — using EMPTY placeholder VK for ${circuit}.`);
    return EMPTY_HOST_VK;
  }
  return vkToHost(JSON.parse(readFileSync(p, 'utf8')));
}

const vk_shield = loadVk('shield');
const vk_transfer = loadVk('transfer');
const vk_unshield = loadVk('unshield');
const vk_dvp = EMPTY_HOST_VK; // dvp.circom not built yet (FIN-016)

// --- validate the host encoding before emitting -----------------------------
let bad = false;
function check(label: string, ok: boolean): void {
  if (!ok) {
    bad = true;
    console.error(`  FAIL ${label}`);
  }
}
for (const [name, vk, nPublic] of [
  ['shield', vk_shield, 59],
  ['transfer', vk_transfer, 73],
  ['unshield', vk_unshield, 64],
] as const) {
  check(`${name}: alpha_g1 is 96 bytes`, vk.alpha_g1.length === 96 * 2);
  check(`${name}: beta/gamma/delta are 192 bytes`, [vk.beta_g2, vk.gamma_g2, vk.delta_g2].every((g) => g.length === 192 * 2));
  check(`${name}: ic has nPublic+1 = ${nPublic + 1} points`, vk.ic.length === nPublic + 1);
  check(`${name}: every ic point is 96 bytes`, vk.ic.every((p) => p.length === 96 * 2));
}
check('initial_frontier has treeDepth elements', state.initialFrontier.length === state.treeDepth);
if (bad) {
  console.error('\nInit-config validation FAILED — host encoding is malformed.');
  process.exit(1);
}

// --- assemble the InitConfig (field names match contracts/finnes types.rs) ---
const cfg = {
  admin,
  issuer_authority: issuer,
  auditor_pk: frToHex(state.auditorPk),
  kyc_root: frToHex(state.roots.kycRoot),
  sanction_root: frToHex(state.roots.sanctionRoot),
  assets_root: frToHex(state.roots.assetsRoot),
  frozen_root: frToHex(state.roots.frozenRoot),
  initial_frontier: state.initialFrontier.map((f) => frToHex(f)),
  initial_root: frToHex(state.roots.initialRoot),
  vk_shield,
  vk_transfer,
  vk_unshield,
  vk_dvp,
};

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, `${JSON.stringify({ cfg }, null, 2)}\n`);

console.log('Finnes — post-deploy init config (FIN-015)');
console.log(`  admin            : ${admin}${admin === PLACEHOLDER_ADDR ? '  <-- SET ADMIN_ADDRESS' : ''}`);
console.log(`  issuer_authority : ${issuer}${issuer === PLACEHOLDER_ADDR ? '  <-- SET ISSUER_ADDRESS' : ''}`);
console.log(`  tree depth       : ${state.treeDepth} (initial_frontier ${state.initialFrontier.length} elems)`);
console.log('  VKs (host bytes) : shield ic=' + vk_shield.ic.length + ', transfer ic=' + vk_transfer.ic.length + ', unshield ic=' + vk_unshield.ic.length + ', dvp=EMPTY');
console.log(`  wrote -> ${OUT}`);
console.log('  NEXT: deploy the contract, set ADMIN_ADDRESS/ISSUER_ADDRESS, then `npm run init`.');
