// Encryption well-formedness parity gate (FIN-004, invariant #5).
//
// Asserts the SDK encryptor (sdk/src/encrypt.ts) and the in-circuit binding
// (circuits/lib/enc_check.circom) agree: a ciphertext produced by the SDK
// satisfies the circuit constraints (witness calculation succeeds), and any
// tampering - a flipped ciphertext slot or a wrong key - is rejected. This is the
// property behind invariant #5: the prover cannot ship a value-correct commitment
// with a disagreeing/undecryptable auditor ciphertext.
// Run: `npx tsx scripts/test-enc-parity.ts`.

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

import {
  auditorPkFromKey,
  decryptAuditor,
  decryptRecipient,
  encryptToAuditor,
  encryptToRecipient,
} from '../sdk/src/encrypt.js';
import type { Note } from '../sdk/src/types.js';

const BUILD = 'circuits/build/enc';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'pipe'] });
}
function compile(name: string): void {
  sh(`circom circuits/test/enc/${name}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`);
}
function witnessOk(name: string, input: unknown): boolean {
  writeFileSync(`${BUILD}/${name}.input.json`, JSON.stringify(input));
  try {
    sh(`npx --no-install snarkjs wtns calculate ${BUILD}/${name}_js/${name}.wasm ${BUILD}/${name}.input.json ${BUILD}/${name}.wtns`);
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

// --- fixtures ----------------------------------------------------------------
const note: Note = {
  assetId: 0x1234_5678n,
  value: 9_876_543n,
  ownerPk: 0xdead_beefn,
  rho: 0x0f0f_0f0fn,
  rNote: 0x00ca_fe00n,
};
const kView = 424242n;
const kPair = 990099n;
const rhoEnc = 7n;

// =============================================================================
// Auditor ciphertext (mandatory).
// =============================================================================
compile('auditor_check');
const auditorPk = auditorPkFromKey(kView).pk;
const cAuditor = encryptToAuditor(note, kView, { rhoEnc });

function auditorInput(c: readonly bigint[], pk = auditorPk): unknown {
  return {
    auditor_pk: pk.toString(),
    c_auditor: c.map(String),
    value: note.value.toString(),
    asset_id: note.assetId.toString(),
    owner_pk: note.ownerPk.toString(),
    rho: note.rho.toString(),
    k_view: kView.toString(),
    rho_enc: rhoEnc.toString(),
  };
}

expect('auditor: SDK ciphertext satisfies circuit', witnessOk('auditor_check', auditorInput(cAuditor.fields)) === true);
expect(
  'auditor: tampered slot (value+1) rejected',
  witnessOk('auditor_check', auditorInput([cAuditor.fields[0]!, cAuditor.fields[1]! + 1n, ...cAuditor.fields.slice(2)])) === false,
);
expect(
  'auditor: wrong auditor_pk rejected',
  witnessOk('auditor_check', auditorInput(cAuditor.fields, auditorPk + 1n)) === false,
);
// SDK round-trip recovers the plaintext.
{
  const pt = decryptAuditor(cAuditor, kView);
  expect(
    'auditor: SDK decrypt round-trips',
    pt.value === note.value && pt.assetId === note.assetId && pt.ownerPk === note.ownerPk && pt.rho === note.rho,
  );
}

// =============================================================================
// Recipient ciphertext (optional; well-formedness only).
// =============================================================================
compile('recipient_check');
const cRecipient = encryptToRecipient(note, kPair, { rhoEnc });

function recipientInput(c: readonly bigint[]): unknown {
  return {
    c_recipient: c.map(String),
    value: note.value.toString(),
    asset_id: note.assetId.toString(),
    rho: note.rho.toString(),
    r_note: note.rNote.toString(),
    k_pair: kPair.toString(),
    rho_enc: rhoEnc.toString(),
  };
}

expect('recipient: SDK ciphertext satisfies circuit', witnessOk('recipient_check', recipientInput(cRecipient.fields)) === true);
expect(
  'recipient: tampered slot (r_note) rejected',
  witnessOk('recipient_check', recipientInput([...cRecipient.fields.slice(0, 4), cRecipient.fields[4]! + 1n])) === false,
);
{
  const pt = decryptRecipient(cRecipient, kPair);
  expect(
    'recipient: SDK decrypt round-trips',
    pt.value === note.value && pt.assetId === note.assetId && pt.rho === note.rho && pt.rNote === note.rNote,
  );
}

if (failed) {
  console.error('\nENC PARITY FAILED - SDK encryptor and circuit binding disagree.');
  process.exit(1);
}
console.log('\nENC PARITY OK - SDK ciphertexts satisfy the in-circuit binding; tampering rejected.');
