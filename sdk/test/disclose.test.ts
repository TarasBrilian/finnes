/**
 * Auditor disclosure + SAC-address encoding (FIN-014).
 *
 * Asserts the regulator view: an auditor holding `k_view` decrypts a whole
 * transaction's MANDATORY auditor ciphertexts to full plaintext (amount, asset,
 * party), with the wrong key recovering garbage, the `unshield` "no change"
 * sentinel skipped, and resolver labels attached. Also pins the SAC-address →
 * `Fr` encoding so `deriveAssetId` agrees with the scenario fixtures.
 *
 * The cross-surface circuit↔SDK auditor-ciphertext parity is
 * `scripts/test-enc-parity.ts`; this file is the SDK-internal disclosure logic.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { encryptToAuditor } from '../src/encrypt.js';
import {
  commitNote,
  deriveAssetId,
  deriveOwnerPk,
  sacAddressToField,
} from '../src/note.js';
import { poseidonBLS } from '../src/poseidon.js';
import {
  discloseTransaction,
  formatRawAmount,
  type AuditorObservedTx,
} from '../src/disclose.js';
import { buildTransferWitness, type ImtLowLeaf } from '../src/witness.js';
import type { MerklePath, Note, OwnerSk } from '../src/types.js';

// --- a confidential transfer's two output notes (recipient + change) ----------
const kView = 424242n; // sender↔auditor shared key; auditor_pk = Poseidon(kView)

const recipientSk = 111_111n as OwnerSk;
const senderSk = 222_222n as OwnerSk;
const assetId = deriveAssetId('777'); // self-binds to Poseidon(777)

const recipientNote: Note = {
  assetId,
  value: 5_000_000n,
  ownerPk: deriveOwnerPk(recipientSk),
  rho: 0xaaa1n,
  rNote: 0xbbb1n,
};
const changeNote: Note = {
  assetId,
  value: 2_500_000n,
  ownerPk: deriveOwnerPk(senderSk),
  rho: 0xaaa2n,
  rNote: 0xbbb2n,
};

function observedTransfer(): AuditorObservedTx {
  return {
    circuit: 'transfer',
    nullifiers: [0x9991n, 0x9992n],
    outputs: [
      {
        commitment: commitNote(recipientNote),
        cAuditor: encryptToAuditor(recipientNote, kView, { rhoEnc: 7n }),
      },
      {
        commitment: commitNote(changeNote),
        cAuditor: encryptToAuditor(changeNote, kView, { rhoEnc: 8n }),
      },
    ],
  };
}

test('auditor discloses a transfer to full plaintext (amount, asset, parties)', () => {
  const disclosed = discloseTransaction(observedTransfer(), kView);

  assert.equal(disclosed.outputs.length, 2);
  assert.deepEqual(disclosed.nullifiers, [0x9991n, 0x9992n]);

  const [recip, change] = disclosed.outputs;
  // amounts
  assert.equal(recip!.value, 5_000_000n);
  assert.equal(change!.value, 2_500_000n);
  // asset identity
  assert.equal(recip!.assetId, assetId);
  assert.equal(change!.assetId, assetId);
  // parties (owner_pk) + position-derived roles
  assert.equal(recip!.ownerPk, recipientNote.ownerPk);
  assert.equal(recip!.role, 'recipient');
  assert.equal(change!.ownerPk, changeNote.ownerPk);
  assert.equal(change!.role, 'change');
  // genuine notes are in 64-bit range
  assert.ok(recip!.valueInRange && change!.valueInRange);
});

test('disclosure attaches resolver labels (asset + party)', () => {
  const parties = new Map([
    [recipientNote.ownerPk, 'Bank B'],
    [changeNote.ownerPk, 'Bank A'],
  ]);
  const disclosed = discloseTransaction(observedTransfer(), kView, {
    asset: (a) => (a === assetId ? { label: 'TBOND-2031', decimals: 7 } : undefined),
    party: (pk) => parties.get(pk),
  });

  const [recip, change] = disclosed.outputs;
  assert.equal(recip!.assetLabel, 'TBOND-2031');
  assert.equal(recip!.decimals, 7);
  assert.equal(recip!.party, 'Bank B');
  assert.equal(change!.party, 'Bank A');
  assert.equal(formatRawAmount(recip!.value, recip!.decimals), '0.5');
});

test('wrong view key does NOT recover the real amounts', () => {
  const disclosed = discloseTransaction(observedTransfer(), kView + 1n);
  // A foreign/garbled decrypt almost never lands on the true value...
  assert.notEqual(disclosed.outputs[0]!.value, recipientNote.value);
  // ...and is overwhelmingly out of the 64-bit note range (wrong-key signal).
  assert.equal(disclosed.outputs[0]!.valueInRange, false);
});

test('unshield "no change" sentinel output is skipped', () => {
  const tx: AuditorObservedTx = {
    circuit: 'unshield',
    nullifiers: [0x9991n],
    // cm_change_0 == 0 (no change): all-zero ciphertext, must not be disclosed.
    outputs: [{ commitment: 0n, cAuditor: { fields: [0n, 0n, 0n, 0n, 0n] } }],
  };
  const disclosed = discloseTransaction(tx, kView);
  assert.equal(disclosed.outputs.length, 0);
});

test('roles derive from the ORIGINAL output position, not a post-filter index', () => {
  // A leading sentinel must NOT re-index the surviving note: the real output at
  // original index 1 of a 2-output transfer is the change note (back to sender),
  // and must keep the 'change' role even though it is the only survivor.
  const tx: AuditorObservedTx = {
    circuit: 'transfer',
    nullifiers: [],
    outputs: [
      { commitment: 0n, cAuditor: { fields: [0n, 0n, 0n, 0n, 0n] } }, // sentinel at index 0
      {
        commitment: commitNote(changeNote),
        cAuditor: encryptToAuditor(changeNote, kView, { rhoEnc: 9n }),
      },
    ],
  };
  const disclosed = discloseTransaction(tx, kView);
  assert.equal(disclosed.outputs.length, 1);
  assert.equal(disclosed.outputs[0]!.role, 'change'); // not 'recipient', not 'output'
  assert.equal(disclosed.outputs[0]!.ownerPk, changeNote.ownerPk);
});

test('END-TO-END: auditor discloses the c_auditor that buildTransferWitness emits', () => {
  // The strongest parity: disclose the ciphertexts AS PRODUCED by the witness
  // builder (the same `c_auditor` signals the Groth16 proof binds), consumed via
  // the witness record's own signal names/shapes — not a hand-built ciphertext.
  const depth = 4;
  const path: MerklePath = {
    siblings: Array<bigint>(depth).fill(0n),
    pathBits: Array<0 | 1>(depth).fill(0),
    leafIndex: 0,
  };
  const low: ImtLowLeaf = { value: 0n, nextIndex: 0n, nextValue: 0n };
  const spendSk = 333_333n as OwnerSk;
  const inNote = (value: bigint, rho: bigint): Note => ({
    assetId,
    value,
    ownerPk: deriveOwnerPk(spendSk),
    rho,
    rNote: rho + 1n,
  });

  const { witness, derived } = buildTransferWitness({
    ownerSk: spendSk,
    inNotes: [inNote(5_000_000n, 1n), inNote(2_500_000n, 2n)],
    inPaths: [path, path],
    anchorRoot: 0n,
    outNotes: [recipientNote, changeNote],
    kycLeaf: recipientNote.ownerPk,
    kycPath: path,
    kycRoot: 0n,
    sanctionLow: low,
    sanctionPath: path,
    sanctionRoot: 0n,
    frozenLow: [low, low],
    frozenPaths: [path, path],
    frozenRoot: 0n,
    sacAddress: 777n,
    decimals: 7n,
    perTxLimitRaw: 10_000_000n,
    assetsPath: path,
    assetsRoot: 0n,
    oldFrontier: Array<bigint>(depth).fill(0n),
    nextIndex: 0,
    fee: 0n,
    auditorPk: 0n,
    kView,
    kPair: [990n, 991n],
    rhoEncAuditor: [7n, 8n],
    rhoEncRecipient: [70n, 80n],
  });

  // Reconstruct the auditor's on-chain view from the witness's PUBLIC signals.
  const cAud = witness.c_auditor as string[][];
  const tx: AuditorObservedTx = {
    circuit: 'transfer',
    nullifiers: [BigInt(witness.nf_in_0 as string), BigInt(witness.nf_in_1 as string)],
    outputs: [
      { commitment: BigInt(witness.cm_out_0 as string), cAuditor: { fields: cAud[0]!.map(BigInt) } },
      { commitment: BigInt(witness.cm_out_1 as string), cAuditor: { fields: cAud[1]!.map(BigInt) } },
    ],
  };

  const disclosed = discloseTransaction(tx, kView);
  // Recovered plaintext matches the minted output notes exactly.
  assert.equal(disclosed.outputs[0]!.value, recipientNote.value);
  assert.equal(disclosed.outputs[0]!.assetId, assetId);
  assert.equal(disclosed.outputs[0]!.ownerPk, recipientNote.ownerPk);
  assert.equal(disclosed.outputs[1]!.value, changeNote.value);
  assert.equal(disclosed.outputs[1]!.ownerPk, changeNote.ownerPk);
  // Disclosed commitments equal the builder's derived output commitments.
  assert.equal(disclosed.outputs[0]!.commitment, derived.cmOut[0]);
  assert.equal(disclosed.outputs[1]!.commitment, derived.cmOut[1]);
});

// --- SAC-address encoding (sacAddressToField / deriveAssetId) ------------------
test('sacAddressToField: field-element literal matches the scenario convention', () => {
  // scripts/lib/*-scenario.ts use sacAddress = 777n directly; deriveAssetId must agree.
  assert.equal(sacAddressToField('777'), 777n);
  assert.equal(sacAddressToField('0x309'), 777n); // 0x309 == 777
  assert.equal(deriveAssetId('777'), poseidonBLS([777n]));
});

test('sacAddressToField: throws on a real StrKey (production gap, not a silent mod-r)', () => {
  // A real C…/G… StrKey shape must FAIL LOUDLY rather than silently produce a
  // non-injective / CRC-unvalidated asset_id (FIN-014 hardening).
  assert.throws(() => sacAddressToField('C' + 'D'.repeat(55))); // 56 base32 chars
  assert.throws(() => sacAddressToField('GABC' + 'D'.repeat(52)));
});

test('sacAddressToField: rejects an unrecognised address', () => {
  assert.throws(() => sacAddressToField('not-an-address!'));
  assert.throws(() => sacAddressToField(''));
});

test('formatRawAmount: whole / zero / decimals=0 / negative edges', () => {
  assert.equal(formatRawAmount(10_000_000n, 7), '1'); // exact whole strips fraction
  assert.equal(formatRawAmount(0n, 7), '0');
  assert.equal(formatRawAmount(5_000_000n, 0), '5000000'); // decimals=0 → no fraction
  assert.equal(formatRawAmount(-500_000n, 7), '-0.05'); // negative + trailing-zero strip
});
