/**
 * Note encryption + scanning round-trips (FIN-004).
 *
 * Asserts the additive-Poseidon-keystream encryptor is internally coherent:
 * auditor/recipient encrypt→decrypt round-trips, a wrong key recovers garbage,
 * and wallet scanning discovers an owned note only when the commitment re-derives.
 * The cross-surface circuit↔SDK parity (SDK ciphertext satisfies the in-circuit
 * binding) is `scripts/test-enc-parity.ts`.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  auditorPkFromKey,
  decryptAuditor,
  decryptRecipient,
  encryptToAuditor,
  encryptToRecipient,
  K_A,
  K_R,
} from '../src/encrypt.js';
import { poseidonBLS } from '../src/poseidon.js';
import { commitNote, deriveOwnerPk } from '../src/note.js';
import { scanForOwnedNotes } from '../src/scan.js';
import type { Note, OwnerSk } from '../src/types.js';

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

test('auditor_pk = Poseidon(k_view)', () => {
  assert.equal(auditorPkFromKey(kView).pk, poseidonBLS([kView]));
});

test('auditor encrypt→decrypt round-trips (value, asset_id, owner_pk, rho)', () => {
  const c = encryptToAuditor(note, kView, { rhoEnc });
  assert.equal(c.fields.length, K_A);
  assert.equal(c.fields[0], rhoEnc, 'slot 0 is the published nonce');
  const pt = decryptAuditor(c, kView);
  assert.equal(pt.value, note.value);
  assert.equal(pt.assetId, note.assetId);
  assert.equal(pt.ownerPk, note.ownerPk);
  assert.equal(pt.rho, note.rho);
});

test('auditor decrypt with the wrong key does NOT recover the plaintext', () => {
  const c = encryptToAuditor(note, kView, { rhoEnc });
  const pt = decryptAuditor(c, kView + 1n);
  assert.notEqual(pt.value, note.value);
});

test('recipient encrypt→decrypt round-trips (value, asset_id, rho, r_note)', () => {
  const c = encryptToRecipient(note, kPair, { rhoEnc });
  assert.equal(c.fields.length, K_R);
  const pt = decryptRecipient(c, kPair);
  assert.equal(pt.value, note.value);
  assert.equal(pt.assetId, note.assetId);
  assert.equal(pt.rho, note.rho);
  assert.equal(pt.rNote, note.rNote);
});

test('scan discovers an owned note via commitment re-derivation', () => {
  const ownerSk = 314159n as OwnerSk;
  const ownerPk = deriveOwnerPk(ownerSk);
  // The note as actually sent: owner_pk is the recipient's derived key.
  const sent: Note = { ...note, ownerPk };
  const cRecipient = encryptToRecipient(sent, kPair, { rhoEnc });
  const commitment = commitNote(sent);

  const found = scanForOwnedNotes(
    [{ commitment, cRecipient }],
    { ownerSk, recipientKey: kPair, leafIndex: 3 },
  );
  assert.equal(found.length, 1);
  assert.equal(found[0]!.commitment, commitment);
  assert.equal(found[0]!.note.value, sent.value);
  assert.equal(found[0]!.leafIndex, 3);
});

test('scan rejects a ciphertext under the wrong pairwise key (no false positive)', () => {
  const ownerSk = 314159n as OwnerSk;
  const ownerPk = deriveOwnerPk(ownerSk);
  const sent: Note = { ...note, ownerPk };
  const cRecipient = encryptToRecipient(sent, kPair, { rhoEnc });
  const commitment = commitNote(sent);

  const found = scanForOwnedNotes(
    [{ commitment, cRecipient }],
    { ownerSk, recipientKey: kPair + 1n },
  );
  assert.equal(found.length, 0);
});
