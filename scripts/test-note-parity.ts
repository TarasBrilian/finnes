// Note gadget parity gate (FIN-003).
//
// Asserts the circuit's note commitment / nullifier (circuits/lib/note.circom)
// equal the SDK's (sdk/src/note.ts) for shared inputs — catching any
// input-ORDERING drift between the two surfaces (the most common integration
// bug, CLAUDE.md). Run: `npx tsx scripts/test-note-parity.ts`.

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { commitNote, deriveNullifier } from '../sdk/src/note.js';
import type { Note, OwnerSk } from '../sdk/src/types.js';

const BUILD = 'circuits/build/note';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'inherit'] });
}
function symIndex(symPath: string, signal: string): number {
  for (const line of readFileSync(symPath, 'utf8').split('\n')) {
    const parts = line.split(',');
    if (parts[3] === signal) return Number(parts[1]);
  }
  throw new Error(`signal ${signal} not found in ${symPath}`);
}
function circuitOut(name: string, input: Record<string, string>, outSignal: string): bigint {
  sh(`circom circuits/test/note/${name}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`);
  const inputPath = `${BUILD}/${name}.input.json`;
  writeFileSync(inputPath, JSON.stringify(input));
  const wtns = `${BUILD}/${name}.wtns`;
  sh(`npx --no-install snarkjs wtns calculate ${BUILD}/${name}_js/${name}.wasm ${inputPath} ${wtns}`);
  const wjson = `${BUILD}/${name}.wtns.json`;
  sh(`npx --no-install snarkjs wtns export json ${wtns} ${wjson}`);
  const witness = JSON.parse(readFileSync(wjson, 'utf8')) as string[];
  return BigInt(witness[symIndex(`${BUILD}/${name}.sym`, outSignal)]!);
}

let failed = false;
function check(label: string, ok: boolean, detail = ''): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'MATCH   ' : 'MISMATCH'} ${label}${ok ? '' : `\n         ${detail}`}`);
}

// --- commitment: Poseidon(asset_id, value, owner_pk, rho, r_note) -------------
{
  const note: Note = { assetId: 7n, value: 123_456n, ownerPk: 99n, rho: 11n, rNote: 22n };
  const sdk = commitNote(note);
  const circuit = circuitOut(
    'commit5',
    {
      asset_id: note.assetId.toString(),
      value: note.value.toString(),
      owner_pk: note.ownerPk.toString(),
      rho: note.rho.toString(),
      r_note: note.rNote.toString(),
    },
    'main.cm',
  );
  check('NoteCommitment cm', circuit === sdk, `circuit=${circuit} sdk=${sdk}`);
}

// --- nullifier: Poseidon(rho, owner_sk) ---------------------------------------
{
  const rho = 11n;
  const ownerSk = 314159n as OwnerSk;
  const sdk = deriveNullifier(rho, ownerSk);
  const circuit = circuitOut(
    'null2',
    { rho: rho.toString(), owner_sk: ownerSk.toString() },
    'main.nf',
  );
  check('Nullifier nf', circuit === sdk, `circuit=${circuit} sdk=${sdk}`);
}

if (failed) {
  console.error('\nNOTE PARITY FAILED — circuit and SDK disagree (check input ordering).');
  process.exit(1);
}
console.log('\nNOTE PARITY OK — circuit and SDK agree on commitment + nullifier.');
