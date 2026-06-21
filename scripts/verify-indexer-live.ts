// FIN-019 verification: exercise the frontend indexer's extraction logic against
// the LIVE deployed contract and decrypt the auditor ciphertexts with the demo
// view key — proving the regulator path reads real on-chain data, not a fixture.
//
// Mirrors frontend/lib/indexer.ts `indexTransactions` + finnes-client
// `decryptAuditorView`. Run: npx tsx scripts/verify-indexer-live.ts

import { rpc, scValToNative } from '@stellar/stellar-sdk';
import {
  commitNote,
  deriveAssetId,
  deriveOwnerPk,
  discloseTransaction,
  IncrementalMerkleTree,
  K_A,
  TREE_DEPTH,
  type Ciphertext,
  type Fr,
} from '../sdk/src/index.js';
import {
  GENESIS_NOTE,
  SHIELD2_NOTE,
  TRANSFER_OUT_CHANGE,
  TRANSFER_OUT_RECIPIENT,
  UNSHIELD2_CHANGE_NOTE,
} from './lib/live-notes.js';

// Canonical on-chain demo leaves in leaf order — the indexer's seed for the
// aged-out prefix (mirrors frontend/lib/live-notes `liveSeedCommitments`).
const SEED_COMMITMENTS: Fr[] = [
  GENESIS_NOTE,
  SHIELD2_NOTE,
  TRANSFER_OUT_RECIPIENT,
  TRANSFER_OUT_CHANGE,
  UNSHIELD2_CHANGE_NOTE,
].map(commitNote);

/** Splice the confirmed aged-out prefix when continuity is provable (see indexer.ts). */
function bridgeAgedOutPrefix(events: bigint[]): bigint[] {
  if (!events.length) return events;
  const p = SEED_COMMITMENTS.indexOf(events[0]!);
  return p > 0 ? [...SEED_COMMITMENTS.slice(0, p), ...events] : events;
}

const CONTRACT_ID = 'CDIWXQSWIP6GKJKCAZPFONDD7VZ2PR2AQVCBQ7WRNTL64M3DAP55G7IA';
const RPC_URL = 'https://soroban-testnet.stellar.org';
const DEMO_AUDITOR_VIEW_KEY: Fr = 777_000_001n;

const toBig = (b: Buffer | Uint8Array): bigint => BigInt('0x' + Buffer.from(b).toString('hex'));

function cipherAt(packed: (Buffer | Uint8Array)[] | undefined, n: number): Ciphertext {
  const fields: Fr[] = [];
  for (let i = 0; i < K_A; i++) {
    const slot = packed?.[n * K_A + i];
    fields.push(slot ? toBig(slot) : 0n);
  }
  return { fields };
}

// Asset / party label resolvers (demo registry, mirrors demo-data.ts).
const ASSETS = new Map<Fr, string>([
  [deriveAssetId('777'), 'TBOND-2031'],
  [deriveAssetId('888'), 'eUSD'],
]);
const PARTIES = new Map<Fr, string>([
  [deriveOwnerPk(1001n as never), 'Meridian Capital (Bank A)'],
  [deriveOwnerPk(1002n as never), 'Cendrawasih Bank (Bank B)'],
  [deriveOwnerPk(1003n as never), 'Garuda Sekuritas (Bank C)'],
]);
const resolveAsset = (a: Fr) => (ASSETS.has(a) ? { label: ASSETS.get(a)!, decimals: 7 } : undefined);
const resolveParty = (pk: Fr) => PARTIES.get(pk);

async function main() {
  const s = new rpc.Server(RPC_URL);
  const latest = (await s.getLatestLedger()).sequence;
  const start = Math.max(1, latest - 17000);
  const s2 = s as unknown as { getEvents: (r: unknown) => Promise<{ events: any[]; cursor?: string }> };

  const effects: { topic: string; value: any; txHash: string; ts: string }[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 80; page++) {
    const filters = [{ type: 'contract', contractIds: [CONTRACT_ID] }];
    const req = cursor ? { cursor, filters, limit: 200 } : { startLedger: start, filters, limit: 200 };
    const r = await s2.getEvents(req);
    if (!r.events.length) break;
    for (const ev of r.events) {
      effects.push({
        topic: scValToNative(ev.topic[0]) as string,
        value: scValToNative(ev.value),
        txHash: ev.txHash,
        ts: ev.ledgerClosedAt,
      });
    }
    if (!r.cursor || r.cursor === cursor) break;
    cursor = r.cursor;
  }

  console.log(`Indexed ${effects.length} contract events from ledger ${start}..${latest}\n`);

  // (A) Tree-reconstruction consistency: rebuild the commitment tree from the
  // extracted leaves (the same logic buildChainTree/the write-path anchors to)
  // and confirm its root equals the new_root the CONTRACT computed in its last
  // tree-mutating event. A match proves the leaf order/extraction is correct.
  const leaves: bigint[] = [];
  let lastNewRoot = '';
  for (const e of effects) {
    const v = e.value as Record<string, any>;
    if (e.topic === 'shield') { leaves.push(toBig(v.cm_out)); lastNewRoot = Buffer.from(v.new_root).toString('hex'); }
    else if (e.topic === 'transfer') { leaves.push(toBig(v.cm_out_0)); leaves.push(toBig(v.cm_out_1)); lastNewRoot = Buffer.from(v.new_root).toString('hex'); }
    else if (e.topic === 'unshield') { const cc = toBig(v.cm_change_0); if (cc !== 0n) leaves.push(cc); lastNewRoot = Buffer.from(v.new_root).toString('hex'); }
    else if (e.topic === 'recovery') { leaves.push(toBig(v.cm_out)); lastNewRoot = Buffer.from(v.new_root).toString('hex'); }
  }
  const bridged = bridgeAgedOutPrefix(leaves);
  const tree = new IncrementalMerkleTree(TREE_DEPTH);
  bridged.forEach((l) => tree.insert(l));
  const indexerRoot = tree.root().toString(16).padStart(64, '0');
  const rootMatch = indexerRoot === lastNewRoot;
  const seeded = bridged.length - leaves.length;
  console.log(`Tree reconstruction: ${leaves.length} in-window leaves + ${seeded} aged-out seed → ${bridged.length} leaves`);
  console.log(`  indexer root        : ${indexerRoot.slice(0, 16)}…`);
  console.log(`  contract last new_root: ${lastNewRoot.slice(0, 16)}…`);
  console.log(rootMatch ? '✅ MATCH — indexer tree == contract-computed root (write-path anchor is sound)\n'
                        : '❌ MISMATCH — leaf order/extraction drifted\n');

  let disclosed = 0;
  for (const e of effects) {
    const v = e.value as Record<string, any>;
    const cAud = v.c_auditor as Buffer[] | undefined;
    let circuit: 'shield' | 'transfer' | 'unshield' | null = null;
    let outputs: { commitment: bigint; cAuditor: Ciphertext }[] = [];
    let nullifiers: string[] = [];

    if (e.topic === 'shield') {
      circuit = 'shield';
      outputs = [{ commitment: toBig(v.cm_out), cAuditor: cipherAt(cAud, 0) }];
    } else if (e.topic === 'transfer') {
      circuit = 'transfer';
      nullifiers = [v.nf_in_0, v.nf_in_1].map((b: Buffer) => Buffer.from(b).toString('hex').slice(0, 12));
      outputs = [
        { commitment: toBig(v.cm_out_0), cAuditor: cipherAt(cAud, 0) },
        { commitment: toBig(v.cm_out_1), cAuditor: cipherAt(cAud, 1) },
      ];
    } else if (e.topic === 'unshield') {
      circuit = 'unshield';
      const cc = toBig(v.cm_change_0);
      nullifiers = [Buffer.from(v.nf_in_0).toString('hex').slice(0, 12)];
      outputs = cc === 0n ? [] : [{ commitment: cc, cAuditor: cipherAt(cAud, 0) }];
    } else {
      continue; // init / register / recovery — not a confidential tx
    }

    console.log(`• ${circuit.padEnd(8)} ${e.txHash.slice(0, 12)}…  ${e.ts}  nf=[${nullifiers.join(', ')}]  outputs=${outputs.length}`);
    if (!outputs.length) {
      console.log('    (no confidential output note — exact-spend unshield reveals amount/recipient publicly)\n');
      continue;
    }
    const view = discloseTransaction({ circuit, nullifiers: [], outputs }, DEMO_AUDITOR_VIEW_KEY, {
      asset: resolveAsset,
      party: resolveParty,
    });
    for (const o of view.outputs) {
      console.log(`    ↳ ${(o.role ?? 'output').padEnd(9)} ${o.party ?? '?'}  ${o.value} raw  ${o.assetLabel ?? o.assetId}  inRange=${o.valueInRange}`);
    }
    console.log();
    disclosed++;
  }

  console.log(`Decrypted ${disclosed} confidential transaction(s) from LIVE chain events with the demo view key.`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
