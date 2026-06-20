'use client';

/**
 * Real write-path execution (FIN-027, option 2). Each flow ACTUALLY runs the
 * pipeline — assemble a contract-acceptable witness from the live state, prove it
 * in the browser, and submit the real Soroban tx — reporting genuine per-step
 * status (ok / error), never a static TODO list. Steps that need an operator
 * prerequisite fail HONESTLY: the prove step errors if the `.zkey` isn't served,
 * the submit step errors if Freighter isn't connected, and transfer errors if
 * there aren't enough spendable notes on-chain.
 *
 * The session acts as an ENROLLED demo identity (Bank B) — a random session key is
 * not in `kyc_root`, so the in-circuit KYC check would (correctly) reject it. This
 * is the demo's stand-in for admin KYC enrollment; the check is never dropped.
 *
 * SECURITY (invariant #8): the witness is assembled and proven in this tab; only
 * the proof + public inputs (public data) are submitted. No secret leaves here.
 */

import {
  buildShieldWitness,
  buildTransferWitness,
  buildUnshieldWitness,
  commitNote,
  sacAddressToField,
} from '@finnes/sdk';

import { demoState, DEMO_AUDITOR_VIEW_KEY, HEAD_LOW } from './demo-state.js';
import { allLiveNotes, liveNoteNullifier } from './live-notes.js';
import { buildChainTree, type ChainTree } from './indexer.js';
import { saveStoredNote } from './note-store.js';
import { proveInBrowser } from './prove-browser.js';
import { isNullifierUsed, submitInvocation } from './soroban.js';
import type { OpResult, OpStep, StepStatus } from './finnes-client.js';

// --- result helpers (mirrors finnes-client) --------------------------------
const ok = (label: string, detail: string): OpStep => ({ label, status: 'ok', detail });
const err = (label: string, detail: string): OpStep => ({ label, status: 'error', detail });
function done(steps: OpStep[], txHash?: string): OpResult {
  const status: StepStatus = steps.some((s) => s.status === 'error')
    ? 'error'
    : steps.some((s) => s.status === 'todo')
      ? 'todo'
      : 'ok';
  return { status, steps, txHash };
}

/** 31-byte random field element (< r) for fresh note openings / nonces. */
function randFr(): bigint {
  const b = new Uint8Array(31);
  (globalThis.crypto ?? crypto).getRandomValues(b);
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return x;
}

const hex = (x: bigint): string => x.toString(16).padStart(64, '0');

// --- public-input mappers (publicHex -> named struct per docs/PUBLIC_IO.md) -
function mapShieldPi(h: string[]): Record<string, unknown> {
  return {
    asset_id: h[0], amount: h[1], kyc_root: h[2], assets_root: h[3], auditor_pk: h[4],
    cm_out_0: h[5], new_root: h[6], fee: h[7], next_index: h[8],
    old_frontier: h.slice(9, 29), new_frontier: h.slice(29, 49),
    c_auditor: h.slice(49, 54), c_recipient: h.slice(54, 59),
  };
}
function mapTransferPi(h: string[]): Record<string, unknown> {
  return {
    anchor_root: h[0], kyc_root: h[1], sanction_root: h[2], assets_root: h[3], frozen_root: h[4],
    auditor_pk: h[5], nf_in_0: h[6], nf_in_1: h[7], cm_out_0: h[8], cm_out_1: h[9],
    new_root: h[10], fee: h[11], next_index: h[12],
    old_frontier: h.slice(13, 33), new_frontier: h.slice(33, 53),
    c_auditor: h.slice(53, 63), c_recipient: h.slice(63, 73),
  };
}
function mapUnshieldPi(h: string[]): Record<string, unknown> {
  return {
    anchor_root: h[0], kyc_root: h[1], sanction_root: h[2], assets_root: h[3], frozen_root: h[4],
    auditor_pk: h[5], nf_in_0: h[6], asset_id: h[7], amount: h[8], recipient: h[9],
    cm_change_0: h[10], new_root: h[11], fee: h[12], next_index: h[13],
    old_frontier: h.slice(14, 34), new_frontier: h.slice(34, 54),
    c_auditor: h.slice(54, 59), c_recipient: h.slice(59, 64),
  };
}

/** The enrolled identity the institution console acts as (holds the spendable note). */
function identity() {
  const st = demoState();
  return { st, me: st.accounts[1]!, asset: st.assets[0]! }; // Bank B, TBOND
}

const proveHint =
  'Place the D=20 .zkey under public/artifacts/<circuit>/ (gitignored; copy from the ' +
  'Railway ceremony or setup/build) for in-browser proving.';
const submitHint = 'Connect a funded Testnet Freighter account (it signs + pays).';

/**
 * The single spendable on-chain note for the demo identity (or null) — so the
 * Unshield form can show the max and pre-fill the amount instead of letting the
 * user submit an over-the-note value that the witness builder would reject.
 */
export async function fetchSpendableUnshield(): Promise<{ rawAmount: bigint; leafIndex: number; assetLabel: string } | null> {
  const { me, asset } = identity();
  const chain = await buildChainTree();
  const unspent = await spendableNotes(me.ownerPk, chain);
  const s = unspent[0];
  return s ? { rawAmount: s.note.value, leafIndex: s.leafIndex, assetLabel: asset.label } : null;
}

/** A spendable note: its opening + the LIVE leaf index (matched on-chain). */
interface Spendable {
  readonly note: ReturnType<typeof allLiveNotes>[number]['note'];
  readonly ownerSk: bigint;
  readonly leafIndex: number;
}

/**
 * Live spendable notes: match each known opening (demo seeds + this wallet's
 * shielded notes) to its leaf in the ON-CHAIN tree (the indexer), then keep the
 * ones not yet nullified. Re-matching by commitment means we never rely on a stale
 * hardcoded index — the on-chain events are the source of truth.
 */
async function spendableNotes(ownerPk: bigint, chain: ChainTree): Promise<Spendable[]> {
  const out: Spendable[] = [];
  for (const l of allLiveNotes()) {
    if (l.note.ownerPk !== ownerPk) continue;
    const leafIndex = chain.commitments.indexOf(commitNote(l.note));
    if (leafIndex < 0) continue; // not on-chain
    if (await isNullifierUsed(liveNoteNullifier(l))) continue; // already spent
    out.push({ note: l.note, ownerSk: l.ownerSk as unknown as bigint, leafIndex });
  }
  return out;
}

/**
 * Shield one note of `value` to the demo identity: read the LIVE tree from chain
 * events → assemble → prove → submit → remember it. Returns the tx hash. Anchors
 * to the current on-chain frontier (the indexer), so it can never drift.
 */
async function doShield(value: bigint, steps: OpStep[], label: string): Promise<string> {
  const { st, me, asset } = identity();
  if (value <= 0n || value > asset.perTxLimitRaw) {
    throw new Error(`shield amount must be in (0, ${asset.perTxLimitRaw}] raw (per-tx limit)`);
  }
  const chain = await buildChainTree(); // live frontier + leaf count from on-chain events
  const leafIndex = chain.leafCount;
  const outNote = { assetId: asset.assetId, value, ownerPk: me.ownerPk, rho: randFr(), rNote: randFr() };
  const { witness } = buildShieldWitness({
    outNote,
    kycPath: me.kycPath, kycRoot: st.kycRoot,
    sacAddress: sacAddressToField(asset.sacAddress), decimals: BigInt(asset.decimals), perTxLimitRaw: asset.perTxLimitRaw,
    assetsPath: asset.assetsPath, assetsRoot: st.assetsRoot,
    oldFrontier: chain.tree.frontier(), nextIndex: leafIndex, fee: 0n,
    auditorPk: st.auditorPk, kView: DEMO_AUDITOR_VIEW_KEY, kPair: randFr(), rhoEncAuditor: randFr(), rhoEncRecipient: randFr(),
  });
  const proof = await proveInBrowser('shield', witness as Record<string, unknown>);
  const res = await submitInvocation('shield', { proof: proof.hostProof, pi: mapShieldPi(proof.publicHex) });
  saveStoredNote({
    leafIndex, assetId: asset.assetId.toString(), value: value.toString(),
    ownerPk: me.ownerPk.toString(), ownerSk: (me.ownerSk as unknown as bigint).toString(),
    rho: outNote.rho.toString(), rNote: outNote.rNote.toString(),
  });
  steps.push(ok(label, `minted ${value} raw to ${me.label} (leaf ${leafIndex}); proved in-browser + submitted — tx ${res.txHash.slice(0, 10)}….`));
  return res.txHash;
}

/** SHIELD: mint a new confidential note for the deposited (asset, amount). */
export async function runShield(rawAmount: bigint): Promise<OpResult> {
  const steps: OpStep[] = [];
  try {
    const tx = await doShield(rawAmount, steps, 'Shield deposit');
    return done(steps, tx);
  } catch (e) {
    return done([...steps, classify(steps, e)]);
  }
}

/** UNSHIELD: spend an on-chain note out to a transparent recipient. */
export async function runUnshield(rawAmount: bigint): Promise<OpResult> {
  const steps: OpStep[] = [];
  try {
    const { st, me, asset } = identity();
    const chain = await buildChainTree();
    const unspent = await spendableNotes(me.ownerPk, chain);
    if (unspent.length === 0) {
      return done([err('Select spent note', `${me.label} has 0 spendable notes on-chain. Shield one first (the Shield tab mints a note you can then unshield).`)]);
    }
    const spend = unspent[0]!;
    if (rawAmount <= 0n || rawAmount > spend.note.value) {
      return done([err('Validate amount', `amount must be in (0, ${spend.note.value}] raw (the spendable note's value).`)]);
    }
    const change = rawAmount < spend.note.value
      ? { assetId: asset.assetId, value: spend.note.value - rawAmount, ownerPk: me.ownerPk, rho: randFr(), rNote: randFr() }
      : undefined;
    steps.push(ok('Select spent note + change', `spend leaf ${spend.leafIndex} (${spend.note.value} raw); ${change ? `change ${change.value} back to ${me.label}` : 'exact spend (no change)'}.`));

    const { witness } = buildUnshieldWitness({
      inNote: spend.note, ownerSk: spend.ownerSk, inPath: chain.tree.inclusionPath(spend.leafIndex), anchorRoot: chain.tree.root(),
      frozenLow: HEAD_LOW, frozenPath: st.frozenLowPath, frozenRoot: st.frozenRoot,
      recipient: me.ownerPk, kycPath: me.kycPath, kycRoot: st.kycRoot,
      sanctionLow: HEAD_LOW, sanctionPath: st.sanctionLowPath, sanctionRoot: st.sanctionRoot,
      amount: rawAmount, changeNote: change,
      sacAddress: sacAddressToField(asset.sacAddress), decimals: BigInt(asset.decimals), perTxLimitRaw: asset.perTxLimitRaw,
      assetsPath: asset.assetsPath, assetsRoot: st.assetsRoot,
      oldFrontier: chain.tree.frontier(), nextIndex: chain.leafCount, fee: 0n,
      auditorPk: st.auditorPk, kView: DEMO_AUDITOR_VIEW_KEY, kPair: randFr(), rhoEncAuditor: randFr(), rhoEncRecipient: randFr(),
    });
    steps.push(ok('Assemble unshield witness', 'frozen non-membership of the spent note + recipient KYC (invariant #19).'));

    const proof = await proveInBrowser('unshield', witness as Record<string, unknown>);
    steps.push(ok('Generate Groth16 proof (in-browser)', `${proof.publicSignals.length} public signals; witness stays in this tab (inv #8).`));

    const res = await submitInvocation('unshield', { proof: proof.hostProof, pi: mapUnshieldPi(proof.publicHex) });
    steps.push(ok('Submit unshield to contract', `real Soroban tx ${res.txHash}; SAC moved contract→recipient.`));
    return done(steps, res.txHash);
  } catch (e) {
    return done([...steps, classify(steps, e)]);
  }
}

/** TRANSFER: 2-in / 2-out. Spends 2 notes → recipient (enrolled Bank A) + change. */
export async function runTransfer(rawAmount: bigint): Promise<OpResult> {
  const steps: OpStep[] = [];
  try {
    const { st, me, asset } = identity();
    const recipientAcct = st.accounts[0]!; // Bank A — an enrolled recipient (kyc_leaf)
    let chain = await buildChainTree();
    let unspent = await spendableNotes(me.ownerPk, chain);
    steps.push(ok('Scan spendable notes (live)', `${me.label} has ${unspent.length} spendable note(s).`));

    // AUTO-PREPARE (option 1): a fixed 2-in transfer needs 2 notes. If you have
    // fewer, shield the missing ones automatically (each = the transfer amount, so
    // the two inputs cover it) — so you never have to press Shield manually first.
    // Each auto-shield is its own on-chain tx (approve each in your wallet).
    const needed = 2 - unspent.length;
    if (needed > 0) {
      steps.push(ok('Auto-prepare notes', `a 2-in transfer needs 2 notes; auto-shielding ${needed} (each ${rawAmount} raw) — approve each in your wallet.`));
      for (let i = 0; i < needed; i++) {
        await doShield(rawAmount, steps, `Auto-shield note ${i + 1}/${needed}`);
      }
      chain = await buildChainTree();
      unspent = await spendableNotes(me.ownerPk, chain);
    }
    if (unspent.length < 2) {
      return done([...steps, err('Select 2 input notes', `could not prepare 2 spendable notes (have ${unspent.length}).`)]);
    }
    // Spend the 2 highest-value notes so their sum covers the amount.
    unspent.sort((a, b) => (b.note.value > a.note.value ? 1 : b.note.value < a.note.value ? -1 : 0));
    const [in0, in1] = [unspent[0]!, unspent[1]!];
    const sum = in0.note.value + in1.note.value;
    if (rawAmount <= 0n || rawAmount > sum) {
      return done([...steps, err('Validate amount', `amount must be in (0, ${sum}] raw (sum of your 2 input notes).`)]);
    }
    const changeVal = sum - rawAmount;
    const tree = chain.tree; // live tree from on-chain events
    const outRecipient = { assetId: asset.assetId, value: rawAmount, ownerPk: recipientAcct.ownerPk, rho: randFr(), rNote: randFr() };
    const outChange = { assetId: asset.assetId, value: changeVal, ownerPk: me.ownerPk, rho: randFr(), rNote: randFr() };
    steps.push(ok('Select 2 input notes + build outputs', `spend leaves ${in0.leafIndex},${in1.leafIndex} (${sum} raw) → ${rawAmount} to ${recipientAcct.label} + ${changeVal} change to ${me.label}.`));

    const { witness } = buildTransferWitness({
      ownerSk: me.ownerSk,
      inNotes: [in0.note, in1.note],
      inPaths: [tree.inclusionPath(in0.leafIndex), tree.inclusionPath(in1.leafIndex)],
      anchorRoot: tree.root(),
      outNotes: [outRecipient, outChange],
      kycLeaf: recipientAcct.ownerPk, kycPath: recipientAcct.kycPath, kycRoot: st.kycRoot,
      sanctionLow: HEAD_LOW, sanctionPath: st.sanctionLowPath, sanctionRoot: st.sanctionRoot,
      frozenLow: [HEAD_LOW, HEAD_LOW], frozenPaths: [st.frozenLowPath, st.frozenLowPath], frozenRoot: st.frozenRoot,
      sacAddress: sacAddressToField(asset.sacAddress), decimals: BigInt(asset.decimals), perTxLimitRaw: asset.perTxLimitRaw,
      assetsPath: asset.assetsPath, assetsRoot: st.assetsRoot,
      oldFrontier: tree.frontier(), nextIndex: tree.size, fee: 0n,
      auditorPk: st.auditorPk, kView: DEMO_AUDITOR_VIEW_KEY,
      kPair: [randFr(), randFr()], rhoEncAuditor: [randFr(), randFr()], rhoEncRecipient: [randFr(), randFr()],
    });
    steps.push(ok('Assemble transfer witness', 'per-asset conservation, 64-bit range, recipient KYC, sanctions/frozen non-membership, limits.'));

    const proof = await proveInBrowser('transfer', witness as Record<string, unknown>);
    steps.push(ok('Generate Groth16 proof (in-browser)', `${proof.publicSignals.length} public signals; witness stays in this tab (inv #8).`));

    const res = await submitInvocation('confidential_transfer', { proof: proof.hostProof, pi: mapTransferPi(proof.publicHex) });
    // Keep the change note (back to us) spendable; the recipient note belongs to Bank A.
    saveStoredNote({
      leafIndex: tree.size + 1, assetId: asset.assetId.toString(), value: changeVal.toString(),
      ownerPk: me.ownerPk.toString(), ownerSk: (me.ownerSk as unknown as bigint).toString(),
      rho: outChange.rho.toString(), rNote: outChange.rNote.toString(),
    });
    steps.push(ok('Submit confidential_transfer', `real Soroban tx ${res.txHash}; 2 nullifiers recorded, tree advanced by 2.`));
    return done(steps, res.txHash);
  } catch (e) {
    return done([...steps, classify(steps, e)]);
  }
}

/** Turn a thrown error into an honest, actionable step. Contract/on-chain errors
 *  are detected FIRST (they surface during prepare/submit, not proving). */
function classify(prior: OpStep[], e: unknown): OpStep {
  const msg = e instanceof Error ? e.message : String(e);
  // Depositor has no TBOND trustline / balance (shield pulls TBOND from the wallet).
  if (/trustline/i.test(msg)) {
    return err(
      'Submit to contract',
      'Your connected wallet has no TBOND trustline (or no TBOND). Shield pulls TBOND from your ' +
        'wallet, so it must hold it. Add the TBOND asset in Freighter (issuer ' +
        'GB66GONTENMTB5L5QXO7ARYR6HN7FAQG7MX6KCAJGHJIYUXE44JW37TD), then fund it — or connect an ' +
        'account that already holds TBOND.',
    );
  }
  // Any other contract rejection (from the simulate inside prepareTransaction).
  const code = msg.match(/Error\(Contract,\s*#(\d+)\)/);
  if (code || /HostError|escalating error|contract call failed/i.test(msg)) {
    return err('Submit to contract', `the contract rejected the transaction${code ? ` (error #${code[1]})` : ''}: ${msg.slice(0, 200)}`);
  }
  // Proving artifacts missing (only before a proof was produced).
  const proven = prior.some((s) => s.label.startsWith('Generate Groth16'));
  if (!proven && /zkey|wasm|artifact|Failed to fetch|404|fullProve|Invalid witness length/i.test(msg)) {
    return err('Generate Groth16 proof (in-browser)', `${msg}. ${proveHint}`);
  }
  // Wallet / signing problems.
  if (/Freighter|wallet|sign|getAccount|not connected|no account/i.test(msg)) {
    return err('Submit to contract', `${msg}. ${submitHint}`);
  }
  return err('Execute write', msg);
}

export { hex };
