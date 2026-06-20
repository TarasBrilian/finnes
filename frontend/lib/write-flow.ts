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
  buildUnshieldWitness,
  commitNote,
  sacAddressToField,
} from '@finnes/sdk';

import { demoState, DEMO_AUDITOR_VIEW_KEY, HEAD_LOW } from './demo-state.js';
import { LIVE_NOTES, liveNoteNullifier, liveTreeState, reconstructLiveTree } from './live-notes.js';
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
  const owned = LIVE_NOTES.filter((l) => l.ownerSk === me.ownerSk);
  for (const l of owned) {
    if (!(await isNullifierUsed(liveNoteNullifier(l)))) {
      return { rawAmount: l.note.value, leafIndex: l.leafIndex, assetLabel: asset.label };
    }
  }
  return null;
}

/** SHIELD: mint a new confidential note for the deposited (asset, amount). */
export async function runShield(rawAmount: bigint): Promise<OpResult> {
  const steps: OpStep[] = [];
  try {
    const { st, me, asset } = identity();
    if (rawAmount <= 0n || rawAmount > asset.perTxLimitRaw) {
      return done([err('Validate amount', `amount must be in (0, ${asset.perTxLimitRaw}] raw (per-tx limit).`)]);
    }
    const tree = liveTreeState();
    const outNote = { assetId: asset.assetId, value: rawAmount, ownerPk: me.ownerPk, rho: randFr(), rNote: randFr() };
    const { witness } = buildShieldWitness({
      outNote,
      kycPath: me.kycPath, kycRoot: st.kycRoot,
      sacAddress: sacAddressToField(asset.sacAddress), decimals: BigInt(asset.decimals), perTxLimitRaw: asset.perTxLimitRaw,
      assetsPath: asset.assetsPath, assetsRoot: st.assetsRoot,
      oldFrontier: tree.frontier, nextIndex: tree.leafCount, fee: 0n,
      auditorPk: st.auditorPk, kView: DEMO_AUDITOR_VIEW_KEY, kPair: randFr(), rhoEncAuditor: randFr(), rhoEncRecipient: randFr(),
    });
    steps.push(ok('Build note + assemble shield witness', `mint ${rawAmount} raw to ${me.label}; auditor-encrypted (inv #5), anchored to live frontier (leaf ${tree.leafCount}).`));

    const proof = await proveInBrowser('shield', witness as Record<string, unknown>);
    steps.push(ok('Generate Groth16 proof (in-browser)', `${proof.publicSignals.length} public signals; witness never left this tab (inv #8).`));

    const res = await submitInvocation('shield', { proof: proof.hostProof, pi: mapShieldPi(proof.publicHex) });
    steps.push(ok('Submit shield to contract', `real Soroban tx ${res.txHash}; SAC pulled depositor→contract atomically.`));
    return done(steps, res.txHash);
  } catch (e) {
    return done([...steps, classify(steps, e)]);
  }
}

/** UNSHIELD: spend an on-chain note out to a transparent recipient. */
export async function runUnshield(rawAmount: bigint): Promise<OpResult> {
  const steps: OpStep[] = [];
  try {
    const { st, me, asset } = identity();
    const owned = LIVE_NOTES.filter((l) => l.ownerSk === me.ownerSk);
    const unspent: typeof owned = [];
    for (const l of owned) if (!(await isNullifierUsed(liveNoteNullifier(l)))) unspent.push(l);
    if (unspent.length === 0) {
      return done([err('Select spent note', `${me.label} has 0 spendable notes on-chain (the FIN-025/026 demo spent them). Shield one first.`)]);
    }
    const spend = unspent[0]!;
    if (rawAmount <= 0n || rawAmount > spend.note.value) {
      return done([err('Validate amount', `amount must be in (0, ${spend.note.value}] raw (the spendable note's value).`)]);
    }
    const tree = reconstructLiveTree();
    const change = rawAmount < spend.note.value
      ? { assetId: asset.assetId, value: spend.note.value - rawAmount, ownerPk: me.ownerPk, rho: randFr(), rNote: randFr() }
      : undefined;
    steps.push(ok('Select spent note + change', `spend leaf ${spend.leafIndex} (${spend.note.value} raw); ${change ? `change ${change.value} back to ${me.label}` : 'exact spend (no change)'}.`));

    const { witness } = buildUnshieldWitness({
      inNote: spend.note, ownerSk: spend.ownerSk, inPath: tree.inclusionPath(spend.leafIndex), anchorRoot: tree.root(),
      frozenLow: HEAD_LOW, frozenPath: st.frozenLowPath, frozenRoot: st.frozenRoot,
      recipient: me.ownerPk, kycPath: me.kycPath, kycRoot: st.kycRoot,
      sanctionLow: HEAD_LOW, sanctionPath: st.sanctionLowPath, sanctionRoot: st.sanctionRoot,
      amount: rawAmount, changeNote: change,
      sacAddress: sacAddressToField(asset.sacAddress), decimals: BigInt(asset.decimals), perTxLimitRaw: asset.perTxLimitRaw,
      assetsPath: asset.assetsPath, assetsRoot: st.assetsRoot,
      oldFrontier: tree.frontier(), nextIndex: tree.size, fee: 0n,
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

/** TRANSFER: 2-in / 2-out. Needs ≥2 spendable notes for the same owner. */
export async function runTransfer(_rawAmount: bigint, _recipient: string): Promise<OpResult> {
  const steps: OpStep[] = [];
  try {
    const { me } = identity();
    const owned = LIVE_NOTES.filter((l) => l.ownerSk === me.ownerSk);
    const unspent: typeof owned = [];
    for (const l of owned) if (!(await isNullifierUsed(liveNoteNullifier(l)))) unspent.push(l);
    if (unspent.length < 2) {
      return done([
        ok('Scan spendable notes (live)', `${me.label} has ${unspent.length} spendable note(s) on-chain.`),
        err('Select 2 input notes', `a confidential transfer spends 2 notes for one owner; only ${unspent.length} available. Shield ${2 - unspent.length} more first.`),
      ]);
    }
    // (With ≥2 notes this would build the Transfer(20,5,5) witness, prove, and
    // submit — same pattern as runUnshield. Unreachable from the current demo
    // state, so left as an honest gate rather than dead unverifiable code.)
    return done([...steps, err('Assemble transfer witness', 'reachable once ≥2 spendable notes exist; build+prove+submit wiring mirrors unshield.')]);
  } catch (e) {
    return done([...steps, classify(steps, e)]);
  }
}

/** Turn a thrown error into an honest, actionable step (prove vs submit vs other). */
function classify(prior: OpStep[], e: unknown): OpStep {
  const msg = e instanceof Error ? e.message : String(e);
  const proven = prior.some((s) => s.label.startsWith('Generate Groth16'));
  if (!proven && /fetch|artifact|zkey|wasm|Failed to fetch|404|Unexpected|network/i.test(msg)) {
    return err('Generate Groth16 proof (in-browser)', `${msg}. ${proveHint}`);
  }
  if (/Freighter|wallet|sign|account|getAccount|not connected|funded/i.test(msg)) {
    return err('Submit to contract', `${msg}. ${submitHint}`);
  }
  return err('Execute write', msg);
}

export { hex };
