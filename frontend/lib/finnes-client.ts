'use client';

/**
 * Thin client wrapper over @finnes/sdk + @finnes/prover and (placeholder)
 * Soroban contract invocations.
 *
 * ============================================================================
 * TRUST BOUNDARY (ARCHITECTURE.md → Frontend; CLAUDE.md invariant #8)
 * ============================================================================
 * Everything secret stays here, client-side:
 *   - key material (lib/keys.ts), note plaintext, the witness, owner_sk/rho/r.
 * This wrapper:
 *   - builds intents from LOCAL notes,
 *   - assembles the witness and calls the prover (which runs client-side),
 *   - submits ONLY public data (proof, public inputs, ciphertexts) to the chain.
 * It may fetch PUBLIC data (Merkle paths, roots, ciphertext blobs) from the API,
 * but it MUST NEVER send a witness, a key, or note plaintext to the backend.
 *
 * STATUS (FIN-014/015): the READ paths are REAL over a local demo fixture
 * (`demo-data.ts`, an indexer stand-in) with genuine SDK crypto:
 *   - scanConfidentialBalances → scanForOwnedNotes (real trial-decrypt),
 *   - decryptAuditorView       → discloseTransaction (real auditor decrypt).
 *
 * STATUS (FIN-027, option 2 — in-browser proving): the WRITE-path INFRASTRUCTURE
 * is now real and verified against the deployed contract:
 *   - fetchStateRoots  → live `current_root` over Soroban RPC (soroban.ts),
 *   - proveInBrowser   → client-side snarkjs groth16.fullProve (prove-browser.ts),
 *   - submitToContract → real Soroban invocation, spec-encoded + Freighter-signed
 *                        + RPC-sent (soroban.ts; arg encoding validated by a live
 *                        simulate that decodes to contract logic, not an error).
 * What remains for a one-click arbitrary-input write (reported honestly per step,
 * NEVER faked): the live commitment-tree frontier/paths need an indexer (FIN-019;
 * the demo's deterministic tree can stand in), the session must act as a
 * KYC-enrolled identity, and the operator must place the D=20 `.zkey` under
 * public/artifacts/<circuit>/. We NEVER fake a successful settlement.
 * ============================================================================
 */

import type {
  AuditorPublicKey,
  Ciphertext,
  Commitment,
  Fr,
  StateRoots,
} from '@finnes/sdk';
import {
  buildTransferPublicInputs,
  buildShieldPublicInputs,
  buildUnshieldPublicInputs,
  discloseTransaction,
  scanForOwnedNotes,
  TREE_DEPTH,
} from '@finnes/sdk';
import type { ProofBundle, Witness } from '@finnes/prover';

import type { SpendingKeypair, AuditorKeypair } from './keys.js';
import {
  buildDemoOwnedCiphertexts,
  buildDemoTransactions,
  demoComplianceRoots,
  DEMO_AUDITOR_PK,
  DEMO_PAIRWISE_KEY,
  resolveAsset,
  resolveParty,
} from './demo-data.js';
import { readCurrentRoot, submitInvocation } from './soroban.js';
import { fetchSpendableUnshield, runShield, runTransfer, runUnshield } from './write-flow.js';

export { fetchSpendableUnshield };

// ---------------------------------------------------------------------------
// Result envelope - operations report a real, honest status.
// ---------------------------------------------------------------------------

export type StepStatus = 'ok' | 'todo' | 'error';

export interface OpStep {
  readonly label: string;
  readonly status: StepStatus;
  /** Human-readable detail; for `todo`, what still needs wiring. */
  readonly detail: string;
}

export interface OpResult {
  /** Overall: 'todo' whenever any required step is unimplemented. */
  readonly status: StepStatus;
  readonly steps: readonly OpStep[];
  /** On a (future) real submission: the chain tx hash. Never faked. */
  readonly txHash?: string;
}

function todo(label: string, detail: string): OpStep {
  return { label, status: 'todo', detail };
}
function ok(label: string, detail: string): OpStep {
  return { label, status: 'ok', detail };
}
function summarise(steps: OpStep[], txHash?: string): OpResult {
  const status: StepStatus = steps.some((s) => s.status === 'error')
    ? 'error'
    : steps.some((s) => s.status === 'todo')
      ? 'todo'
      : 'ok';
  return { status, steps, txHash };
}

// ---------------------------------------------------------------------------
// Backend (public-data) reads. SAFE: only public data crosses this boundary.
// ---------------------------------------------------------------------------

/**
 * Fetch the current/recent state roots (FIN-027).
 *
 * REAL: `anchorRoot` is read LIVE from the deployed contract's `current_root`
 * view over Soroban RPC (read-only simulate, no wallet/fee). The four compliance
 * roots are the deterministic demo-state values the post-deploy `init` stored
 * (`demoComplianceRoots`, real SDK Poseidon/Merkle) — they change rarely (config),
 * the tree root is what moves. A proof built against these will match contract
 * state. Returns `isMock: false`; an empty tree yields `anchorRoot = 0`.
 */
export async function fetchStateRoots(): Promise<{ roots: StateRoots; isMock: boolean }> {
  const hex = await readCurrentRoot(); // live contract state
  const anchorRoot: Fr = hex ? BigInt('0x' + hex) : 0n;
  return { isMock: false, roots: { anchorRoot, ...demoComplianceRoots() } };
}

/**
 * Fetch the auditor public key the contract enforces (public state).
 * TODO(backend/contract): read `auditor_pk` from contract state.
 */
export async function fetchAuditorPublicKey(): Promise<{ pk: AuditorPublicKey; isMock: boolean }> {
  // The demo's enforced auditor key = Poseidon(demo k_view). Real value (so the
  // UI can show what the contract would check), demo source.
  return { pk: { pk: DEMO_AUDITOR_PK }, isMock: true };
}

// ---------------------------------------------------------------------------
// Scanning - discover owned notes by trial-decrypting on-chain ciphertexts.
// Runs client-side with the viewing secret (invariant #8).
// ---------------------------------------------------------------------------

export interface ConfidentialBalance {
  readonly assetId: Fr;
  /** Display label (from the assets registry / SDK display layer). */
  readonly assetLabel: string;
  /** Aggregate raw SAC units across owned notes. */
  readonly rawAmount: bigint;
  readonly noteCount: number;
  readonly isMock: boolean;
}

/**
 * Scan + aggregate the institution's confidential balances.
 *
 * REAL (FIN-014/015): runs the SDK's `scanForOwnedNotes` — trial-decrypts each
 * observed recipient ciphertext with the session's spending key and ACCEPTS a
 * note only when the recomputed Poseidon commitment matches (foreign/garbled
 * ciphertexts are silently skipped). Per-asset figures are never summed across
 * assets (invariant #3/#16). The ciphertext SOURCE is a local demo fixture
 * (`demo-data.ts`, an indexer stand-in, FIN-019); the decryption is genuine.
 *
 * SECURITY (invariant #8): `owner_sk` and recovered plaintext stay in this tab.
 */
export async function scanConfidentialBalances(
  spending: SpendingKeypair,
): Promise<ConfidentialBalance[]> {
  // Indexer stand-in: ciphertexts the institution would fetch from the backend.
  const observed = buildDemoOwnedCiphertexts(spending.ownerPk);
  const discovered = scanForOwnedNotes(observed, {
    ownerSk: spending.ownerSk,
    recipientKey: DEMO_PAIRWISE_KEY,
  });

  // Aggregate per asset (never across assets).
  const byAsset = new Map<Fr, { rawAmount: bigint; noteCount: number }>();
  for (const d of discovered) {
    const acc = byAsset.get(d.note.assetId) ?? { rawAmount: 0n, noteCount: 0 };
    acc.rawAmount += d.note.value;
    acc.noteCount += 1;
    byAsset.set(d.note.assetId, acc);
  }

  return [...byAsset.entries()].map(([assetId, agg]) => ({
    assetId,
    assetLabel: resolveAsset(assetId)?.label ?? `asset ${assetId.toString()}`,
    rawAmount: agg.rawAmount,
    noteCount: agg.noteCount,
    isMock: false,
  }));
}

// ---------------------------------------------------------------------------
// KYC / limit status (public compliance read).
// ---------------------------------------------------------------------------

export interface ComplianceState {
  readonly kycApproved: boolean;
  readonly sanctioned: boolean;
  /** Per-asset transfer limit (raw units) from the assets registry, if known. */
  readonly perTxLimitRaw?: bigint;
  readonly isMock: boolean;
}

/**
 * TODO(backend): the demo enrolls all accounts into `kyc_root` via an admin
 * script (ARCHITECTURE.md → Backend/API). Wire to the API KYC path lookup.
 */
export async function fetchComplianceState(_ownerPk: Fr): Promise<ComplianceState> {
  return { kycApproved: true, sanctioned: false, perTxLimitRaw: 10_000_000n, isMock: true };
}

// ---------------------------------------------------------------------------
// Intents → witness → prover → contract. The heart of the trust boundary.
// ---------------------------------------------------------------------------

export interface ShieldIntent {
  readonly sacAddress: string;
  readonly assetLabel: string;
  /** Raw SAC units to deposit. */
  readonly rawAmount: bigint;
}

export interface TransferIntent {
  readonly assetId: Fr;
  readonly assetLabel: string;
  /** Recipient owner public key (or address that maps to one). */
  readonly recipientPk: string;
  readonly rawAmount: bigint;
}

export interface UnshieldIntent {
  readonly assetId: Fr;
  readonly assetLabel: string;
  /** Transparent Stellar recipient (C.../G... address). */
  readonly recipient: string;
  readonly rawAmount: bigint;
}

/**
 * SHIELD: transparent RWA → shielded note.
 *
 * Flow (ARCHITECTURE.md → Assets registry & boundary):
 *   1. Build the output note opening (SECRET, client-side).
 *   2. Encrypt to the auditor (mandatory, invariant #5) + recipient.
 *   3. Assemble the witness, prove client-side, build public inputs.
 *   4. Sign + submit the SAC deposit + contract `shield` invocation.
 */
export async function shield(intent: ShieldIntent, _spending: SpendingKeypair): Promise<OpResult> {
  // REAL execution (FIN-027): assemble the shield witness from live state, prove
  // in-browser, submit the Soroban tx. Honest ok/error per step; never faked.
  return runShield(intent.rawAmount);
}

/**
 * CONFIDENTIAL TRANSFER: shielded A → shielded B (2-in / 2-out, single asset).
 */
export async function confidentialTransfer(
  intent: TransferIntent,
  _spending: SpendingKeypair,
): Promise<OpResult> {
  // REAL execution (FIN-027): scan live spendable notes, build the 2-in/2-out
  // witness, prove, submit. Honestly errors if < 2 spendable notes exist on-chain.
  // The demo sends to an enrolled recipient (Bank A); the recipient field is
  // informational (an arbitrary owner_pk must be KYC-enrolled to receive).
  void intent.recipientPk;
  return runTransfer(intent.rawAmount);
}

/**
 * UNSHIELD: shielded → transparent. Top compliance checkpoint (invariant #19):
 * MUST prove frozen-set non-membership + transparent recipient compliance.
 */
export async function unshield(intent: UnshieldIntent, _spending: SpendingKeypair): Promise<OpResult> {
  // REAL execution (FIN-027): pick a live spendable note, build the unshield
  // witness (frozen non-membership + recipient KYC, invariant #19), prove, submit.
  return runUnshield(intent.rawAmount);
}

// ---------------------------------------------------------------------------
// Regulator / auditor: decrypt the mandatory auditor ciphertext for a tx.
// Runs in the AUDITOR zone with the auditor view secret (invariant #8).
// ---------------------------------------------------------------------------

/** One output note as the public sees it: an opaque commitment + its auditor ct. */
export interface OnChainOutput {
  readonly commitment: Commitment;
  /** The mandatory auditor ciphertext for this note (field-packed; invariant #5). */
  readonly cAuditor: Ciphertext;
}

export interface OnChainTxSummary {
  readonly txHash: string;
  readonly timestamp: string;
  readonly circuit: 'shield' | 'transfer' | 'unshield' | 'dvp';
  /** What the PUBLIC sees: opaque nullifiers + per-output commitments/ciphertexts. */
  readonly nullifiers: readonly string[];
  readonly outputs: readonly OnChainOutput[];
  readonly isMock: boolean;
}

/** One decrypted output note in the regulator's full view. */
export interface DisclosedOutput {
  readonly role: string;
  /** Party label (resolved from `owner_pk`) or the raw `owner_pk` hex. */
  readonly party: string;
  readonly assetLabel: string;
  readonly assetId: Fr;
  readonly rawAmount: bigint;
  readonly decimals: number;
}

/** The decrypted, FULL view only the regulator can produce. */
export interface DecryptedAuditView {
  /** Every decrypted output note (recipient + change for a transfer). */
  readonly outputs: readonly DisclosedOutput[];
  /** Convenience for the headline display (the primary/recipient note). */
  readonly assetLabel: string;
  readonly assetId: Fr;
  /** Plaintext amount of the headline note (raw SAC units). */
  readonly rawAmount: bigint;
  readonly senderPk: string;
  readonly recipientPk: string;
  readonly isMock: boolean;
}

/**
 * List on-chain transactions (regulator view). PUBLIC data only - the regulator
 * sees the same opaque records as everyone else until they decrypt.
 *
 * The records are a local DEMO fixture (`demo-data.ts`, an indexer stand-in,
 * FIN-019) but carry GENUINE Poseidon commitments + auditor ciphertexts, so the
 * disclosure below is a real decryption, not a faked reveal.
 */
export async function listOnChainTransactions(): Promise<OnChainTxSummary[]> {
  return buildDemoTransactions().map((t) => ({
    txHash: t.txHash,
    timestamp: t.timestamp,
    circuit: t.circuit,
    nullifiers: t.nullifiers,
    outputs: t.outputs.map((o) => ({ commitment: o.commitment, cAuditor: o.cAuditor })),
    isMock: true,
  }));
}

function partyLabel(ownerPk: Fr): string {
  return resolveParty(ownerPk) ?? `0x${ownerPk.toString(16).slice(0, 8)}…`;
}

/**
 * Decrypt the auditor ciphertexts for a selected tx - the demo's climax
 * ("public sees nothing, regulator sees everything").
 *
 * REAL (FIN-014/015): runs the SDK's `discloseTransaction`, decrypting every
 * output note's MANDATORY auditor ciphertext with the auditor's view key
 * (`auditor.sk = k_view`) to full plaintext (amount, asset, party). For a
 * transfer, output 0 is the recipient note and output 1 is the change note back
 * to the sender, so both parties are recovered. A view key that does not match
 * the key the notes were encrypted to recovers out-of-64-bit-range garbage; we
 * detect that (`valueInRange`) and throw rather than show a bogus "reveal".
 *
 * SECURITY: `auditor.sk` is SECRET and stays in this tab. Never log it; never
 * send it or the plaintext to any backend (invariant #8).
 */
export async function decryptAuditorView(
  tx: OnChainTxSummary,
  auditor: AuditorKeypair,
): Promise<DecryptedAuditView> {
  const disclosed = discloseTransaction(
    { circuit: tx.circuit, nullifiers: [], outputs: tx.outputs.map((o) => ({ commitment: o.commitment, cAuditor: o.cAuditor })) },
    auditor.sk,
    { asset: resolveAsset, party: resolveParty },
  );

  if (disclosed.outputs.length === 0 || !disclosed.outputs[0]!.valueInRange) {
    throw new Error(
      'This view key cannot decrypt this transaction (it is not the auditor key the notes were encrypted to).',
    );
  }

  const outputs: DisclosedOutput[] = disclosed.outputs.map((o) => ({
    role: o.role ?? 'output',
    party: o.party ?? partyLabel(o.ownerPk),
    assetLabel: o.assetLabel ?? `asset ${o.assetId.toString()}`,
    assetId: o.assetId,
    rawAmount: o.value,
    decimals: o.decimals ?? 7,
  }));

  // Headline = the recipient/primary note (output 0); sender = the change note.
  const head = outputs[0]!;
  const change = outputs.find((o) => o.role === 'change');
  return {
    outputs,
    assetLabel: head.assetLabel,
    assetId: head.assetId,
    rawAmount: head.rawAmount,
    recipientPk: head.party,
    senderPk: change?.party ?? (tx.circuit === 'shield' ? 'transparent deposit' : '—'),
    isMock: false,
  };
}

// ---------------------------------------------------------------------------
// Submission helper (placeholder). Real contract wiring lives here.
// ---------------------------------------------------------------------------

/**
 * REAL contract submission (FIN-027). Accepts ONLY public data: the host-byte
 * proof + the named public-input struct (hex strings / arrays) the entrypoint
 * expects (asset_id, roots, nullifiers, commitments, frontiers, ciphertexts, …).
 * NEVER pass a witness or key here (invariant #8).
 *
 * Delegates to `soroban.submitInvocation`, which encodes the args via the
 * deployed contract's OWN spec, prepares + signs (Freighter) + sends the tx over
 * RPC, and returns a REAL tx hash. The verify-before-effects ordering (invariant
 * #9) is enforced ON-CHAIN, not here. `shield` additionally needs a `depositor`
 * field (the transparent G-address authorising the SAC pull).
 */
export async function submitToContract(
  entrypoint: 'shield' | 'confidential_transfer' | 'unshield',
  native: Readonly<Record<string, unknown>>,
): Promise<{ txHash: string }> {
  return submitInvocation(entrypoint, native as Record<string, unknown>);
}

/** Display helper: format raw SAC units using the asset's display decimals. */
export function formatRawAmount(raw: bigint, decimals = 7): string {
  const neg = raw < 0n;
  const abs = neg ? -raw : raw;
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const frac = abs % base;
  const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '');
  const s = fracStr ? `${whole}.${fracStr}` : `${whole}`;
  return neg ? `-${s}` : s;
}

// Re-export the witness type so callers don't reach into the prover directly.
export type { Witness };
