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
 * STATUS (FIN-014/015): the READ paths are now REAL over a local demo fixture
 * (`demo-data.ts`, an indexer stand-in) with genuine SDK crypto:
 *   - scanConfidentialBalances → scanForOwnedNotes (real trial-decrypt),
 *   - decryptAuditorView       → discloseTransaction (real auditor decrypt).
 * The WRITE paths (shield/confidential_transfer/unshield) still return honest
 * step-by-step `todo` results: the SDK witness builders + encryptors are wired,
 * but client-side proving needs the D=20 ceremony artifacts and submission needs
 * the Soroban entrypoints — both out of scope for the frontend-wiring slice.
 * We NEVER fake a successful settlement.
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
  DEMO_AUDITOR_PK,
  DEMO_PAIRWISE_KEY,
  resolveAsset,
  resolveParty,
} from './demo-data.js';

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
 * Fetch the current/recent state roots from the API/indexer.
 *
 * TODO(backend): wire to the real indexer API (ARCHITECTURE.md → Backend). For
 * now returns clearly-labelled mock roots so the UI can render.
 */
export async function fetchStateRoots(): Promise<{ roots: StateRoots; isMock: boolean }> {
  // MOCK - not real chain state.
  const z: Fr = 0n;
  return {
    isMock: true,
    roots: {
      anchorRoot: z,
      kycRoot: z,
      sanctionRoot: z,
      assetsRoot: z,
      frozenRoot: z,
    },
  };
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
export async function shield(
  _intent: ShieldIntent,
  _spending: SpendingKeypair,
): Promise<OpResult> {
  const steps: OpStep[] = [];

  steps.push(
    todo(
      'Build note opening + asset binding',
      'sdk createNote / deriveAssetId / sacAddressToField are wired (FIN-014); needs ' +
        'integrating into this submit flow (asset_id = Poseidon(sac_address)). TODO(flow).',
    ),
  );
  steps.push(
    todo(
      'Encrypt note to auditor (mandatory) + recipient',
      'sdk encryptToAuditor/encryptToRecipient are wired (FIN-004); auditor ciphertext is ' +
        'mandatory (invariant #5). Needs integrating into this flow. TODO(flow).',
    ),
  );
  steps.push(
    todo(
      'Assemble shield witness',
      'prover assembleShieldWitness needs final circuit signal names + frontier/ciphertext packing. TODO(prover).',
    ),
  );
  steps.push(
    todo(
      'Generate Groth16 proof (client-side, BLS12-381)',
      'prover.prove needs the bls12381 .wasm/.zkey from circuits:build + setup:ceremony. ' +
        'Runs in-browser; witness never leaves this tab (invariant #8). TODO(prover/setup).',
    ),
  );
  steps.push(
    todo(
      'Submit shield tx to Soroban contract',
      'Contract `shield` entrypoint + SAC deposit not wired. TODO(contract). ' +
        'Build public inputs via buildShieldPublicInputs (depth ' + TREE_DEPTH + ').',
    ),
  );

  return summarise(steps);
}

/**
 * CONFIDENTIAL TRANSFER: shielded A → shielded B (2-in / 2-out, single asset).
 */
export async function confidentialTransfer(
  _intent: TransferIntent,
  _spending: SpendingKeypair,
): Promise<OpResult> {
  const steps: OpStep[] = [];

  steps.push(
    todo(
      'Select input notes + build outputs',
      'Owned notes come from the real scan (scanForOwnedNotes, FIN-014); needs UTXO ' +
        'selection + output construction wired into this flow. TODO(flow).',
    ),
  );
  steps.push(
    ok(
      'Fetch public Merkle paths + roots from API',
      'Only PUBLIC data crosses to the backend. fetchStateRoots returns MOCK roots for now.',
    ),
  );
  steps.push(
    todo(
      'Encrypt 2 output notes to auditor (mandatory) + recipients',
      'sdk encrypt* are wired (FIN-004); mandatory auditor ct (invariant #5). Needs ' +
        'integrating into this flow. TODO(flow).',
    ),
  );
  steps.push(
    todo(
      'Assemble transfer witness (nullifiers, conservation, KYC, limits)',
      'prover assembleTransferWitness - per-asset conservation, 64-bit range, KYC membership, ' +
        'sanctions/frozen non-membership, assets membership + value ≤ per_tx_limit. TODO(prover).',
    ),
  );
  steps.push(
    todo(
      'Generate Groth16 proof (client-side)',
      'prover.prove with bls12381 artifacts. Witness stays in this tab (invariant #8). TODO(prover/setup).',
    ),
  );
  steps.push(
    todo(
      'Submit confidential_transfer to contract',
      'Contract entrypoint not wired. Public inputs via buildTransferPublicInputs. TODO(contract).',
    ),
  );

  // Demonstrate that the PUBLIC-input builder is real (it does not touch secrets),
  // but it cannot complete without real nullifiers/commitments/ciphertexts.
  void buildTransferPublicInputs;

  return summarise(steps);
}

/**
 * UNSHIELD: shielded → transparent. Top compliance checkpoint (invariant #19):
 * MUST prove frozen-set non-membership + transparent recipient compliance.
 */
export async function unshield(
  _intent: UnshieldIntent,
  _spending: SpendingKeypair,
): Promise<OpResult> {
  const steps: OpStep[] = [];

  steps.push(
    todo(
      'Select spent note + change',
      'Owned notes come from the real scan (scanForOwnedNotes, FIN-014); needs spent-note ' +
        'selection + change construction wired into this flow. TODO(flow).',
    ),
  );
  steps.push(
    todo(
      'Assemble unshield witness (frozen non-membership + recipient KYC)',
      'prover assembleUnshieldWitness - invariant #19: frozen-set non-membership of the spent ' +
        'commitment + KYC/non-sanctioned transparent recipient. TODO(prover).',
    ),
  );
  steps.push(
    todo(
      'Generate Groth16 proof (client-side)',
      'prover.prove with bls12381 artifacts. TODO(prover/setup).',
    ),
  );
  steps.push(
    todo(
      'Submit unshield tx (contract calls SAC transfer)',
      'Contract `unshield` reveals (asset_id, amount, recipient) for the SAC transfer. ' +
        'Public inputs via buildUnshieldPublicInputs. TODO(contract).',
    ),
  );

  void buildUnshieldPublicInputs;
  void buildShieldPublicInputs;

  return summarise(steps);
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
 * Placeholder contract submission. Accepts ONLY public data (a proof bundle +
 * ciphertexts). NEVER pass a witness or key here.
 *
 * TODO(contract): build a Soroban operation invoking the entrypoint with the
 * proof, public inputs, and ciphertexts; sign via Freighter (transparent legs)
 * or submit via the relayer fee-bump; await the tx result. Order per invariant
 * #9: validate root → nullifiers → compliance roots → verify Groth16 → bind
 * ciphertexts → mutate. (That ordering is enforced ON-CHAIN, not here.)
 */
export async function submitToContract(
  _entrypoint: 'shield' | 'confidential_transfer' | 'settle_dvp' | 'unshield',
  _bundle: ProofBundle,
  _ciphertexts: readonly Ciphertext[],
): Promise<{ txHash: string }> {
  throw new Error(
    'TODO(contract): Soroban entrypoint invocation not wired. ' +
      'Submit proof + public inputs + ciphertexts (public data only).',
  );
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
