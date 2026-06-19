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
 * STATUS: SCAFFOLD. The SDK/prover/contract calls below are stubs that throw or
 * return a clearly-labelled "not wired" result. We NEVER fake a successful
 * settlement. Every place needing real wiring is marked TODO(sdk/prover/contract).
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
  TREE_DEPTH,
} from '@finnes/sdk';
import type { ProofBundle, Witness } from '@finnes/prover';

import type { SpendingKeypair, AuditorKeypair } from './keys.js';

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
  return { pk: { pk: 0n }, isMock: true };
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
 * TODO(sdk): call `scanForOwnedNotes` over indexer-served ciphertexts using the
 * viewing context. `tryDecryptNote` currently THROWS (encryption scheme not
 * fixed - sdk/src/scan.ts, encrypt.ts). Until then we return labelled MOCK
 * balances so the institution view is demo-credible without faking decryption.
 */
export async function scanConfidentialBalances(
  _spending: SpendingKeypair,
): Promise<ConfidentialBalance[]> {
  // MOCK display data - clearly labelled in the UI as not-yet-decrypted.
  return [
    {
      assetId: 1n,
      assetLabel: 'TBOND-2031 (tokenized bond)',
      rawAmount: 5_000_000n,
      noteCount: 3,
      isMock: true,
    },
    {
      assetId: 2n,
      assetLabel: 'eUSD (confidential cash)',
      rawAmount: 12_500_000n,
      noteCount: 5,
      isMock: true,
    },
  ];
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
      'sdk createNote / deriveAssetId / sacAddressToField are SCAFFOLD stubs that throw ' +
        '(asset_id = Poseidon(sac_address); SAC-address→Fr encoding undefined). TODO(sdk).',
    ),
  );
  steps.push(
    todo(
      'Encrypt note to auditor (mandatory) + recipient',
      'sdk encryptToAuditor/encryptToRecipient throw - hybrid value-equality scheme not fixed. ' +
        'Auditor ciphertext is mandatory (invariant #5). TODO(sdk).',
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
      'Requires decrypted owned notes (scan) - sdk scan/encrypt throw. TODO(sdk).',
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
      'sdk encrypt* throw (scheme not fixed). Mandatory auditor ct, invariant #5. TODO(sdk).',
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
      'Requires decrypted owned notes (scan throws). TODO(sdk).',
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

export interface OnChainTxSummary {
  readonly txHash: string;
  readonly timestamp: string;
  readonly circuit: 'shield' | 'transfer' | 'unshield' | 'dvp';
  /** What the PUBLIC sees: opaque commitments, nullifiers, ciphertext refs. */
  readonly nullifiers: readonly string[];
  readonly outputCommitments: readonly Commitment[];
  /** The mandatory auditor ciphertext attached to this tx (field-packed). */
  readonly cAuditor: Ciphertext;
  readonly isMock: boolean;
}

/** The decrypted, FULL view only the regulator can produce. */
export interface DecryptedAuditView {
  readonly assetLabel: string;
  readonly assetId: Fr;
  /** Plaintext amount (raw SAC units). */
  readonly rawAmount: bigint;
  readonly senderPk: string;
  readonly recipientPk: string;
  readonly isMock: boolean;
}

/**
 * List on-chain transactions (regulator view). PUBLIC data only - the regulator
 * sees the same opaque records as everyone else until they decrypt.
 *
 * TODO(backend): wire to the indexer. Returns clearly-labelled MOCK txs.
 */
export async function listOnChainTransactions(): Promise<OnChainTxSummary[]> {
  const ct = (n: bigint): Ciphertext => ({ fields: [n, n + 1n, n + 2n] });
  return [
    {
      txHash: 'MOCK_TX_a1b2c3…',
      timestamp: '2026-06-18T09:14:00Z',
      circuit: 'transfer',
      nullifiers: ['0x9f…21', '0x4c…e7'],
      outputCommitments: [111111n, 222222n],
      cAuditor: ct(900n),
      isMock: true,
    },
    {
      txHash: 'MOCK_TX_d4e5f6…',
      timestamp: '2026-06-18T10:02:00Z',
      circuit: 'shield',
      nullifiers: [],
      outputCommitments: [333333n],
      cAuditor: ct(700n),
      isMock: true,
    },
    {
      txHash: 'MOCK_TX_77aa88…',
      timestamp: '2026-06-18T11:48:00Z',
      circuit: 'unshield',
      nullifiers: ['0x12…ab'],
      outputCommitments: [444444n],
      cAuditor: ct(500n),
      isMock: true,
    },
  ];
}

/**
 * Decrypt the auditor ciphertext for a selected tx - the demo's climax
 * ("public sees nothing, regulator sees everything").
 *
 * TODO(sdk): the real path derives the auditor decryption key from `auditor.sk`
 * and decrypts `tx.cAuditor` (hybrid scheme - sdk/src/encrypt.ts, scan.ts both
 * THROW today). We DO NOT fabricate a decryption. We return a clearly-labelled
 * MOCK plaintext so the regulator flow is demo-credible, and we flag `isMock`.
 *
 * SECURITY: `auditor.sk` is SECRET and stays in this tab. Never log it; never
 * send it or the plaintext to any backend (invariant #8).
 */
export async function decryptAuditorView(
  tx: OnChainTxSummary,
  _auditor: AuditorKeypair,
): Promise<DecryptedAuditView> {
  // TODO(sdk): real trial-decrypt. For now, derive a deterministic MOCK from the
  // ciphertext fields so the UI shows a plausible "full transaction".
  const seed = tx.cAuditor.fields.reduce((a, b) => a + b, 0n);
  const mockAmount = (seed % 9_000_000n) + 1_000_000n;
  const labels = ['TBOND-2031 (tokenized bond)', 'eUSD (confidential cash)'];
  return {
    isMock: true,
    assetId: seed % 2n,
    assetLabel: labels[Number(seed % 2n)] ?? labels[0]!,
    rawAmount: mockAmount,
    senderPk: '0xPK_SENDER_' + tx.txHash.slice(-6),
    recipientPk: '0xPK_RECIPIENT_' + tx.txHash.slice(-6),
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
