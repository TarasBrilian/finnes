'use client';

/**
 * Deterministic DEMO fixtures built with the REAL @finnes/sdk crypto.
 *
 * These stand in for what a production indexer would serve (FIN-019): genuine
 * on-chain-shaped records — real Poseidon commitments and real additive-keystream
 * ciphertexts. Because they are produced by the same SDK the prover/circuit use,
 * the regulator's `discloseTransaction` and the institution's `scanForOwnedNotes`
 * genuinely decrypt them — this is NOT a faked "reveal". Only the SOURCE of the
 * data is local/demo; the cryptography is real.
 *
 * The auditor ciphertexts are keyed by a FIXED demo view key so the regulator can
 * decrypt them after loading the matching "Demo key" (AuditorKeyInput). A wrong
 * key recovers out-of-range garbage, which the disclosure path reports honestly.
 *
 * SECURITY (invariant #8): these demo secrets are NOT real key material; never
 * model production keys this way. No real secret is logged or persisted.
 */

import type { Ciphertext, Commitment, Fr, Note, OwnerPk, OwnerSk, StateRoots } from '@finnes/sdk';
import {
  assetsLeafHash,
  auditorPkFromKey,
  commitNote,
  deriveAssetId,
  deriveNullifier,
  deriveOwnerPk,
  encryptToAuditor,
  encryptToRecipient,
  FR_MODULUS,
  imtLeafHash,
  IncrementalMerkleTree,
  sacAddressToField,
  TREE_DEPTH,
} from '@finnes/sdk';

/** Fixed demo auditor view key `k_view`; `auditor_pk = Poseidon(k_view)`. */
export const DEMO_AUDITOR_VIEW_KEY: Fr = 777_000_001n;
/** The matching public key the contract would enforce on every transfer. */
export const DEMO_AUDITOR_PK: Fr = auditorPkFromKey(DEMO_AUDITOR_VIEW_KEY).pk;
/** Fixed sender↔recipient pairwise secret keying the demo recipient ciphertexts. */
export const DEMO_PAIRWISE_KEY: Fr = 555_000_002n;

/** Demo counterparties (institutions). `sk` is a demo placeholder, not real. */
interface DemoParty {
  readonly label: string;
  readonly ownerSk: OwnerSk;
  readonly ownerPk: OwnerPk;
}
function party(label: string, sk: bigint): DemoParty {
  const ownerSk = sk as OwnerSk;
  return { label, ownerSk, ownerPk: deriveOwnerPk(ownerSk) };
}
const PARTIES: readonly DemoParty[] = [
  party('Meridian Capital (Bank A)', 1001n),
  party('Cendrawasih Bank (Bank B)', 1002n),
  party('Garuda Sekuritas (Bank C)', 1003n),
];

/** Demo authorized assets. `sac` is the field-literal SAC address (scenario form). */
interface DemoAsset {
  readonly assetId: Fr;
  readonly label: string;
  readonly decimals: number;
}
function asset(sac: string, label: string, decimals: number): DemoAsset {
  return { assetId: deriveAssetId(sac), label, decimals };
}
const ASSETS: readonly DemoAsset[] = [
  asset('777', 'TBOND-2031 (tokenized bond)', 7),
  asset('888', 'eUSD (confidential cash)', 7),
];

/**
 * Per-asset registry leaf metadata, in lockstep with scripts/lib/demo-state.ts
 * (the off-chain state the deployed contract was init'd with). `limit` is the raw
 * per-tx limit committed into `assets_root`.
 */
const ASSET_REGISTRY: readonly { sac: string; decimals: number; limit: bigint }[] = [
  { sac: '777', decimals: 7, limit: 10_000_000n }, // TBOND-2031
  { sac: '888', decimals: 7, limit: 50_000_000n }, // eUSD
];

const IMT_MAX: Fr = FR_MODULUS - 1n;

/**
 * Compute the four compliance roots deterministically, matching what the
 * post-deploy `init` stored on-chain (kyc membership of the demo banks; empty
 * sanction/frozen IMTs; the assets registry). Real SDK Poseidon/Merkle — the same
 * roots a proof must anchor to. These change rarely (config), so they are derived
 * here rather than read per-call; the LIVE tree `anchor_root` is read from chain.
 */
export function demoComplianceRoots(): Omit<StateRoots, 'anchorRoot'> {
  const kyc = new IncrementalMerkleTree(TREE_DEPTH);
  for (const p of PARTIES) kyc.insert(p.ownerPk);

  const emptyImt = () => {
    const t = new IncrementalMerkleTree(TREE_DEPTH);
    t.insert(imtLeafHash(0n, 1n, IMT_MAX));
    t.insert(imtLeafHash(IMT_MAX, 0n, 0n));
    return t;
  };

  const assets = new IncrementalMerkleTree(TREE_DEPTH);
  for (const a of ASSET_REGISTRY) {
    assets.insert(assetsLeafHash(deriveAssetId(a.sac), sacAddressToField(a.sac), BigInt(a.decimals), a.limit));
  }

  return {
    kycRoot: kyc.root(),
    sanctionRoot: emptyImt().root(),
    assetsRoot: assets.root(),
    frozenRoot: emptyImt().root(),
  };
}

/** Resolve an `asset_id` to its display label + decimals (assets registry stand-in). */
export function resolveAsset(assetId: Fr): { label: string; decimals: number } | undefined {
  const a = ASSETS.find((x) => x.assetId === assetId);
  return a ? { label: a.label, decimals: a.decimals } : undefined;
}
/** Resolve an output note's `owner_pk` to a known party label (KYC directory stand-in). */
export function resolveParty(ownerPk: Fr): string | undefined {
  return PARTIES.find((p) => p.ownerPk === ownerPk)?.label;
}

function note(assetId: Fr, value: bigint, ownerPk: Fr, rho: Fr, rNote: Fr): Note {
  return { assetId, value, ownerPk, rho, rNote };
}

/** A demo output note: its commitment + the MANDATORY auditor ciphertext. */
export interface DemoOutput {
  readonly commitment: Commitment;
  readonly cAuditor: Ciphertext;
}

/** A demo on-chain transaction (regulator's public view + the bound ciphertexts). */
export interface DemoTransaction {
  readonly txHash: string;
  readonly timestamp: string;
  readonly circuit: 'shield' | 'transfer' | 'unshield' | 'dvp';
  readonly nullifiers: readonly string[];
  readonly outputs: readonly DemoOutput[];
}

function shortHex(f: Fr): string {
  const h = f.toString(16);
  return `0x${h.slice(0, 4)}…${h.slice(-2)}`;
}

/** Encrypt a note to the demo auditor key and pair it with its commitment. */
function output(n: Note, rhoEnc: Fr): DemoOutput {
  return { commitment: commitNote(n), cAuditor: encryptToAuditor(n, DEMO_AUDITOR_VIEW_KEY, { rhoEnc }) };
}

const [BANK_A, BANK_B, BANK_C] = PARTIES as [DemoParty, DemoParty, DemoParty];
const [TBOND, EUSD] = ASSETS as [DemoAsset, DemoAsset];

/**
 * Build the demo transaction ledger with GENUINE commitments + auditor
 * ciphertexts. Each transfer mints a recipient note (output 0) and a change note
 * back to the sender (output 1), exactly as `transfer.circom` does — so the
 * regulator recovers both parties.
 */
export function buildDemoTransactions(): DemoTransaction[] {
  return [
    {
      // Bank A → Bank B: 5.0 TBOND, 2.0 change back to A.
      txHash: 'a1b2c3d4e5f6',
      timestamp: '2026-06-18T09:14:00Z',
      circuit: 'transfer',
      nullifiers: [shortHex(deriveNullifier(0x11n, BANK_A.ownerSk)), shortHex(deriveNullifier(0x12n, BANK_A.ownerSk))],
      outputs: [
        output(note(TBOND.assetId, 5_000_000n, BANK_B.ownerPk, 0x21n, 0x31n), 0x41n),
        output(note(TBOND.assetId, 2_000_000n, BANK_A.ownerPk, 0x22n, 0x32n), 0x42n),
      ],
    },
    {
      // Bank A shields 12.5 eUSD (transparent → shielded; no spent inputs).
      txHash: 'd4e5f6a7b8c9',
      timestamp: '2026-06-18T10:02:00Z',
      circuit: 'shield',
      nullifiers: [],
      outputs: [output(note(EUSD.assetId, 12_500_000n, BANK_A.ownerPk, 0x23n, 0x33n), 0x43n)],
    },
    {
      // Bank B → Bank C: 3.0 eUSD, 1.5 change back to B.
      txHash: '77aa88bb99cc',
      timestamp: '2026-06-18T11:48:00Z',
      circuit: 'transfer',
      nullifiers: [shortHex(deriveNullifier(0x13n, BANK_B.ownerSk)), shortHex(deriveNullifier(0x14n, BANK_B.ownerSk))],
      outputs: [
        output(note(EUSD.assetId, 3_000_000n, BANK_C.ownerPk, 0x24n, 0x34n), 0x44n),
        output(note(EUSD.assetId, 1_500_000n, BANK_B.ownerPk, 0x25n, 0x35n), 0x45n),
      ],
    },
  ];
}

/** An owned-note observation for the institution scan: commitment + recipient ct. */
export interface DemoOwnedCiphertext {
  readonly commitment: Commitment;
  readonly cRecipient: Ciphertext;
}

/**
 * Build a handful of notes OWNED BY `ownerPk` (the session's spending key) and
 * encrypt their recipient ciphertexts under the demo pairwise key, so the real
 * `scanForOwnedNotes` re-derives each commitment and recovers them. The institution
 * holds notes across two assets to show per-asset balances (never summed, #3/#16).
 */
export function buildDemoOwnedCiphertexts(ownerPk: OwnerPk): DemoOwnedCiphertext[] {
  const owned: Note[] = [
    note(TBOND.assetId, 5_000_000n, ownerPk, 0x51n, 0x61n),
    note(TBOND.assetId, 3_000_000n, ownerPk, 0x52n, 0x62n),
    note(EUSD.assetId, 8_500_000n, ownerPk, 0x53n, 0x63n),
    note(EUSD.assetId, 4_000_000n, ownerPk, 0x54n, 0x64n),
  ];
  return owned.map((n, i) => ({
    commitment: commitNote(n),
    cRecipient: encryptToRecipient(n, DEMO_PAIRWISE_KEY, { rhoEnc: BigInt(0x70 + i) }),
  }));
}
