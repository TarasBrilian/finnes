'use client';

import { useEffect, useState } from 'react';
import {
  confidentialTransfer,
  fetchSpendableUnshield,
  shield,
  unshield,
  formatRawAmount,
  type OpResult,
  type ShieldIntent,
  type TransferIntent,
  type UnshieldIntent,
} from '@/lib/finnes-client';
import type { SpendingKeypair } from '@/lib/keys';
import { TBOND_SAC } from '@/lib/config';
import { OpResultPanel } from './OpResultPanel';

/**
 * One professional settlement console for the three shielded-domain operations,
 * selected with a segmented control instead of separate cards:
 *
 *  - Transfer  (shielded A → shielded B, 2-in / 2-out)
 *  - Shield    (transparent RWA → note; binds the note to the deposited asset, #18)
 *  - Unshield  (note → transparent; proves frozen non-membership + recipient KYC, #19)
 *
 * The left side is the form; the right side is a disclosure preview (what the
 * public sees, what stays hidden) and a client-side proof pipeline, so the form
 * documents itself. All wiring, validation, and honest TODO results are unchanged.
 */

type Mode = 'transfer' | 'shield' | 'unshield';

const ASSETS = ['TBOND-2031 (tokenized bond)', 'eUSD (confidential cash)'] as const;
const DISPLAY_DECIMALS = 7;

/** A transparent Stellar address: 'G' + 55 base32 chars. A confidential transfer
 *  must commit to the recipient's SHIELDED key (owner_pk), never a G… address. */
function looksLikeStellarAddress(s: string): boolean {
  return /^G[A-Z2-7]{55}$/.test(s.trim());
}

const RECIPIENT_ADDRESS_ERROR =
  "That's a transparent Stellar address (G…). A confidential transfer needs the recipient's " +
  'shielded key (owner_pk), share it from the “Shielded key” panel.';

interface ModeMeta {
  readonly id: Mode;
  readonly label: string;
  readonly verb: string;
  readonly blurb: string;
  readonly reveals: readonly string[];
  readonly hides: readonly string[];
  readonly outputs: string;
}

const MODES: readonly ModeMeta[] = [
  {
    id: 'transfer',
    label: 'Transfer',
    verb: 'Build, prove & submit',
    blurb: 'Move value between two shielded parties.',
    reveals: ['2 nullifiers', '2 commitments', 'ciphertexts'],
    hides: ['amount', 'asset', 'sender', 'recipient'],
    outputs: 'Mints one note to the recipient and one change note back to you.',
  },
  {
    id: 'shield',
    label: 'Shield',
    verb: 'Shield deposit',
    blurb: 'Deposit a transparent RWA token into the shielded domain.',
    reveals: ['asset_id', 'amount', '1 commitment'],
    hides: ['owner', 'rho', 'r_note'],
    outputs: 'Mints one shielded note bound to the deposited asset.',
  },
  {
    id: 'unshield',
    label: 'Unshield',
    verb: 'Unshield & pay out',
    blurb: 'Redeem a note back to a transparent Stellar address.',
    reveals: ['1 nullifier', 'asset_id', 'amount', 'recipient'],
    hides: ['sender', 'change amount'],
    outputs: 'Pays the recipient via SAC transfer; optional change stays shielded.',
  },
];

const PIPELINE: readonly { step: string; detail: string }[] = [
  { step: 'Build', detail: 'Assemble the witness from local notes' },
  { step: 'Encrypt', detail: 'Auditor (mandatory) + recipient ciphertexts' },
  { step: 'Witness', detail: 'Range, conservation, KYC, limits' },
  { step: 'Prove', detail: 'Groth16 over BLS12-381' },
  { step: 'Submit', detail: 'Proof + public inputs + ciphertexts' },
];

export function SettlementConsole({ spending }: { spending: SpendingKeypair | null }) {
  const [mode, setMode] = useState<Mode>('transfer');
  const [assetLabel, setAssetLabel] = useState<string>(ASSETS[0]);
  const [recipientPk, setRecipientPk] = useState('');
  const [sacAddress, setSacAddress] = useState('');
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('');
  const [result, setResult] = useState<OpResult | null>(null);
  const [spendable, setSpendable] = useState<{ rawAmount: bigint; assetLabel: string } | null | 'loading'>(null);
  const [busy, setBusy] = useState(false);

  // On the Unshield tab, read the live spendable note (the on-chain note this
  // identity can redeem) so the form shows the max instead of letting the user
  // submit an over-the-note amount the witness builder would reject.
  // On the Shield tab, pre-fill the registered TBOND SAC so the form is ready (the
  // demo shields the registered TBOND asset; only it is wired on-chain).
  useEffect(() => {
    if (mode === 'shield' && !sacAddress) setSacAddress(TBOND_SAC);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  useEffect(() => {
    if (mode !== 'unshield') {
      setSpendable(null);
      return;
    }
    let cancelled = false;
    setSpendable('loading');
    fetchSpendableUnshield()
      .then((s) => {
        if (cancelled) return;
        setSpendable(s ? { rawAmount: s.rawAmount, assetLabel: s.assetLabel } : null);
        // Pre-fill the amount with the spendable note value so unshield is one-click
        // (the only valid amount is in (0, note value]).
        if (s) setAmount(s.rawAmount.toString());
      })
      .catch(() => {
        if (!cancelled) setSpendable(null);
      });
    return () => {
      cancelled = true;
    };
  }, [mode]);

  const meta = MODES.find((m) => m.id === mode)!;
  const ticker = assetLabel.split(' ')[0];

  const recipientError =
    mode === 'transfer' && recipientPk && looksLikeStellarAddress(recipientPk)
      ? RECIPIENT_ADDRESS_ERROR
      : null;

  const counterparty = mode === 'transfer' ? recipientPk : mode === 'shield' ? sacAddress : recipient;
  const disabled = !spending || !counterparty || !amount || !!recipientError || busy;
  const displayAmount = amount ? formatRawAmount(BigInt(amount), DISPLAY_DECIMALS) : null;

  function switchMode(next: Mode) {
    setMode(next);
    setResult(null);
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!spending || recipientError) return;
    setBusy(true);
    setResult(null);
    try {
      if (mode === 'transfer') {
        const intent: TransferIntent = {
          assetId: 1n,
          assetLabel,
          recipientPk: recipientPk.trim(),
          rawAmount: BigInt(amount),
        };
        setResult(await confidentialTransfer(intent, spending));
      } else if (mode === 'shield') {
        const intent: ShieldIntent = { sacAddress: sacAddress.trim(), assetLabel, rawAmount: BigInt(amount) };
        setResult(await shield(intent, spending));
      } else {
        const intent: UnshieldIntent = {
          assetId: 1n,
          assetLabel,
          recipient: recipient.trim(),
          rawAmount: BigInt(amount),
        };
        setResult(await unshield(intent, spending));
      }
    } catch (err) {
      setResult({
        status: 'error',
        steps: [
          { label: 'Build intent', status: 'error', detail: err instanceof Error ? err.message : 'Invalid input.' },
        ],
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card p-0">
      {/* ---- Header + segmented control --------------------------------- */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-blue-100 px-6 py-5">
        <div>
          <h2 className="font-display text-lg font-bold tracking-tight text-ink">Settlement console</h2>
          <p className="mt-0.5 text-xs text-ink-muted">{meta.blurb}</p>
        </div>
        <div className="inline-flex rounded-lg bg-blue-50 p-1 text-sm font-semibold ring-1 ring-inset ring-blue-100">
          {MODES.map((m) => (
            <button
              key={m.id}
              type="button"
              onClick={() => switchMode(m.id)}
              aria-pressed={mode === m.id}
              className={`rounded-md px-4 py-1.5 transition ${
                mode === m.id ? 'bg-blue-600 text-white shadow-sm' : 'text-ink-muted hover:text-blue-700'
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={onSubmit} className="p-6">
        <div className="grid gap-x-10 gap-y-7 md:grid-cols-2">
          {/* ---- Fields ------------------------------------------------- */}
          <div className="space-y-5">
            <div>
              <label className="label" htmlFor="sc-asset">Asset</label>
              <select id="sc-asset" className="input" value={assetLabel} onChange={(e) => setAssetLabel(e.target.value)}>
                {ASSETS.map((a) => (
                  <option key={a}>{a}</option>
                ))}
              </select>
            </div>

            {mode === 'transfer' && (
              <div>
                <label className="label" htmlFor="sc-recipient-pk">
                  Recipient shielded key
                  <span className="ml-1 font-normal normal-case text-ink-faint">owner_pk</span>
                </label>
                <input
                  id="sc-recipient-pk"
                  className="input font-mono"
                  placeholder="zk…, not a G… address"
                  value={recipientPk}
                  onChange={(e) => setRecipientPk(e.target.value)}
                  aria-invalid={!!recipientError}
                />
                {recipientError ? (
                  <p className="mt-1.5 rounded-lg bg-rose-50 p-2 text-[11px] leading-relaxed text-rose-700">
                    {recipientError}
                  </p>
                ) : (
                  <p className="mt-1.5 text-[11px] text-ink-faint">
                    Public key the receiver shares, safe to paste.
                  </p>
                )}
              </div>
            )}

            {mode === 'shield' && (
              <div>
                <label className="label" htmlFor="sc-sac">SAC contract address</label>
                <input
                  id="sc-sac"
                  className="input font-mono"
                  placeholder="C… Stellar Asset Contract"
                  value={sacAddress}
                  onChange={(e) => setSacAddress(e.target.value)}
                />
                <p className="mt-1.5 text-[11px] text-ink-faint">
                  asset_id = Poseidon(sac_address), the note binds to this asset.
                </p>
              </div>
            )}

            {mode === 'unshield' && (
              <div>
                <label className="label" htmlFor="sc-recipient">Transparent recipient</label>
                <input
                  id="sc-recipient"
                  className="input font-mono"
                  placeholder="G… / C… Stellar address"
                  value={recipient}
                  onChange={(e) => setRecipient(e.target.value)}
                />
                <p className="mt-1.5 text-[11px] text-ink-faint">
                  Must be KYC-approved &amp; non-sanctioned. The demo pays the
                  pre-registered recipient (Bank B → the contract&apos;s registered payout address);
                  arbitrary recipients need an admin <span className="font-mono">register_transparent</span> (FIN-010).
                </p>
              </div>
            )}

            <div>
              <label className="label" htmlFor="sc-amount">
                Amount<span className="ml-1 font-normal normal-case text-ink-faint">raw SAC units</span>
              </label>
              <div className="relative">
                <input
                  id="sc-amount"
                  className="input pr-20 font-mono text-base"
                  inputMode="numeric"
                  placeholder="1000000"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value.replace(/[^0-9]/g, ''))}
                />
                <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center border-l border-blue-100 px-3 text-xs font-semibold text-ink-muted">
                  {ticker}
                </span>
              </div>
              <p className="mt-1.5 flex items-baseline gap-1 text-[11px] text-ink-faint">
                {displayAmount ? (
                  <>
                    <span className="font-mono text-sm font-semibold text-ink">{displayAmount}</span>
                    <span>{ticker} · {DISPLAY_DECIMALS} display decimals (ZK layer never rescales, #16)</span>
                  </>
                ) : (
                  <>Display conversion appears here as you type.</>
                )}
              </p>
              {mode === 'unshield' && (
                <p className="mt-1.5 text-[11px]">
                  {spendable === 'loading' ? (
                    <span className="text-ink-faint">Reading spendable balance on-chain…</span>
                  ) : spendable ? (
                    <span className="text-ink-muted">
                      Spendable note on-chain:{' '}
                      <span className="font-mono text-sm font-semibold text-ink">{spendable.rawAmount.toString()}</span> raw
                      {' '}({formatRawAmount(spendable.rawAmount, DISPLAY_DECIMALS)} {ticker}), pre-filled.{' '}
                      <button
                        type="button"
                        className="ml-1 font-semibold text-blue-600 underline"
                        onClick={() => setAmount(spendable.rawAmount.toString())}
                      >
                        use max
                      </button>
                      <span className="mt-1 block text-ink-faint">
                        No TBOND deposit here, unshield pays OUT from the contract; your wallet only pays the XLM fee.
                      </span>
                    </span>
                  ) : (
                    <span className="text-rose-600">
                      No spendable note for this identity (the demo notes are spent). Shield one first.
                    </span>
                  )}
                </p>
              )}
              {mode === 'transfer' && (
                <p className="mt-1.5 text-[11px] text-ink-faint">
                  A transfer spends 2 notes. If you don&apos;t have 2 yet, this <span className="font-semibold text-ink-muted">auto-shields</span> them
                  first, expect a few wallet prompts (the auto-shields, then the transfer). No need to press Shield manually.
                </p>
              )}
            </div>
          </div>

          {/* ---- Disclosure preview + pipeline -------------------------- */}
          <div className="space-y-6 md:border-l md:border-blue-100 md:pl-10">
            <div>
              <span className="eyebrow">On submit</span>
              <p className="mt-2 text-sm leading-relaxed text-ink-muted">{meta.outputs}</p>
            </div>

            <div className="space-y-3">
              <DisclosureRow label="Public sees" items={[...meta.reveals]} tone="public" />
              <DisclosureRow label="Stays hidden" items={[...meta.hides]} tone="hidden" />
            </div>

            <div>
              <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-faint">
                Proof pipeline · client-side
              </p>
              <ol>
                {PIPELINE.map((p, i) => (
                  <li key={p.step} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full border border-blue-200 bg-blue-50 text-[11px] font-bold text-blue-700">
                        {i + 1}
                      </span>
                      {i < PIPELINE.length - 1 && <span aria-hidden="true" className="my-1 w-px flex-1 bg-blue-100" />}
                    </div>
                    <div className="pb-3">
                      <p className="text-xs font-semibold text-ink">{p.step}</p>
                      <p className="text-[11px] leading-snug text-ink-faint">{p.detail}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </div>

        {/* ---- Action bar --------------------------------------------- */}
        <div className="mt-2 flex flex-col gap-3 border-t border-blue-100 pt-5 sm:flex-row sm:items-center sm:justify-between">
          <p className="order-2 max-w-sm text-[11px] leading-relaxed text-ink-faint sm:order-1">
            The witness is assembled and proven in this tab, keys and note plaintext never leave the
            browser.
          </p>
          <div className="order-1 sm:order-2 sm:text-right">
            <button type="submit" className="btn-primary w-full sm:w-auto sm:min-w-[14rem]" disabled={disabled}>
              {busy ? 'Assembling…' : meta.verb}
              {!busy && <span aria-hidden="true">→</span>}
            </button>
            {!spending && (
              <p className="mt-1.5 text-xs text-ink-faint">Generate a shielded key to enable settlement.</p>
            )}
          </div>
        </div>

        <OpResultPanel result={result} />
      </form>
    </section>
  );
}

function DisclosureRow({
  label,
  items,
  tone,
}: {
  label: string;
  items: string[];
  tone: 'public' | 'hidden';
}) {
  const chip =
    tone === 'public'
      ? 'bg-white text-blue-700 ring-1 ring-inset ring-blue-200'
      : 'bg-blue-900/[0.06] text-ink-muted ring-1 ring-inset ring-blue-900/10';
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
      <span className="w-20 shrink-0 text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-faint">
        {label}
      </span>
      <div className="flex flex-1 flex-wrap gap-1.5">
        {items.map((it) => (
          <span key={it} className={`rounded-md px-2 py-0.5 text-[11px] font-medium ${chip}`}>
            {it}
          </span>
        ))}
      </div>
    </div>
  );
}
