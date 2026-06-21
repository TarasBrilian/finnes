'use client';

/**
 * Test-TBOND faucet page (FIN-027). Lets any visitor get the demo asset so they
 * can actually use the app: connect a wallet → add the TBOND trustline (they sign
 * it, only they can) → claim TBOND from the server faucet. Two steps because a
 * trustline needs the holder's signature; the funding happens server-side.
 */

import { useCallback, useEffect, useState } from 'react';
import {
  Asset,
  BASE_FEE,
  Horizon,
  Networks,
  Operation,
  TransactionBuilder,
} from '@stellar/stellar-sdk';

import { HORIZON_URL, TBOND_CODE, TBOND_ISSUER } from '@/lib/config';

type Freighter = {
  isConnected: () => Promise<{ isConnected: boolean }>;
  requestAccess: () => Promise<{ address: string } | { error: string }>;
  getAddress: () => Promise<{ address: string } | { error: string }>;
  signTransaction: (
    xdr: string,
    opts: { networkPassphrase: string; address?: string },
  ) => Promise<{ signedTxXdr: string } | { error: string }>;
};

const server = () => new Horizon.Server(HORIZON_URL);
const TBOND = () => new Asset(TBOND_CODE, TBOND_ISSUER);

export default function FaucetPage() {
  const [address, setAddress] = useState<string | null>(null);
  const [hasTrustline, setHasTrustline] = useState<boolean | null>(null);
  const [balance, setBalance] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'error' | 'info'; text: string; txHash?: string } | null>(null);

  const fr = useCallback(async (): Promise<Freighter> => (await import('@stellar/freighter-api')) as unknown as Freighter, []);

  const refresh = useCallback(async (addr: string) => {
    try {
      const acct = await server().loadAccount(addr);
      const tb = acct.balances.find((b) => 'asset_code' in b && b.asset_code === TBOND_CODE && b.asset_issuer === TBOND_ISSUER);
      setHasTrustline(!!tb);
      setBalance(tb && 'balance' in tb ? tb.balance : null);
    } catch {
      setHasTrustline(false);
      setBalance(null);
      setMsg({ kind: 'error', text: 'Account not found on Testnet. Fund it with XLM first (Freighter → Testnet friendbot).' });
    }
  }, []);

  const connect = useCallback(async () => {
    setMsg(null);
    try {
      const f = await fr();
      const got = (await f.getAddress()) as { address?: string };
      const addr = got.address || ((await f.requestAccess()) as { address?: string }).address;
      if (!addr) throw new Error('No account connected.');
      setAddress(addr);
      await refresh(addr);
    } catch (e) {
      setMsg({ kind: 'error', text: e instanceof Error ? e.message : 'Could not connect Freighter.' });
    }
  }, [fr, refresh]);

  useEffect(() => {
    void connect();
  }, [connect]);

  async function addTrustline() {
    if (!address) return;
    setBusy('trustline');
    setMsg({ kind: 'info', text: 'Building trustline transaction, approve it in Freighter…' });
    try {
      const f = await fr();
      const s = server();
      const acct = await s.loadAccount(address);
      const tx = new TransactionBuilder(acct, { fee: BASE_FEE, networkPassphrase: Networks.TESTNET })
        .addOperation(Operation.changeTrust({ asset: TBOND() }))
        .setTimeout(120)
        .build();
      const signed = await f.signTransaction(tx.toXDR(), { networkPassphrase: Networks.TESTNET, address });
      if ('error' in signed) throw new Error(String(signed.error));
      const sub = await s.submitTransaction(TransactionBuilder.fromXDR(signed.signedTxXdr, Networks.TESTNET));
      setMsg({ kind: 'ok', text: 'TBOND trustline added. Now claim your test TBOND.', txHash: sub.hash });
      await refresh(address);
    } catch (e) {
      setMsg({ kind: 'error', text: e instanceof Error ? e.message : 'Failed to add trustline.' });
    } finally {
      setBusy(null);
    }
  }

  async function claim() {
    if (!address) return;
    setBusy('claim');
    setMsg({ kind: 'info', text: 'Requesting test TBOND from the faucet…' });
    try {
      const res = await fetch('/api/faucet', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ address }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Faucet request failed.');
      setMsg({ kind: 'ok', text: `Sent ${data.amount} ${data.asset}.`, txHash: data.txHash });
      await refresh(address);
    } catch (e) {
      setMsg({ kind: 'error', text: e instanceof Error ? e.message : 'Faucet request failed.' });
    } finally {
      setBusy(null);
    }
  }

  const msgCls =
    msg?.kind === 'ok' ? 'bg-emerald-50 text-emerald-900' : msg?.kind === 'error' ? 'bg-rose-50 text-rose-900' : 'bg-blue-50 text-blue-900';

  return (
    <main className="mx-auto max-w-xl px-6 py-16">
      <div className="card p-8">
        <h1 className="text-2xl font-semibold text-ink">Test TBOND faucet</h1>
        <p className="mt-2 text-sm text-ink-muted">
          New here? Get demo TBOND on Stellar Testnet so you can try Shield / Transfer / Unshield. Two
          one-time steps: add the TBOND trustline (you sign it), then claim.
        </p>

        <div className="mt-6 space-y-4">
          {!address ? (
            <button className="btn btn-primary w-full" onClick={() => void connect()}>
              Connect Freighter (Testnet)
            </button>
          ) : (
            <>
              <div className="rounded-lg bg-blue-50/60 p-3 text-xs">
                <div className="text-ink-muted">Connected account</div>
                <div className="mono break-all text-ink">{address}</div>
                <div className="mt-1 text-ink-muted">
                  TBOND balance:{' '}
                  <span className="font-mono font-semibold text-ink">{balance ?? (hasTrustline ? '0' : '-')}</span>
                  {hasTrustline === false && <span className="ml-1 text-rose-600">(no trustline yet)</span>}
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3">
                <button
                  className="btn btn-primary"
                  disabled={busy !== null || hasTrustline === true}
                  onClick={() => void addTrustline()}
                >
                  {hasTrustline === true ? '1. TBOND trustline ✓' : busy === 'trustline' ? '1. Adding trustline…' : '1. Add TBOND trustline'}
                </button>
                <button
                  className="btn btn-primary"
                  disabled={busy !== null || hasTrustline !== true}
                  onClick={() => void claim()}
                >
                  {busy === 'claim' ? '2. Claiming…' : '2. Claim test TBOND'}
                </button>
              </div>
            </>
          )}

          {msg && (
            <div className={`rounded-lg px-3 py-2 text-sm ${msgCls}`}>
              {msg.text}
              {msg.txHash && (
                <a
                  className="mono ml-1 underline"
                  href={`https://stellar.expert/explorer/testnet/tx/${msg.txHash}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  Tx {msg.txHash.slice(0, 10)}…
                </a>
              )}
            </div>
          )}
        </div>

        <p className="mt-6 text-[11px] leading-relaxed text-ink-faint">
          Testnet, demo-only, TBOND here has no real value. After claiming, go to the{' '}
          <a className="underline" href="/institution">institution console</a> to shield, transfer, and unshield.
          The funder runs server-side; your keys never leave your wallet.
        </p>
      </div>
    </main>
  );
}
