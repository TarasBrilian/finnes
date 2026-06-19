'use client';

import { useCallback, useState } from 'react';

/**
 * Compact header "Connect wallet" button. Connects a Stellar wallet (Freighter)
 * for the TRANSPARENT side only — the same flow as <WalletConnect>, sized for the
 * top nav. Freighter holds the user's Ed25519 key in the extension; the frontend
 * never sees it, and it is SEPARATE from the shielded spending/viewing keys
 * (lib/keys.ts).
 */

function truncate(addr: string): string {
  return addr.length > 12 ? `${addr.slice(0, 5)}…${addr.slice(-4)}` : addr;
}

export function HeaderWalletButton() {
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const connect = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      // Dynamic import keeps the extension API out of SSR and lets the page load
      // without Freighter installed.
      const freighter = await import('@stellar/freighter-api');

      // freighter-api surface differs slightly across versions; use the common
      // shape and fall back where needed.
      const allowed = await (freighter as any).requestAccess?.();
      if (allowed && allowed.error) throw new Error(String(allowed.error));

      // Finnes settles on Stellar Testnet only — refuse a wallet pointed at
      // mainnet (Freighter reports it as the "PUBLIC" network).
      const net = (await (freighter as any).getNetwork?.())?.network ?? 'TESTNET';
      if (String(net).toUpperCase() !== 'TESTNET') {
        throw new Error(`Wrong network (${net}). Switch Freighter to Testnet and reconnect.`);
      }

      const addr =
        (await (freighter as any).getAddress?.())?.address ??
        (await (freighter as any).getPublicKey?.());

      if (!addr) throw new Error('Freighter returned no address. Is it installed and unlocked?');
      setPublicKey(String(addr));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to connect Freighter.');
      setPublicKey(null);
    } finally {
      setBusy(false);
    }
  }, []);

  const disconnect = useCallback(() => {
    setPublicKey(null);
    setError(null);
  }, []);

  if (publicKey) {
    return (
      <button
        type="button"
        onClick={disconnect}
        title={`${publicKey} — click to disconnect`}
        className="badge border border-emerald-200 bg-emerald-50 text-emerald-800 transition hover:bg-emerald-100"
      >
        <span className="mono">{truncate(publicKey)}</span>
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={connect}
      disabled={busy}
      title={error ?? 'Connect a Stellar wallet (Freighter)'}
      className="badge border border-blue-200 bg-blue-50 text-blue-700 transition hover:bg-blue-100 disabled:opacity-60"
    >
      {busy ? 'Connecting…' : 'Connect wallet'}
    </button>
  );
}
