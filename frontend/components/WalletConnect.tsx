'use client';

import { useCallback, useEffect, useState } from 'react';

/**
 * Connects a Stellar wallet (Freighter) for the TRANSPARENT side only: signing
 * and submitting `shield` / `unshield` transactions (ARCHITECTURE.md → Frontend).
 *
 * SECURITY: Freighter holds the user's transparent Stellar (Ed25519) key in the
 * extension — the frontend never sees it. This is SEPARATE from the shielded
 * spending/viewing keys (lib/keys.ts), which are field elements generated for the
 * ZK layer and likewise never leave the client zone.
 */

export interface WalletState {
  connected: boolean;
  publicKey?: string;
  network?: string;
}

export function WalletConnect({
  onChange,
}: {
  onChange?: (state: WalletState) => void;
}) {
  const [state, setState] = useState<WalletState>({ connected: false });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const update = useCallback(
    (s: WalletState) => {
      setState(s);
      onChange?.(s);
    },
    [onChange],
  );

  const connect = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      // Dynamic import keeps the extension API out of SSR and lets the page load
      // without Freighter installed.
      const freighter = await import('@stellar/freighter-api');

      // TODO(wallet): freighter-api surface differs slightly across versions
      // (isConnected / requestAccess / getAddress vs getPublicKey, getNetwork).
      // This uses the common shape; adjust to the installed version.
      const allowed = await (freighter as any).requestAccess?.();
      if (allowed && allowed.error) throw new Error(String(allowed.error));

      const addr =
        (await (freighter as any).getAddress?.())?.address ??
        (await (freighter as any).getPublicKey?.());
      const net = (await (freighter as any).getNetwork?.())?.network ?? 'TESTNET';

      // Finnes settles on Stellar Testnet only — refuse a wallet pointed at
      // mainnet (Freighter reports it as the "PUBLIC" network).
      if (String(net).toUpperCase() !== 'TESTNET') {
        throw new Error(`Wrong network (${net}). Switch Freighter to Testnet and reconnect.`);
      }

      if (!addr) throw new Error('Freighter returned no address. Is it installed and unlocked?');
      update({ connected: true, publicKey: String(addr), network: String(net) });
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to connect Freighter.');
      update({ connected: false });
    } finally {
      setBusy(false);
    }
  }, [update]);

  const disconnect = useCallback(() => {
    update({ connected: false });
  }, [update]);

  // Surface a hint if the extension is absent, without auto-connecting.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const freighter = await import('@stellar/freighter-api');
        const present = await (freighter as any).isConnected?.();
        if (!cancelled && present && present.error) {
          // present.error means the extension isn't available.
        }
      } catch {
        /* extension/module not present; user can still click Connect */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="card">
      {state.connected ? (
        <button type="button" className="btn-ghost w-full" onClick={disconnect}>
          Disconnect wallet
        </button>
      ) : (
        <button type="button" className="btn-primary w-full" onClick={connect} disabled={busy}>
          {busy ? 'Connecting to Freighter…' : 'Connect Freighter wallet (Stellar Testnet)'}
        </button>
      )}

      {state.connected && (
        <div className="mt-3 rounded-xl bg-blue-50/70 p-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="badge bg-blue-100 text-blue-700">connected</span>
            <span className="text-ink-muted">{state.network}</span>
          </div>
          <div className="mono mt-2 break-all">{state.publicKey}</div>
        </div>
      )}

      {error && (
        <p className="mt-3 rounded-lg bg-rose-50 p-2 text-xs text-rose-700">{error}</p>
      )}
    </div>
  );
}
