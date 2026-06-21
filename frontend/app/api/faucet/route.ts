/**
 * Test-TBOND faucet (FIN-027), SERVER-SIDE. Sends the demo TBOND asset to a
 * visitor's address so newcomers (who hold no TBOND) can actually try the app.
 *
 * The funding secret (`FAUCET_SECRET`) lives ONLY here, server-side (never shipped
 * to the browser). Set it in frontend/.env.local to a TESTNET key that can fund
 * TBOND, ideally the TBOND issuer (it mints on payment) or the deployer (finite
 * balance). The recipient must already hold a TBOND trustline (the faucet PAGE
 * walks the user through signing that with their own wallet, which only they can).
 *
 * Testnet, demo-only: there is no real value here. A light per-address cooldown
 * keeps it from being drained, but this is not a production-hardened service.
 */

import {
  Asset,
  BASE_FEE,
  Horizon,
  Keypair,
  Networks,
  Operation,
  StrKey,
  TransactionBuilder,
} from '@stellar/stellar-sdk';

const HORIZON_URL = process.env.NEXT_PUBLIC_HORIZON_URL || 'https://horizon-testnet.stellar.org';
const ASSET_CODE = process.env.NEXT_PUBLIC_TBOND_CODE || 'TBOND';
const ISSUER = process.env.NEXT_PUBLIC_TBOND_ISSUER || 'GB66GONTENMTB5L5QXO7ARYR6HN7FAQG7MX6KCAJGHJIYUXE44JW37TD';
const FAUCET_SECRET = process.env.FAUCET_SECRET; // SERVER-ONLY; never NEXT_PUBLIC_*.
const DISPENSE = process.env.FAUCET_AMOUNT || '1'; // display TBOND per claim

// Simple in-memory cooldown (per address). Resets on server restart, fine for a demo.
const lastClaim = new Map<string, number>();
const COOLDOWN_MS = 60_000;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

export async function POST(req: Request): Promise<Response> {
  if (!FAUCET_SECRET) {
    return json({ error: 'Faucet not configured: set FAUCET_SECRET (a Testnet funder key) in frontend/.env.local.' }, 503);
  }

  let address: string;
  try {
    ({ address } = await req.json());
  } catch {
    return json({ error: 'Bad request: expected { address }.' }, 400);
  }
  if (typeof address !== 'string' || !StrKey.isValidEd25519PublicKey(address)) {
    return json({ error: 'Invalid Stellar address (G…).' }, 400);
  }

  const now = Date.now();
  const prev = lastClaim.get(address) ?? 0;
  if (now - prev < COOLDOWN_MS) {
    return json({ error: `Please wait ${Math.ceil((COOLDOWN_MS - (now - prev)) / 1000)}s before claiming again.` }, 429);
  }

  const server = new Horizon.Server(HORIZON_URL);
  const asset = new Asset(ASSET_CODE, ISSUER);

  // The recipient must hold a TBOND trustline (only they can add it).
  let recipient;
  try {
    recipient = await server.loadAccount(address);
  } catch {
    return json({ error: 'Account not found on Testnet. Fund it with XLM first (e.g. friendbot).' }, 400);
  }
  const hasTrustline = recipient.balances.some(
    (b) => 'asset_code' in b && b.asset_code === ASSET_CODE && b.asset_issuer === ISSUER,
  );
  if (!hasTrustline) {
    return json({ error: 'No TBOND trustline on this account yet. Add it first (the faucet page does this), then claim.', needsTrustline: true }, 400);
  }

  // Send TBOND from the funder (issuer mints on payment; a non-issuer sends balance).
  try {
    const funder = Keypair.fromSecret(FAUCET_SECRET);
    const source = await server.loadAccount(funder.publicKey());
    const tx = new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.payment({ destination: address, asset, amount: DISPENSE }))
      .setTimeout(60)
      .build();
    tx.sign(funder);
    const res = await server.submitTransaction(tx);
    lastClaim.set(address, now);
    return json({ ok: true, txHash: res.hash, amount: DISPENSE, asset: ASSET_CODE });
  } catch (e: unknown) {
    const detail =
      (e as { response?: { data?: { extras?: { result_codes?: unknown } } } })?.response?.data?.extras?.result_codes ??
      (e instanceof Error ? e.message : String(e));
    return json({ error: `Faucet payment failed: ${JSON.stringify(detail)}` }, 502);
  }
}
