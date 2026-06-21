'use client';

/**
 * Real Soroban contract client for the deployed Finnes contract (FIN-027).
 *
 * READ: `readCurrentRoot` simulates the read-only `current_root` view over RPC
 *   (no wallet, no fee), the live tree root the UI anchors to.
 * WRITE: `submitInvocation` encodes the entrypoint args via the contract's OWN
 *   spec (frontend/lib/contract-spec.json, extracted from the deployed contract),
 *   prepares the transaction over RPC, signs it with Freighter (the transparent
 *   leg / submitter), sends it, and polls for the result, returning a REAL tx
 *   hash. Only PUBLIC data (proof, public inputs, ciphertexts) is ever sent.
 *
 * The arg encoding is validated against the live contract by an offline simulate
 * check (it decodes to contract logic, not an encoding error). PUBLIC data only, 
 * a witness or key MUST NEVER reach this module (invariant #8).
 */

import { Buffer } from 'buffer';
import {
  Account,
  BASE_FEE,
  Contract,
  Keypair,
  TransactionBuilder,
  rpc,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk';
import { Spec } from '@stellar/stellar-sdk/contract';

import { CONTRACT_ID, NETWORK_PASSPHRASE, RPC_URL } from './config.js';
import specEntries from './contract-spec.json';

const server = (): rpc.Server => new rpc.Server(RPC_URL);
const spec = (): Spec => new Spec(specEntries as string[]);
const contract = (): Contract => new Contract(CONTRACT_ID);

/** hex (no 0x) → Buffer, the form the contract spec takes for Bytes/BytesN. */
export const hexBuf = (hex: string): Buffer => Buffer.from(hex, 'hex');

/** Recursively convert a host-byte arg object (hex strings / arrays) to Buffers. */
function hexToBuffers<T>(v: T): unknown {
  if (typeof v === 'string') return hexBuf(v);
  if (Array.isArray(v)) return v.map(hexToBuffers);
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, hexToBuffers(x)]));
  }
  return v;
}

/**
 * Read the deployed contract's current Merkle root (read-only simulate).
 * Returns the 32-byte root as a 0x-less hex string, or null for an empty tree.
 */
export async function readCurrentRoot(): Promise<string | null> {
  const s = server();
  // A throwaway source account is fine for a read-only simulate (never submitted).
  const src = new Account(Keypair.random().publicKey(), '0');
  const tx = new TransactionBuilder(src, { fee: BASE_FEE, networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(contract().call('current_root'))
    .setTimeout(30)
    .build();
  const sim = await s.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(`current_root simulate failed: ${sim.error}`);
  const root = scValToNative(sim.result!.retval) as Buffer | null;
  return root ? Buffer.from(root).toString('hex') : null;
}

/** True iff the nullifier (0x-less hex) is already spent on-chain (read-only). */
export async function isNullifierUsed(nfHex: string): Promise<boolean> {
  const s = server();
  const src = new Account(Keypair.random().publicKey(), '0');
  const arg = spec().funcArgsToScVals('is_nullifier_used', { nf: hexBuf(nfHex) });
  const tx = new TransactionBuilder(src, { fee: BASE_FEE, networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(contract().call('is_nullifier_used', ...(arg as xdr.ScVal[])))
    .setTimeout(30)
    .build();
  const sim = await s.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(`is_nullifier_used simulate failed: ${sim.error}`);
  return scValToNative(sim.result!.retval) === true;
}

/** Freighter signing surface (v3). */
interface Freighter {
  isConnected: () => Promise<{ isConnected: boolean }>;
  requestAccess: () => Promise<{ address: string } | { error: string }>;
  getAddress: () => Promise<{ address: string } | { error: string }>;
  signTransaction: (
    xdr: string,
    opts: { networkPassphrase: string; address?: string },
  ) => Promise<{ signedTxXdr: string; signerAddress?: string } | { error: string }>;
}

async function freighterAddress(fr: Freighter): Promise<string> {
  const got = await fr.getAddress();
  if ('address' in got && got.address) return got.address;
  const req = await fr.requestAccess();
  if ('address' in req && req.address) return req.address;
  throw new Error('Freighter: no account connected (approve access in the extension).');
}

export interface SubmitResult {
  readonly txHash: string;
}

/**
 * Encode + prepare + sign (Freighter) + send a contract invocation; poll the
 * result. `native` is the host-byte arg object (hex strings / arrays) for the
 * entrypoint, matching the contract spec field names.
 */
export async function submitInvocation(
  method: 'shield' | 'confidential_transfer' | 'unshield',
  native: Record<string, unknown>,
): Promise<SubmitResult> {
  const fr = (await import('@stellar/freighter-api')) as unknown as Freighter;
  const connected = await fr.isConnected();
  if (!('isConnected' in connected) || !connected.isConnected) {
    throw new Error('Freighter wallet not detected. Install/unlock Freighter (Testnet) to submit.');
  }
  const sourceAddress = await freighterAddress(fr);

  const s = server();
  const account = await s.getAccount(sourceAddress); // submitter; must be funded on Testnet

  // `shield` takes the depositor (transparent payer) as the first arg; it is the
  // Freighter-connected account (it authorises the SAC pull + pays). Inject it.
  const args =
    method === 'shield' && !('depositor' in native)
      ? { ...native, depositor: sourceAddress }
      : native;

  // Encode args via the contract's own spec (correct ScVal for the structs). The
  // depositor is a G-address (not hex); keep it as-is, convert the rest.
  const encoded =
    method === 'shield'
      ? { ...(hexToBuffers({ ...args, depositor: undefined }) as Record<string, unknown>), depositor: (args as { depositor: string }).depositor }
      : (hexToBuffers(args) as Record<string, unknown>);
  const scvals = spec().funcArgsToScVals(method, encoded);

  const built = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(contract().call(method, ...(scvals as xdr.ScVal[])))
    .setTimeout(60)
    .build();

  // prepareTransaction simulates + attaches the Soroban footprint/resource fees.
  const prepared = await s.prepareTransaction(built);

  const signed = await fr.signTransaction(prepared.toXDR(), {
    networkPassphrase: NETWORK_PASSPHRASE,
    address: sourceAddress,
  });
  if ('error' in signed) throw new Error(`Freighter signing failed: ${signed.error}`);

  const signedTx = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE);
  const sent = await s.sendTransaction(signedTx);
  if (sent.status === 'ERROR') {
    throw new Error(`submit rejected: ${JSON.stringify(sent.errorResult ?? sent)}`);
  }

  // Poll for the final result.
  let result = await s.getTransaction(sent.hash);
  for (let i = 0; i < 30 && result.status === rpc.Api.GetTransactionStatus.NOT_FOUND; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    result = await s.getTransaction(sent.hash);
  }
  if (result.status !== rpc.Api.GetTransactionStatus.SUCCESS) {
    throw new Error(`tx ${sent.hash} did not succeed: ${result.status}`);
  }
  return { txHash: sent.hash };
}

/**
 * Submit the issuer `freeze(cm_target, new_frozen_root)` clawback tx (FIN-018,
 * invariant #14). Both args are `BytesN<32>`, so we encode them directly as
 * `ScVal::Bytes`, no contract-spec entry needed. `freeze` calls
 * `require_auth(issuer_authority)` on-chain, so the connected Freighter account
 * MUST be the issuer (admin=issuer=deployer in the demo); otherwise the tx fails
 * with an auth error, surfaced honestly. PUBLIC data only (a commitment + a root).
 */
export async function submitFreeze(
  cmTargetHex: string,
  newFrozenRootHex: string,
): Promise<SubmitResult> {
  const fr = (await import('@stellar/freighter-api')) as unknown as Freighter;
  const connected = await fr.isConnected();
  if (!('isConnected' in connected) || !connected.isConnected) {
    throw new Error('Freighter wallet not detected. Install/unlock Freighter (Testnet) to submit.');
  }
  const sourceAddress = await freighterAddress(fr);

  const s = server();
  const account = await s.getAccount(sourceAddress); // issuer; must be funded on Testnet

  const args = [
    xdr.ScVal.scvBytes(hexBuf(cmTargetHex)),
    xdr.ScVal.scvBytes(hexBuf(newFrozenRootHex)),
  ];
  const built = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(contract().call('freeze', ...args))
    .setTimeout(60)
    .build();

  const prepared = await s.prepareTransaction(built);
  const signed = await fr.signTransaction(prepared.toXDR(), {
    networkPassphrase: NETWORK_PASSPHRASE,
    address: sourceAddress,
  });
  if ('error' in signed) throw new Error(`Freighter signing failed: ${signed.error}`);

  const signedTx = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE);
  const sent = await s.sendTransaction(signedTx);
  if (sent.status === 'ERROR') {
    throw new Error(`submit rejected: ${JSON.stringify(sent.errorResult ?? sent)}`);
  }

  let result = await s.getTransaction(sent.hash);
  for (let i = 0; i < 30 && result.status === rpc.Api.GetTransactionStatus.NOT_FOUND; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    result = await s.getTransaction(sent.hash);
  }
  if (result.status !== rpc.Api.GetTransactionStatus.SUCCESS) {
    throw new Error(`tx ${sent.hash} did not succeed: ${result.status}`);
  }
  return { txHash: sent.hash };
}
