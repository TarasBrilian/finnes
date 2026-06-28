/**
 * HTTP API (INDEXER_IMPLEMENTATION §6). Read-only, public, CORS-enabled. Serves
 * inclusion paths + in-window roots (the write-path anchor), the regulator ledger,
 * ciphertexts, and the frozen set. The indexer is UNTRUSTED — the on-chain Groth16
 * proof is the integrity guarantee — so reads need no auth.
 */

import express, { type Request, type Response } from 'express';
import { Buffer } from 'node:buffer';

import * as repo from '../db/repo.js';
import * as tree from '../ingest/tree.js';
import { isHalted } from '../ingest/worker.js';
import { chainState, latestLedger } from '../stellar.js';
import { CONTRACT_ID, TREE_MAIN, TREE_ESCROW } from '../config.js';
import { toHex, fromHex, bigToHex, bufToBig } from '../encoding.js';

const RECENT_ROOTS_CAPACITY = 64; // mirrors the contract's recent_roots_capacity()

type AsyncHandler = (req: Request, res: Response) => Promise<unknown>;

const h =
  (fn: AsyncHandler) =>
  (req: Request, res: Response): void => {
    fn(req, res).catch((e: unknown) => {
      console.error('[api]', e);
      if (!res.headersSent) {
        res.status(500).json({ error: { code: 'internal', message: e instanceof Error ? e.message : String(e) } });
      }
    });
  };

const treeId = (req: Request): number => (String(req.query.tree ?? 'main') === 'escrow' ? TREE_ESCROW : TREE_MAIN);
const treeName = (id: number): string => (id === TREE_ESCROW ? 'escrow' : 'main');
const badReq = (res: Response, message: string): Response =>
  res.status(400).json({ error: { code: 'bad_request', message } });
const notFound = (res: Response, message: string): Response =>
  res.status(404).json({ error: { code: 'not_found', message } });

export function createApp(): express.Express {
  const app = express();
  app.use(express.json());
  app.use((_req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    next();
  });
  app.options('*', (_req, res) => res.sendStatus(204));

  app.get('/v1/health', h(async (_req, res) => {
    const st = await repo.getSyncState(CONTRACT_ID);
    let latest: number | null = null;
    try {
      latest = await latestLedger();
    } catch {
      /* RPC unavailable — non-fatal */
    }
    res.json({
      ok: !isHalted(),
      contractId: CONTRACT_ID,
      backfilled: st?.backfilled ?? false,
      halted: isHalted(),
      haltReason: st?.halt_reason ?? null,
      lastLedger: st ? Number(st.last_ledger) : 0,
      latestLedger: latest,
      tree: { leafCount: tree.size(TREE_MAIN), root: bigToHex(tree.rootBig(TREE_MAIN)) },
    });
  }));

  app.get('/v1/state', h(async (req, res) => {
    const t = treeId(req);
    let chainRoot: string | null = null;
    let matches: boolean | null = null;
    try {
      const cs = await chainState();
      chainRoot = cs.root ? toHex(cs.root) : null;
      matches = chainRoot === bigToHex(tree.rootBig(t));
    } catch {
      /* cross-check best-effort */
    }
    res.json({
      tree: treeName(t),
      leafCount: tree.size(t),
      root: bigToHex(tree.rootBig(t)),
      frontier: tree.frontierBig(t).map(bigToHex),
      recentRootsCapacity: RECENT_ROOTS_CAPACITY,
      chainRoot,
      computedRootMatchesChain: matches,
    });
  }));

  app.get('/v1/roots', h(async (req, res) => {
    const t = treeId(req);
    const limit = Math.min(Number(req.query.limit ?? RECENT_ROOTS_CAPACITY), RECENT_ROOTS_CAPACITY);
    const rows = await repo.getRecentRoots(t, limit);
    res.json({
      tree: treeName(t),
      latest: rows[0] ? toHex(rows[0].root) : bigToHex(tree.rootBig(t)),
      roots: rows.map((r) => ({
        root: toHex(r.root),
        leafCount: Number(r.leaf_count),
        ledger: Number(r.ledger),
        txHash: r.tx_hash,
      })),
    });
  }));

  app.get('/v1/leaves', h(async (req, res) => {
    const t = treeId(req);
    const from = Math.max(0, Number(req.query.from ?? 0));
    const limit = Math.min(Number(req.query.limit ?? 1000), 5000);
    const leaves = await repo.getLeaves(t, from, limit);
    res.json({ tree: treeName(t), leafCount: tree.size(t), from, leaves: leaves.map(toHex) });
  }));

  app.get('/v1/commitment/:cm', h(async (req, res) => {
    const t = treeId(req);
    let cm: Buffer;
    try {
      cm = fromHex(req.params.cm!);
    } catch {
      return badReq(res, 'commitment must be hex');
    }
    const idx = await repo.getLeafIndexByCommitment(t, cm);
    if (idx === null) return notFound(res, 'commitment not indexed');
    return res.json({ tree: treeName(t), commitment: toHex(cm), leafIndex: idx });
  }));

  app.get('/v1/path/:leafIndex', h(async (req, res) => {
    const t = treeId(req);
    const idx = Number(req.params.leafIndex);
    if (!Number.isInteger(idx) || idx < 0) return badReq(res, 'leafIndex must be a non-negative integer');
    if (idx >= tree.size(t)) return notFound(res, `leaf ${idx} not indexed (count ${tree.size(t)})`);
    const cm = await repo.getCommitmentAt(t, idx);
    const p = tree.path(t, idx);
    return res.json({
      tree: treeName(t),
      leafIndex: idx,
      commitment: cm ? toHex(cm) : null,
      siblings: p.siblings.map(bigToHex),
      pathBits: p.pathBits,
      anchorRoot: bigToHex(tree.rootBig(t)),
      leafCount: tree.size(t),
    });
  }));

  // Batch — multi-input spends (transfer/dvp) MUST anchor all inputs to ONE root.
  app.post('/v1/paths', h(async (req, res) => {
    const body = (req.body ?? {}) as { tree?: string; leafIndices?: unknown };
    const t = body.tree === 'escrow' ? TREE_ESCROW : TREE_MAIN;
    const indices = body.leafIndices;
    if (!Array.isArray(indices) || indices.length === 0) return badReq(res, 'leafIndices must be a non-empty array');
    const anchorRoot = bigToHex(tree.rootBig(t));
    const leafCount = tree.size(t);
    const paths: unknown[] = [];
    for (const li of indices) {
      const idx = Number(li);
      if (!Number.isInteger(idx) || idx < 0 || idx >= leafCount) return notFound(res, `leaf ${String(li)} not indexed`);
      const cm = await repo.getCommitmentAt(t, idx);
      const p = tree.path(t, idx);
      paths.push({ leafIndex: idx, commitment: cm ? toHex(cm) : null, siblings: p.siblings.map(bigToHex), pathBits: p.pathBits });
    }
    return res.json({ tree: treeName(t), anchorRoot, leafCount, paths });
  }));

  app.get('/v1/nullifier/:nf', h(async (req, res) => {
    let nf: Buffer;
    try {
      nf = fromHex(req.params.nf!);
    } catch {
      return badReq(res, 'nullifier must be hex');
    }
    const r = await repo.nullifierUsed(nf);
    return res.json({ nullifier: toHex(nf), used: r.used, txHash: r.txHash });
  }));

  app.get('/v1/transactions', h(async (req, res) => {
    const limit = Math.min(Number(req.query.limit ?? 50), 200);
    const before = req.query.before !== undefined ? Number(req.query.before) : undefined;
    const rows = await repo.getTransactionRows(limit, before);
    const outs = await repo.getOutputsFor(rows.map((r) => r.tx_hash));
    const byTx = new Map<string, repo.OutputRow[]>();
    for (const o of outs) {
      const arr = byTx.get(o.tx_hash) ?? [];
      arr.push(o);
      byTx.set(o.tx_hash, arr);
    }
    const transactions = rows.map((r) => ({
      txHash: r.tx_hash,
      seq: Number(r.seq),
      circuit: r.circuit,
      ledger: Number(r.ledger),
      closedAt: r.closed_at instanceof Date ? r.closed_at.toISOString() : String(r.closed_at),
      nullifiers: r.nullifiers.map(toHex),
      outputs: (byTx.get(r.tx_hash) ?? []).map((o) => ({ commitment: toHex(o.commitment), cAuditor: o.c_auditor.map(toHex) })),
      publicReveal:
        r.reveal_asset_id && r.reveal_amount && r.reveal_recipient
          ? {
              assetId: toHex(r.reveal_asset_id),
              amount: bufToBig(r.reveal_amount).toString(),
              recipient: toHex(r.reveal_recipient),
            }
          : undefined,
    }));
    const last = rows.at(-1);
    res.json({ transactions, nextBefore: last ? Number(last.seq) : null });
  }));

  app.get('/v1/ciphertexts', h(async (req, res) => {
    const since = Number(req.query.since ?? 0);
    const limit = Math.min(Number(req.query.limit ?? 500), 2000);
    const rows = await repo.getCiphertexts(since, limit);
    const last = rows.at(-1);
    res.json({
      items: rows.map((r) => ({
        txHash: r.tx_hash,
        outputIndex: r.output_index,
        commitment: toHex(r.commitment),
        circuit: r.circuit,
        ledger: Number(r.ledger),
        cAuditor: r.c_auditor.map(toHex),
        cRecipient: r.c_recipient.map(toHex),
      })),
      next: last ? Number(last.id) : since,
    });
  }));

  app.get('/v1/frozen', h(async (_req, res) => {
    const f = await repo.getFrozen();
    res.json({ frozenRoot: f.frozenRoot ? toHex(f.frozenRoot) : null, frozen: f.frozen.map(toHex) });
  }));

  app.get('/v1/registry/asset/:assetId', h(async (req, res) => {
    let id: Buffer;
    try {
      id = fromHex(req.params.assetId!);
    } catch {
      return badReq(res, 'assetId must be hex');
    }
    const sac = await repo.getAsset(id);
    if (!sac) return notFound(res, 'asset not registered');
    return res.json({ assetId: toHex(id), sac });
  }));

  app.get('/v1/registry/transparent/:recipient', h(async (req, res) => {
    let rcpt: Buffer;
    try {
      rcpt = fromHex(req.params.recipient!);
    } catch {
      return badReq(res, 'recipient must be hex');
    }
    const addr = await repo.getTransparent(rcpt);
    if (!addr) return notFound(res, 'recipient not registered');
    return res.json({ recipient: toHex(rcpt), addr });
  }));

  return app;
}
