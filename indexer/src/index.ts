/**
 * Indexer entrypoint (FIN-029). Boot order: migrate schema → rebuild in-memory
 * trees from the DB → start the API (serves progress immediately) → backfill from
 * genesis → continuously tail. See docs/INDEXER_IMPLEMENTATION.md.
 */

import { migrate } from './db/migrate.js';
import * as worker from './ingest/worker.js';
import { createApp } from './api/server.js';
import { PORT, CONTRACT_ID } from './config.js';

async function main(): Promise<void> {
  console.log(`[boot] Finnes indexer — contract ${CONTRACT_ID}`);
  await migrate();
  await worker.boot();

  const app = createApp();
  app.listen(PORT, () => console.log(`[api] listening on :${PORT}`));

  // Ingestion runs after the API is up. A self-check HALT stops ingestion but must
  // NOT crash the process — the API keeps serving the last consistent state and
  // /health reports ok:false. (Crashing here would make PM2 restart-loop.)
  try {
    await worker.backfill();
    worker.startTail();
  } catch (e) {
    console.error('[worker] ingestion stopped:', e instanceof Error ? e.message : e);
  }
}

main().catch((e: unknown) => {
  console.error('[boot] fatal:', e);
  process.exit(1);
});
