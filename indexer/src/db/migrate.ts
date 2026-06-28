/** Apply the schema (idempotent). Run via `npm run -w @finnes/indexer migrate`,
 *  and also called automatically on service boot. */

import { pool } from './client.js';
import { SCHEMA_SQL } from './schema.js';

export async function migrate(): Promise<void> {
  await pool.query(SCHEMA_SQL);
}

// Allow direct execution: `tsx src/db/migrate.ts`.
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  migrate()
    .then(() => {
      console.log('[migrate] schema applied');
      return pool.end();
    })
    .then(() => process.exit(0))
    .catch((e: unknown) => {
      console.error('[migrate] failed:', e);
      process.exit(1);
    });
}
