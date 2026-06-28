/** PostgreSQL connection pool. `DATABASE_URL` is required (Railway Postgres). */

import pg from 'pg';
import { DATABASE_URL } from '../config.js';

const { Pool } = pg;

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is required (set the Railway Postgres connection string)');
}

export const pool = new Pool({ connectionString: DATABASE_URL });

export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: unknown[] = [],
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params as unknown[]);
}
