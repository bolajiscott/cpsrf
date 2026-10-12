import pg from 'pg';
import { getEnv } from '../config/env.js';

let pool;

export function getPool() {
  if (!pool) {
    const env = getEnv();
    pool = new pg.Pool({
      connectionString: env.DATABASE_URL,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
      // Require TLS to the database in production; adjust per your hosting provider's CA setup.
      ssl: env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
    });
    pool.on('error', (err) => {
      // eslint-disable-next-line no-console
      console.error('[DB_POOL_ERROR]', err.message);
    });
  }
  return pool;
}

export async function closePool() {
  if (pool) {
    await pool.end();
    pool = undefined;
  }
}
