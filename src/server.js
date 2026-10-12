import { buildApp } from './app.js';
import { getEnv } from './config/env.js';

const env = getEnv();
const app = buildApp();

const server = app.listen(env.PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`CPSRF/SRF V4 API (Phase 1) listening on port ${env.PORT} [${env.NODE_ENV}]`);
});

function shutdown(signal) {
  // eslint-disable-next-line no-console
  console.log(`${signal} received, shutting down gracefully...`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
