import 'dotenv/config';

const REQUIRED_VARS = [
  'DATABASE_URL',
  'JWT_SIGNING_SECRET',
  'CSRF_SECRET',
];

let cached;

export function getEnv() {
  if (cached) return cached;

  const missing = REQUIRED_VARS.filter((key) => !process.env[key] || process.env[key].startsWith('CHANGE_ME'));
  if (missing.length > 0) {
    throw new Error(
      `Missing or placeholder required environment variables: ${missing.join(', ')}. ` +
      `Copy .env.example to .env and set real values before starting the server.`
    );
  }

  cached = {
    NODE_ENV: process.env.NODE_ENV ?? 'development',
    PORT: Number(process.env.PORT ?? 4000),
    DATABASE_URL: process.env.DATABASE_URL,
    JWT_SIGNING_SECRET: process.env.JWT_SIGNING_SECRET,
    JWT_ACCESS_TOKEN_TTL_SECONDS: Number(process.env.JWT_ACCESS_TOKEN_TTL_SECONDS ?? 900),
    JWT_REFRESH_TOKEN_TTL_SECONDS: Number(process.env.JWT_REFRESH_TOKEN_TTL_SECONDS ?? 1209600),
    COOKIE_SECURE: process.env.COOKIE_SECURE !== 'false',
    COOKIE_DOMAIN: process.env.COOKIE_DOMAIN,
    CSRF_SECRET: process.env.CSRF_SECRET,
    TOTP_ISSUER: process.env.TOTP_ISSUER ?? 'CPSRF-SRF',
    LOGIN_RATE_LIMIT_WINDOW_MS: Number(process.env.LOGIN_RATE_LIMIT_WINDOW_MS ?? 900000),
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS: Number(process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS ?? 8),
  };
  return cached;
}
