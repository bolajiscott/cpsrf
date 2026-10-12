import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { doubleCsrf } from 'csrf-csrf';
import { getEnv } from '../config/env.js';

export function securityHeaders() {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: true,
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  });
}

export function generalRateLimiter() {
  return rateLimit({
    windowMs: 60_000,
    max: 300, // generous default for normal browsing/API use; tighten per-route as needed
    standardHeaders: true,
    legacyHeaders: false,
  });
}

// CSRF protection for cookie-authenticated state-changing requests. Not needed on
// routes that only accept the Authorization header, but this app uses httpOnly
// cookies for tokens, so CSRF defense-in-depth is required.
export function buildCsrfProtection() {
  const env = getEnv();
  return doubleCsrf({
    getSecret: () => env.CSRF_SECRET,
    cookieName: env.NODE_ENV === 'production' ? '__Host-csrf' : 'csrf',
    cookieOptions: {
      httpOnly: true,
      secure: env.COOKIE_SECURE,
      sameSite: 'lax',
      path: '/',
    },
    size: 64,
    getTokenFromRequest: (req) => req.headers['x-csrf-token'],
  });
}
