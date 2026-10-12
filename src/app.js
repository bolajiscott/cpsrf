import express from 'express';
import cookieParser from 'cookie-parser';
import { securityHeaders, generalRateLimiter, buildCsrfProtection } from './middleware/security.js';
import authRoutes from './auth/authRoutes.js';
import adminRoutes from './admin/adminRoutes.js';
import { requireAuth } from './auth/authMiddleware.js';
import { requirePermission } from './rbac/rbacMiddleware.js';
import { PERMISSIONS } from './rbac/roles.js';
import { getPool } from './db/pool.js';

export function buildApp() {
  const app = express();

  app.set('trust proxy', 1); // required for req.ip / rate limiting behind a load balancer or CDN/WAF
  app.disable('x-powered-by');

  app.use(securityHeaders());
  app.use(express.json({ limit: '200kb' }));
  app.use(cookieParser());
  app.use(generalRateLimiter());

  const { doubleCsrfProtection, generateCsrfToken } = buildCsrfProtection();

  // Public endpoint for the frontend to fetch a CSRF token before making state-changing calls.
  app.get('/api/v1/csrf-token', (req, res) => {
    const token = generateCsrfToken(req, res);
    res.status(200).json({ csrfToken: token });
  });

  // Apply CSRF protection to all state-changing methods except login (no session yet
  // to attach a CSRF cookie to on the very first request) - login is instead protected
  // by rate limiting + SameSite cookies + CORS restriction at the infra layer.
  app.use((req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
    if (req.path === '/api/v1/auth/login') return next();
    return doubleCsrfProtection(req, res, next);
  });

  app.use('/api/v1/auth', authRoutes);
  app.use('/api/v1/admin', adminRoutes);

  // Example Phase-1 protected route demonstrating the RBAC pattern; Phase 2 replaces
  // this with the real /admin/audit-log endpoint backed by the audit_events table.
  app.get(
    '/api/v1/admin/audit-log',
    requireAuth,
    requirePermission(PERMISSIONS.AUDIT_LOG_READ),
    async (req, res) => {
      const pool = getPool();
      const { rows } = await pool.query(
        'SELECT id, actor_id, actor_role, action, resource, outcome, metadata, created_at FROM audit_events ORDER BY created_at DESC LIMIT 100'
      );
      res.status(200).json({ events: rows });
    }
  );

  app.get('/api/v1/health', (req, res) => res.status(200).json({ status: 'ok' }));

  app.use((req, res) => res.status(404).json({ error: 'Not found' }));

  // Centralised error handler - never leak stack traces or internal error detail to clients.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err && err.code === 'EBADCSRFTOKEN') {
      return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
    // eslint-disable-next-line no-console
    console.error('[UNHANDLED_ERROR]', err);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
