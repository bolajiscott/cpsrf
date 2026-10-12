import { roleHasPermission } from './roles.js';
import { recordAuditEvent } from '../audit/auditLogger.js';

/**
 * Express middleware factory. Usage: router.post('/x', requireAuth, requirePermission(P.CONTENT_APPROVE_PUBLISH), handler)
 * MUST run after requireAuth (expects req.user populated from a verified token, never a client header/body claim).
 */
export function requirePermission(permission) {
  return async function rbacGuard(req, res, next) {
    const user = req.user;
    if (!user || !user.role) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const allowed = roleHasPermission(user.role, permission);

    if (!allowed) {
      await recordAuditEvent({
        actorId: user.id,
        actorRole: user.role,
        action: 'rbac.denied',
        resource: req.originalUrl,
        outcome: 'denied',
        metadata: { requiredPermission: permission, method: req.method },
      });
      // Deliberately generic - do not confirm the resource exists or what permission
      // would have been required, beyond what's already implied by the route itself.
      return res.status(403).json({ error: 'Forbidden' });
    }

    await recordAuditEvent({
      actorId: user.id,
      actorRole: user.role,
      action: 'rbac.granted',
      resource: req.originalUrl,
      outcome: 'granted',
      metadata: { permission, method: req.method },
    });

    next();
  };
}

/**
 * Stricter variant for a fixed allow-list of roles, for routes that are role-specific
 * rather than permission-specific (e.g. only Auditor may hit /admin/audit-log/export).
 */
export function requireRole(...allowedRoles) {
  return async function roleGuard(req, res, next) {
    const user = req.user;
    if (!user || !user.role) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!allowedRoles.includes(user.role)) {
      await recordAuditEvent({
        actorId: user.id,
        actorRole: user.role,
        action: 'rbac.role_denied',
        resource: req.originalUrl,
        outcome: 'denied',
        metadata: { allowedRoles, method: req.method },
      });
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}
