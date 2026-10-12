// Structured audit logging. Every privileged action - auth events, RBAC decisions,
// content workflow transitions, protected-data access, partner document access -
// should call recordAuditEvent(). Writes are append-only at the application layer;
// DB-level protection (REVOKE UPDATE/DELETE for the app role on audit_events) is set
// up in db/schema.sql so a compromised app credential still can't rewrite history.

import { getPool } from '../db/pool.js';

/**
 * @param {Object} event
 * @param {string|null} event.actorId - user id performing the action, or null for system/anonymous
 * @param {string|null} event.actorRole - role at time of action (roles can change later; snapshot it)
 * @param {string} event.action - dot-namespaced action, e.g. 'auth.login_success', 'content.transition'
 * @param {string} event.resource - route or entity reference the action targeted
 * @param {'granted'|'denied'|'success'|'failure'|'info'} event.outcome
 * @param {Object} [event.metadata] - additional structured context; NEVER put secrets/tokens/passwords here
 * @param {string} [event.ipAddress]
 */
export async function recordAuditEvent(event) {
  const pool = getPool();
  const {
    actorId = null,
    actorRole = null,
    action,
    resource = null,
    outcome,
    metadata = {},
    ipAddress = null,
  } = event;

  if (!action || !outcome) {
    throw new Error('recordAuditEvent requires action and outcome');
  }

  // Defensive redaction: strip common secret-shaped keys even if a caller forgets.
  const safeMetadata = redactSecrets(metadata);

  try {
    await pool.query(
      `INSERT INTO audit_events (actor_id, actor_role, action, resource, outcome, metadata, ip_address, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now())`,
      [actorId, actorRole, action, resource, outcome, JSON.stringify(safeMetadata), ipAddress]
    );
  } catch (err) {
    // Audit logging must never crash the request path, but a failure here is itself
    // a security-relevant event - fall back to stderr so it's captured by process logs.
    // eslint-disable-next-line no-console
    console.error('[AUDIT_WRITE_FAILURE]', {
      action, outcome, resource, error: err.message,
    });
  }
}

const SECRET_KEY_PATTERN = /(password|secret|token|mfa_?code|totp|authorization|cookie)/i;

function redactSecrets(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  const out = Array.isArray(obj) ? [] : {};
  for (const [key, value] of Object.entries(obj)) {
    if (SECRET_KEY_PATTERN.test(key)) {
      out[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      out[key] = redactSecrets(value);
    } else {
      out[key] = value;
    }
  }
  return out;
}
