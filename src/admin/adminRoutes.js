import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../auth/authMiddleware.js';
import { requirePermission } from '../rbac/rbacMiddleware.js';
import { PERMISSIONS, isKnownRole, ROLES } from '../rbac/roles.js';
import { createUser, AuthError } from '../auth/authService.js';

// Invite-only provisioning, confirmed by CPSRF leadership: CPSRF's roles are internal
// staff/reviewers, not public sign-ups, so there is deliberately no self-registration
// route anywhere in this app. The ONLY way a user account comes into existence is an
// existing User-Manage-permitted admin calling this route. New accounts are created
// with mfa_enabled=false; if the assigned role is in MFA_REQUIRED_ROLES, the new user
// will be routed through mandatory MFA enrollment on their first login (see
// authService.loginWithPassword) before they get any access.

const router = Router();

const createUserSchema = z.object({
  email: z.string().email(),
  // Temporary/invite password: the admin sets this and communicates it out-of-band
  // (e.g. verbally, or a one-time-use channel); there is no email-based invite link
  // in Phase 1. Forcing a password reset on first login is a Phase 2+ enhancement.
  password: z.string().min(12).max(256),
  displayName: z.string().min(1).max(200),
  role: z.string().refine(isKnownRole, { message: 'Unknown role' }),
});

router.post(
  '/users',
  requireAuth,
  requirePermission(PERMISSIONS.USER_MANAGE),
  async (req, res) => {
    const parsed = createUserSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid request', details: parsed.error.flatten() });
    }
    try {
      const user = await createUser({
        email: parsed.data.email,
        password: parsed.data.password,
        displayName: parsed.data.displayName,
        role: parsed.data.role,
        actorId: req.user.id,
        actorRole: req.user.role,
      });
      return res.status(201).json({ user });
    } catch (err) {
      if (err instanceof AuthError) return res.status(err.statusCode).json({ error: err.message });
      if (err && err.code === '23505') { // Postgres unique_violation (email already exists)
        return res.status(409).json({ error: 'A user with that email already exists' });
      }
      // eslint-disable-next-line no-console
      console.error('[ADMIN_CREATE_USER_ERROR]', err);
      return res.status(500).json({ error: 'Internal error' });
    }
  }
);

// Reference list for the admin UI to populate a role picker - not a permissions leak,
// since role names themselves aren't sensitive and RBAC is enforced server-side regardless.
router.get('/roles', requireAuth, requirePermission(PERMISSIONS.USER_MANAGE), async (req, res) => {
  return res.status(200).json({ roles: Object.values(ROLES) });
});

export default router;
