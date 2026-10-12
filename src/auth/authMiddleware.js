import { verifyJwt } from '../security/crypto/jwt.js';
import { getEnv } from '../config/env.js';

/**
 * Populates req.user from the access token cookie. This is the ONLY place req.user
 * is set - never trust a client-supplied user id/role from the request body/headers.
 */
export function requireAuth(req, res, next) {
  const env = getEnv();
  const token = req.cookies?.access_token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const payload = verifyJwt(token, env.JWT_SIGNING_SECRET);
    if (payload.purpose !== 'access') {
      return res.status(401).json({ error: 'Authentication required' });
    }
    req.user = { id: payload.sub, role: payload.role };
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired, please log in again' });
  }
}

/**
 * Like requireAuth, but also accepts a narrowly-scoped 'mfa_setup_required' token -
 * the token issued at login to a user in an MFA-mandatory role who hasn't enrolled yet.
 * Use ONLY on the MFA enrollment routes. A token with this purpose is rejected by
 * plain requireAuth everywhere else, so it cannot be used to reach any other endpoint -
 * enforcement doesn't depend on this middleware being applied correctly elsewhere,
 * it's enforced by requireAuth's strict purpose check on every other protected route.
 */
export function requireAuthForMfaSetup(req, res, next) {
  const env = getEnv();
  const token = req.cookies?.access_token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const payload = verifyJwt(token, env.JWT_SIGNING_SECRET);
    if (payload.purpose !== 'access' && payload.purpose !== 'mfa_setup_required') {
      return res.status(401).json({ error: 'Authentication required' });
    }
    req.user = { id: payload.sub, role: payload.role };
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired, please log in again' });
  }
}

/**
 * Same as requireAuth but does not fail the request if no/invalid token is present -
 * useful for endpoints that behave differently for logged-in vs anonymous users.
 */
export function optionalAuth(req, res, next) {
  const env = getEnv();
  const token = req.cookies?.access_token;
  if (token) {
    try {
      const payload = verifyJwt(token, env.JWT_SIGNING_SECRET);
      if (payload.purpose === 'access') {
        req.user = { id: payload.sub, role: payload.role };
      }
    } catch {
      // ignore - treated as anonymous
    }
  }
  next();
}
