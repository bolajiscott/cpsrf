import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { getEnv } from '../config/env.js';
import { requireAuth, requireAuthForMfaSetup } from './authMiddleware.js';
import {
  loginWithPassword, verifyMfaAndIssueTokens, beginMfaEnrollment,
  confirmMfaEnrollment, refreshTokens, revokeAllSessionsForUser, AuthError,
} from './authService.js';

const router = Router();

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(256),
});

const mfaVerifySchema = z.object({
  mfaTicket: z.string().min(1),
  totpCode: z.string().min(6).max(6),
});

const mfaConfirmSchema = z.object({
  enrollmentTicket: z.string().min(1),
  totpCode: z.string().min(6).max(6),
});

function loginRateLimiter() {
  const env = getEnv();
  return rateLimit({
    windowMs: env.LOGIN_RATE_LIMIT_WINDOW_MS,
    max: env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
    standardHeaders: true,
    legacyHeaders: false,
    // Key by IP + attempted email so one abusive IP can't lock out unrelated accounts,
    // while still rate-limiting credential-stuffing against a single account.
    keyGenerator: (req) => `${req.ip}:${req.body?.email ?? 'unknown'}`,
    message: { error: 'Too many login attempts, please try again later' },
  });
}

function setAuthCookies(res, { accessToken, refreshToken, refreshExpiresAt }) {
  const env = getEnv();
  const cookieBase = {
    httpOnly: true,
    secure: env.COOKIE_SECURE,
    sameSite: 'lax',
    domain: env.COOKIE_DOMAIN,
    path: '/',
  };
  res.cookie('access_token', accessToken, { ...cookieBase, maxAge: env.JWT_ACCESS_TOKEN_TTL_SECONDS * 1000 });
  res.cookie('refresh_token', refreshToken, {
    ...cookieBase,
    path: '/api/v1/auth/refresh', // scope refresh cookie narrowly
    expires: refreshExpiresAt,
  });
}

// A restricted setup token is delivered the same way as a real access token (an
// httpOnly access_token cookie), but short-lived and with no refresh cookie - it's
// only good for the enrollment routes and expires on its own if enrollment isn't
// completed, rather than lingering as a semi-authenticated session.
function setMfaSetupCookie(res, setupToken) {
  const env = getEnv();
  res.cookie('access_token', setupToken, {
    httpOnly: true,
    secure: env.COOKIE_SECURE,
    sameSite: 'lax',
    domain: env.COOKIE_DOMAIN,
    path: '/',
    maxAge: 15 * 60 * 1000,
  });
}

router.post('/login', loginRateLimiter(), async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid request' });

  try {
    const result = await loginWithPassword({
      email: parsed.data.email,
      password: parsed.data.password,
      ipAddress: req.ip,
    });
    if (result.status === 'mfa_required') {
      return res.status(200).json({ status: 'mfa_required', mfaTicket: result.mfaTicket });
    }
    if (result.status === 'mfa_setup_required') {
      setMfaSetupCookie(res, result.setupToken);
      return res.status(200).json({
        status: 'mfa_setup_required',
        message: 'Multi-factor authentication is mandatory for this role. Call /mfa/enroll/start to begin enrollment.',
      });
    }
    setAuthCookies(res, result);
    return res.status(200).json({ status: 'authenticated', user: result.user });
  } catch (err) {
    if (err instanceof AuthError) return res.status(err.statusCode).json({ error: err.message });
    // eslint-disable-next-line no-console
    console.error('[LOGIN_ERROR]', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/mfa/verify', loginRateLimiter(), async (req, res) => {
  const parsed = mfaVerifySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid request' });

  try {
    const result = await verifyMfaAndIssueTokens({
      mfaTicket: parsed.data.mfaTicket,
      totpCode: parsed.data.totpCode,
      ipAddress: req.ip,
    });
    setAuthCookies(res, result);
    return res.status(200).json({ status: 'authenticated', user: result.user });
  } catch (err) {
    if (err instanceof AuthError) return res.status(err.statusCode).json({ error: err.message });
    // eslint-disable-next-line no-console
    console.error('[MFA_VERIFY_ERROR]', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// requireAuthForMfaSetup (not plain requireAuth) so a user in an MFA-mandatory role who
// hasn't enrolled yet - and therefore only holds a restricted mfa_setup_required ticket -
// can reach these two routes and nowhere else. Already-authenticated users with a full
// session can also reach these routes, for voluntary/optional MFA setup.
router.post('/mfa/enroll/start', requireAuthForMfaSetup, async (req, res) => {
  const { otpauthUri, secret, enrollmentTicket } = beginMfaEnrollment({ user: req.user });
  // secret is also returned in plaintext for manual entry (in case QR scanning isn't available);
  // the frontend should render otpauthUri as a QR code.
  return res.status(200).json({ otpauthUri, secret, enrollmentTicket });
});

router.post('/mfa/enroll/confirm', requireAuthForMfaSetup, async (req, res) => {
  const parsed = mfaConfirmSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid request' });

  try {
    const { recoveryCodes, tokens } = await confirmMfaEnrollment({
      user: req.user,
      enrollmentTicket: parsed.data.enrollmentTicket,
      totpCode: parsed.data.totpCode,
    });
    // Enrollment just completed - upgrade from the restricted setup ticket (or the
    // existing full session, for voluntary enrollment) to a full authenticated session.
    setAuthCookies(res, tokens);
    return res.status(200).json({
      status: 'mfa_enabled',
      recoveryCodes,
      notice: 'Store these recovery codes securely now - they will not be shown again.',
    });
  } catch (err) {
    if (err instanceof AuthError) return res.status(err.statusCode).json({ error: err.message });
    // eslint-disable-next-line no-console
    console.error('[MFA_ENROLL_ERROR]', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/refresh', async (req, res) => {
  const refreshToken = req.cookies?.refresh_token;
  if (!refreshToken) return res.status(401).json({ error: 'No session' });
  try {
    const tokens = await refreshTokens({ refreshToken, ipAddress: req.ip, userAgent: req.get('user-agent') });
    setAuthCookies(res, tokens);
    return res.status(200).json({ status: 'refreshed' });
  } catch (err) {
    if (err instanceof AuthError) return res.status(err.statusCode).json({ error: err.message });
    // eslint-disable-next-line no-console
    console.error('[REFRESH_ERROR]', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

router.post('/logout', requireAuth, async (req, res) => {
  await revokeAllSessionsForUser(req.user.id);
  res.clearCookie('access_token', { path: '/' });
  res.clearCookie('refresh_token', { path: '/api/v1/auth/refresh' });
  return res.status(200).json({ status: 'logged_out' });
});

router.get('/me', requireAuth, async (req, res) => {
  return res.status(200).json({ id: req.user.id, role: req.user.role });
});

export default router;
