import { randomBytes, createHash } from 'node:crypto';
import { getPool } from '../db/pool.js';
import { getEnv } from '../config/env.js';
import { hashPassword, verifyPassword, needsRehash } from '../security/crypto/passwordHash.js';
import {
  generateBase32Secret, buildOtpAuthUri, verifyTotp, generateRecoveryCodes,
} from '../security/crypto/totp.js';
import { signJwt, verifyJwt } from '../security/crypto/jwt.js';
import { recordAuditEvent } from '../audit/auditLogger.js';
import { isKnownRole, isMfaRequiredForRole } from '../rbac/roles.js';

const MAX_FAILED_LOGINS_BEFORE_LOCK = 6;
const LOCK_DURATION_MINUTES = 15;
const MFA_SETUP_TICKET_TTL_SECONDS = 900; // 15 min - enough time to scan a QR and confirm

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Step 1 of login: verify email + password. Does NOT issue tokens yet if MFA is enabled -
 * returns a short-lived "mfa_pending" ticket the client must exchange with a TOTP code.
 */
export async function loginWithPassword({ email, password, ipAddress }) {
  const env = getEnv();
  const pool = getPool();
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = rows[0];

  // Constant-shape response whether or not the user exists, to avoid user enumeration.
  const dummyHash = 'scrypt$131072$8$1$00$00';
  if (!user) {
    await verifyPassword(password, dummyHash);
    await recordAuditEvent({ action: 'auth.login_failure', outcome: 'failure', metadata: { reason: 'no_such_user' }, ipAddress });
    throw new AuthError('Invalid email or password', 401);
  }

  if (user.status !== 'active') {
    await recordAuditEvent({ actorId: user.id, actorRole: user.role, action: 'auth.login_failure', outcome: 'failure', metadata: { reason: 'account_not_active' }, ipAddress });
    throw new AuthError('Invalid email or password', 401);
  }

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    await recordAuditEvent({ actorId: user.id, actorRole: user.role, action: 'auth.login_failure', outcome: 'failure', metadata: { reason: 'account_locked' }, ipAddress });
    throw new AuthError('Account temporarily locked due to repeated failed attempts', 423);
  }

  const passwordOk = await verifyPassword(password, user.password_hash);
  if (!passwordOk) {
    const newFailCount = user.failed_login_count + 1;
    const shouldLock = newFailCount >= MAX_FAILED_LOGINS_BEFORE_LOCK;
    await pool.query(
      `UPDATE users SET failed_login_count = $1, locked_until = $2, updated_at = now() WHERE id = $3`,
      [
        shouldLock ? 0 : newFailCount,
        shouldLock ? new Date(Date.now() + LOCK_DURATION_MINUTES * 60000) : null,
        user.id,
      ]
    );
    await recordAuditEvent({
      actorId: user.id, actorRole: user.role, action: 'auth.login_failure', outcome: 'failure',
      metadata: { reason: 'bad_password', locked: shouldLock }, ipAddress,
    });
    throw new AuthError('Invalid email or password', 401);
  }

  // Reset failure counter on success, and transparently upgrade the hash if cost
  // parameters have changed since this password was last set.
  const updates = { failed_login_count: 0, locked_until: null };
  if (needsRehash(user.password_hash)) {
    updates.password_hash = await hashPassword(password);
  }
  await pool.query(
    `UPDATE users SET failed_login_count = $1, locked_until = $2, password_hash = COALESCE($3, password_hash), updated_at = now() WHERE id = $4`,
    [updates.failed_login_count, updates.locked_until, updates.password_hash ?? null, user.id]
  );

  if (user.mfa_enabled) {
    const mfaTicket = signJwt(
      { sub: user.id, purpose: 'mfa_pending', exp: Math.floor(Date.now() / 1000) + 300 },
      env.JWT_SIGNING_SECRET
    );
    await recordAuditEvent({ actorId: user.id, actorRole: user.role, action: 'auth.password_ok_mfa_required', outcome: 'success', ipAddress });
    return { status: 'mfa_required', mfaTicket };
  }

  // MFA not enabled. Policy confirmed by CPSRF leadership: Super Administrator, Managing
  // Editor, Authorised Approver, Legal Reviewer, and Humanitarian Data Officer MUST
  // enroll in MFA before receiving a full access token. Issue a narrowly-scoped setup
  // ticket instead - it only satisfies requireAuthForMfaSetup on the enrollment routes
  // (src/auth/authMiddleware.js), and is rejected by requireAuth everywhere else, so
  // there's no path to a protected resource without completing enrollment first.
  if (isMfaRequiredForRole(user.role)) {
    const setupToken = signJwt(
      {
        sub: user.id,
        role: user.role,
        purpose: 'mfa_setup_required',
        exp: Math.floor(Date.now() / 1000) + MFA_SETUP_TICKET_TTL_SECONDS,
      },
      env.JWT_SIGNING_SECRET
    );
    await recordAuditEvent({
      actorId: user.id, actorRole: user.role, action: 'auth.mfa_setup_required', outcome: 'info', ipAddress,
    });
    return { status: 'mfa_setup_required', setupToken };
  }

  const tokens = await issueTokenPair(user, { ipAddress });
  await recordAuditEvent({ actorId: user.id, actorRole: user.role, action: 'auth.login_success', outcome: 'success', ipAddress });
  return { status: 'authenticated', ...tokens, user: publicUser(user) };
}

/**
 * Step 2 of login: exchange an mfa_pending ticket + TOTP code for real tokens.
 */
export async function verifyMfaAndIssueTokens({ mfaTicket, totpCode, ipAddress }) {
  const env = getEnv();
  const pool = getPool();

  let ticketPayload;
  try {
    ticketPayload = verifyJwt(mfaTicket, env.JWT_SIGNING_SECRET);
  } catch {
    throw new AuthError('MFA session expired or invalid, please log in again', 401);
  }
  if (ticketPayload.purpose !== 'mfa_pending') {
    throw new AuthError('Invalid MFA session', 401);
  }

  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [ticketPayload.sub]);
  const user = rows[0];
  if (!user || !user.mfa_enabled || !user.mfa_totp_secret) {
    throw new AuthError('MFA not configured for this account', 400);
  }

  const result = verifyTotp(user.mfa_totp_secret, totpCode, {
    // Replay protection: reject a code for a step we've already accepted.
  });

  if (!result.valid || (user.mfa_last_used_step != null && result.stepUsed <= Number(user.mfa_last_used_step))) {
    await recordAuditEvent({ actorId: user.id, actorRole: user.role, action: 'auth.mfa_failure', outcome: 'failure', ipAddress });
    throw new AuthError('Invalid or expired authentication code', 401);
  }

  await pool.query('UPDATE users SET mfa_last_used_step = $1, updated_at = now() WHERE id = $2', [result.stepUsed, user.id]);

  const tokens = await issueTokenPair(user, { ipAddress });
  await recordAuditEvent({ actorId: user.id, actorRole: user.role, action: 'auth.mfa_success_login', outcome: 'success', ipAddress });
  return { status: 'authenticated', ...tokens, user: publicUser(user) };
}

/**
 * Begin MFA enrollment for an already-authenticated user: generate a secret and
 * otpauth:// URI for QR display. The secret is NOT persisted until confirmed via
 * confirmMfaEnrollment, so an abandoned enrollment never leaves a half-set-up MFA state.
 */
export function beginMfaEnrollment({ user }) {
  const env = getEnv();
  const secret = generateBase32Secret();
  const otpauthUri = buildOtpAuthUri({ secret, accountLabel: user.email, issuer: env.TOTP_ISSUER });
  // Short-lived signed ticket carrying the pending secret, so we don't need a DB write
  // for an unconfirmed enrollment attempt.
  const enrollmentTicket = signJwt(
    { sub: user.id, purpose: 'mfa_enroll', secret, exp: Math.floor(Date.now() / 1000) + 600 },
    env.JWT_SIGNING_SECRET
  );
  return { otpauthUri, secret, enrollmentTicket };
}

export async function confirmMfaEnrollment({ user, enrollmentTicket, totpCode }) {
  const env = getEnv();
  const pool = getPool();
  let payload;
  try {
    payload = verifyJwt(enrollmentTicket, env.JWT_SIGNING_SECRET);
  } catch {
    throw new AuthError('Enrollment session expired, please restart MFA setup', 400);
  }
  if (payload.purpose !== 'mfa_enroll' || payload.sub !== user.id) {
    throw new AuthError('Invalid enrollment session', 400);
  }

  const result = verifyTotp(payload.secret, totpCode);
  if (!result.valid) {
    throw new AuthError('Code did not match - check your authenticator app and try again', 400);
  }

  const recoveryCodes = generateRecoveryCodes(10);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'UPDATE users SET mfa_enabled = true, mfa_totp_secret = $1, mfa_last_used_step = $2, updated_at = now() WHERE id = $3',
      [payload.secret, result.stepUsed, user.id]
    );
    await client.query('DELETE FROM mfa_recovery_codes WHERE user_id = $1', [user.id]);
    for (const code of recoveryCodes) {
      const codeHash = await hashPassword(code.replace('-', '') + 'x'.repeat(6)); // pad to meet min length
      await client.query('INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)', [user.id, codeHash]);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  await recordAuditEvent({ actorId: user.id, actorRole: user.role, action: 'auth.mfa_enrolled', outcome: 'success' });

  // Issue a full token pair now that MFA is enrolled. This covers both the voluntary
  // enrollment case (already had a full session) and the mandatory-MFA bootstrap case
  // (only had a restricted mfa_setup_required ticket) - either way, enrollment
  // completion is the moment a full session should exist, without a second login.
  const tokens = await issueTokenPair(user);
  return { recoveryCodes, tokens }; // recoveryCodes shown once; caller must instruct the user to store them securely
}

async function issueTokenPair(user, { ipAddress, userAgent } = {}) {
  const env = getEnv();
  const pool = getPool();

  const accessToken = signJwt(
    {
      sub: user.id,
      role: user.role,
      purpose: 'access',
      exp: Math.floor(Date.now() / 1000) + env.JWT_ACCESS_TOKEN_TTL_SECONDS,
    },
    env.JWT_SIGNING_SECRET
  );

  const rawRefreshToken = randomBytes(48).toString('hex');
  const refreshExpiresAt = new Date(Date.now() + env.JWT_REFRESH_TOKEN_TTL_SECONDS * 1000);
  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent)
     VALUES ($1, $2, $3, $4, $5)`,
    [user.id, hashToken(rawRefreshToken), refreshExpiresAt, ipAddress ?? null, userAgent ?? null]
  );

  return { accessToken, refreshToken: rawRefreshToken, refreshExpiresAt };
}

/**
 * Rotate a refresh token: validate the presented one, revoke it, issue a new pair.
 * Rotation-on-use means a stolen-then-reused refresh token is detectable (the
 * legitimate client's next refresh will fail because it's already been replaced).
 */
export async function refreshTokens({ refreshToken, ipAddress, userAgent }) {
  const pool = getPool();
  const tokenHash = hashToken(refreshToken);
  const { rows } = await pool.query(
    `SELECT rt.*, u.role, u.status FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id WHERE rt.token_hash = $1`,
    [tokenHash]
  );
  const record = rows[0];
  if (!record || record.revoked_at || new Date(record.expires_at) < new Date() || record.status !== 'active') {
    if (record) {
      // Reused/expired/revoked token presented - revoke the whole chain defensively.
      await pool.query('UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL', [record.user_id]);
      await recordAuditEvent({ actorId: record.user_id, actorRole: record.role, action: 'auth.refresh_token_reuse_detected', outcome: 'failure', ipAddress });
    }
    throw new AuthError('Session expired, please log in again', 401);
  }

  await pool.query('UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1', [record.id]);
  const { rows: userRows } = await pool.query('SELECT * FROM users WHERE id = $1', [record.user_id]);
  const tokens = await issueTokenPair(userRows[0], { ipAddress, userAgent });
  await recordAuditEvent({ actorId: record.user_id, actorRole: record.role, action: 'auth.token_refreshed', outcome: 'success', ipAddress });
  return tokens;
}

export async function revokeAllSessionsForUser(userId) {
  const pool = getPool();
  await pool.query('UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL', [userId]);
}

export async function createUser({ email, password, displayName, role, actorId, actorRole }) {
  if (!isKnownRole(role)) throw new AuthError(`Unknown role: ${role}`, 400);
  const pool = getPool();
  const passwordHash = await hashPassword(password);
  const { rows } = await pool.query(
    `INSERT INTO users (email, display_name, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *`,
    [email, displayName, passwordHash, role]
  );
  await recordAuditEvent({ actorId, actorRole, action: 'user.created', outcome: 'success', metadata: { newUserEmail: email, role } });
  return publicUser(rows[0]);
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.display_name,
    role: user.role,
    mfaEnabled: user.mfa_enabled,
  };
}

export class AuthError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.statusCode = statusCode;
  }
}
