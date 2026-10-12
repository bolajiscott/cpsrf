// TOTP (RFC 6238) / HOTP (RFC 4226) implementation using only node:crypto.
// Compatible with Google Authenticator, Authy, 1Password, etc. (30s step, 6 digits, SHA1 - the
// widely-supported default; SHA256/512 supported too if you want stronger issuer-side config).

import { createHmac, randomBytes } from 'node:crypto';

const DEFAULT_STEP_SECONDS = 30;
const DEFAULT_DIGITS = 6;
const DEFAULT_ALGO = 'sha1';

// Base32 (RFC 4648) - required encoding for authenticator-app secrets.
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateBase32Secret(byteLength = 20) {
  const bytes = randomBytes(byteLength);
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
  let output = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    output += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  }
  return output;
}

function base32Decode(base32) {
  const clean = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) throw new Error('Invalid base32 character in TOTP secret');
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function hotp(secretBuffer, counter, { digits = DEFAULT_DIGITS, algo = DEFAULT_ALGO } = {}) {
  const counterBuffer = Buffer.alloc(8);
  // 64-bit big-endian counter
  counterBuffer.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  counterBuffer.writeUInt32BE(counter % 2 ** 32, 4);

  const hmac = createHmac(algo, secretBuffer).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (binCode % 10 ** digits).toString().padStart(digits, '0');
  return otp;
}

export function generateTotp(base32Secret, opts = {}) {
  const step = opts.step ?? DEFAULT_STEP_SECONDS;
  const timestamp = opts.timestamp ?? Date.now();
  const counter = Math.floor(timestamp / 1000 / step);
  const secretBuffer = base32Decode(base32Secret);
  return hotp(secretBuffer, counter, opts);
}

/**
 * Verify a user-submitted TOTP code, allowing +/- `window` steps of clock drift.
 * Returns { valid, stepUsed } - stepUsed lets you enforce single-use-per-step
 * (replay protection) by recording the last accepted counter per user.
 */
export function verifyTotp(base32Secret, userCode, opts = {}) {
  const step = opts.step ?? DEFAULT_STEP_SECONDS;
  const window = opts.window ?? 1; // +/- 1 step = +/- 30s, standard tolerance
  const timestamp = opts.timestamp ?? Date.now();
  const baseCounter = Math.floor(timestamp / 1000 / step);
  const secretBuffer = base32Decode(base32Secret);
  const normalizedInput = String(userCode).trim();

  for (let errorWindow = -window; errorWindow <= window; errorWindow++) {
    const counter = baseCounter + errorWindow;
    const candidate = hotp(secretBuffer, counter, opts);
    if (timingSafeStringEqual(candidate, normalizedInput)) {
      return { valid: true, stepUsed: counter };
    }
  }
  return { valid: false, stepUsed: null };
}

function timingSafeStringEqual(a, b) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * Build an otpauth:// URI for QR-code enrollment in authenticator apps.
 */
export function buildOtpAuthUri({ secret, accountLabel, issuer }) {
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedLabel = encodeURIComponent(`${issuer}:${accountLabel}`);
  return `otpauth://totp/${encodedLabel}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}

/**
 * Generate single-use recovery codes for MFA (shown once at enrollment).
 * Store only their hashes (reuse passwordHash.js scrypt hashing) - never plaintext.
 */
export function generateRecoveryCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = randomBytes(5).toString('hex'); // 10 hex chars
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}
