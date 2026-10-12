// Password hashing using Node's built-in scrypt (node:crypto).
// Format stored in DB: scrypt$N$r$p$saltHex$hashHex
// No external dependency - this is the full credential-verification trust boundary.

import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);

// OWASP-recommended-range scrypt cost parameters (2024 guidance: N=2^17 minimum
// for interactive login; tune upward as server hardware allows).
const SCRYPT_PARAMS = Object.freeze({
  N: 2 ** 17, // CPU/memory cost
  r: 8,       // block size
  p: 1,       // parallelization
  keylen: 64,
  maxmem: 256 * 1024 * 1024,
});

/**
 * Hash a plaintext password. Returns an encoded string safe to store in the DB.
 */
export async function hashPassword(plaintext) {
  if (typeof plaintext !== 'string' || plaintext.length < 12) {
    throw new Error('Password must be a string of at least 12 characters');
  }
  const salt = randomBytes(16);
  const derivedKey = await scrypt(plaintext, salt, SCRYPT_PARAMS.keylen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: SCRYPT_PARAMS.maxmem,
  });
  return [
    'scrypt',
    SCRYPT_PARAMS.N,
    SCRYPT_PARAMS.r,
    SCRYPT_PARAMS.p,
    salt.toString('hex'),
    derivedKey.toString('hex'),
  ].join('$');
}

/**
 * Verify a plaintext password against a stored encoded hash.
 * Uses a timing-safe comparison. Never throws on mismatch - returns false.
 */
export async function verifyPassword(plaintext, encoded) {
  try {
    const [scheme, nStr, rStr, pStr, saltHex, hashHex] = String(encoded).split('$');
    if (scheme !== 'scrypt') return false;
    const N = Number(nStr);
    const r = Number(rStr);
    const p = Number(pStr);
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const derivedKey = await scrypt(plaintext, salt, expected.length, {
      N, r, p, maxmem: SCRYPT_PARAMS.maxmem,
    });
    if (derivedKey.length !== expected.length) return false;
    return timingSafeEqual(derivedKey, expected);
  } catch {
    // Malformed hash or verification error -> treat as failed auth, never leak detail.
    return false;
  }
}

/**
 * Whether a stored hash should be re-hashed with current parameters
 * (e.g. after raising cost factors). Called post successful login.
 */
export function needsRehash(encoded) {
  const [scheme, nStr, rStr, pStr] = String(encoded).split('$');
  if (scheme !== 'scrypt') return true;
  return (
    Number(nStr) !== SCRYPT_PARAMS.N ||
    Number(rStr) !== SCRYPT_PARAMS.r ||
    Number(pStr) !== SCRYPT_PARAMS.p
  );
}
