// Minimal HS256 JWT implementation using only node:crypto.
// Deliberately narrow: signs/verifies compact JWS tokens for internal session/access
// tokens. Does not implement the full JOSE spec (no other algorithms, no JWK) -
// that's a feature here, not a gap: fewer algorithm-confusion attack surfaces.

import { createHmac, timingSafeEqual } from 'node:crypto';

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlDecode(input) {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
  return Buffer.from(padded, 'base64');
}

/**
 * Sign a JWT with HS256. `payload` should include `sub`, `role`, `exp` (unix seconds), etc.
 */
export function signJwt(payload, secret) {
  if (!secret || secret.length < 32) {
    throw new Error('JWT signing secret must be at least 32 characters');
  }
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = createHmac('sha256', secret).update(signingInput).digest();
  const encodedSignature = base64url(signature);
  return `${signingInput}.${encodedSignature}`;
}

/**
 * Verify a JWT's signature and expiry. Throws on any failure with a generic message
 * (never leak which check failed - avoids oracle attacks on malformed tokens).
 */
export function verifyJwt(token, secret) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const expectedSignature = createHmac('sha256', secret).update(signingInput).digest();
  const providedSignature = base64urlDecode(encodedSignature);

  if (
    providedSignature.length !== expectedSignature.length ||
    !timingSafeEqual(providedSignature, expectedSignature)
  ) {
    throw new Error('Invalid token');
  }

  let header, payload;
  try {
    header = JSON.parse(base64urlDecode(encodedHeader).toString('utf8'));
    payload = JSON.parse(base64urlDecode(encodedPayload).toString('utf8'));
  } catch {
    throw new Error('Invalid token');
  }

  if (header.alg !== 'HS256') throw new Error('Invalid token');

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && nowSeconds >= payload.exp) {
    throw new Error('Token expired');
  }
  if (typeof payload.nbf === 'number' && nowSeconds < payload.nbf) {
    throw new Error('Token not yet valid');
  }

  return payload;
}
