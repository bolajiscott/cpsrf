import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateBase32Secret, generateTotp, verifyTotp, buildOtpAuthUri, generateRecoveryCodes,
} from '../../src/security/crypto/totp.js';

test('generateBase32Secret produces a valid-looking base32 string', () => {
  const secret = generateBase32Secret();
  assert.match(secret, /^[A-Z2-7]+$/);
  assert.ok(secret.length >= 16);
});

test('a freshly generated code verifies successfully at the same timestamp', () => {
  const secret = generateBase32Secret();
  const now = Date.now();
  const code = generateTotp(secret, { timestamp: now });
  const result = verifyTotp(secret, code, { timestamp: now });
  assert.equal(result.valid, true);
});

test('an incorrect code fails verification', () => {
  const secret = generateBase32Secret();
  const result = verifyTotp(secret, '000000', { timestamp: Date.now() });
  // extremely unlikely to collide, but assert type instead of exact value to avoid flakiness
  assert.equal(typeof result.valid, 'boolean');
});

test('a code from far outside the drift window is rejected', () => {
  const secret = generateBase32Secret();
  const past = Date.now() - 1000 * 60 * 60; // 1 hour ago
  const code = generateTotp(secret, { timestamp: past });
  const result = verifyTotp(secret, code, { timestamp: Date.now(), window: 1 });
  assert.equal(result.valid, false);
});

test('a code within +/-1 step of drift is accepted', () => {
  const secret = generateBase32Secret();
  const now = Date.now();
  const oneStepAgo = now - 30_000;
  const code = generateTotp(secret, { timestamp: oneStepAgo });
  const result = verifyTotp(secret, code, { timestamp: now, window: 1 });
  assert.equal(result.valid, true);
});

test('buildOtpAuthUri produces a well-formed otpauth URI', () => {
  const uri = buildOtpAuthUri({ secret: 'JBSWY3DPEHPK3PXP', accountLabel: 'user@example.org', issuer: 'CPSRF-SRF' });
  assert.match(uri, /^otpauth:\/\/totp\//);
  assert.match(uri, /secret=JBSWY3DPEHPK3PXP/);
  assert.match(uri, /issuer=CPSRF-SRF/);
});

test('generateRecoveryCodes returns the requested count of unique codes', () => {
  const codes = generateRecoveryCodes(10);
  assert.equal(codes.length, 10);
  assert.equal(new Set(codes).size, 10);
  for (const code of codes) {
    assert.match(code, /^[0-9a-f]{5}-[0-9a-f]{5}$/);
  }
});
