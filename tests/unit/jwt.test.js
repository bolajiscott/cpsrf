import test from 'node:test';
import assert from 'node:assert/strict';
import { signJwt, verifyJwt } from '../../src/security/crypto/jwt.js';

const SECRET = 'a'.repeat(64);

test('signJwt rejects a secret shorter than 32 chars', () => {
  assert.throws(() => signJwt({ sub: 'x' }, 'short-secret'));
});

test('sign then verify round-trips the payload', () => {
  const payload = { sub: 'user-123', role: 'Auditor', exp: Math.floor(Date.now() / 1000) + 60 };
  const token = signJwt(payload, SECRET);
  const decoded = verifyJwt(token, SECRET);
  assert.equal(decoded.sub, 'user-123');
  assert.equal(decoded.role, 'Auditor');
});

test('verifyJwt rejects a token signed with a different secret', () => {
  const token = signJwt({ sub: 'x', exp: Math.floor(Date.now() / 1000) + 60 }, SECRET);
  assert.throws(() => verifyJwt(token, 'b'.repeat(64)));
});

test('verifyJwt rejects an expired token', () => {
  const token = signJwt({ sub: 'x', exp: Math.floor(Date.now() / 1000) - 10 }, SECRET);
  assert.throws(() => verifyJwt(token, SECRET), /expired/);
});

test('verifyJwt rejects a tampered payload', () => {
  const token = signJwt({ sub: 'user-123', role: 'Auditor', exp: Math.floor(Date.now() / 1000) + 60 }, SECRET);
  const [header, payload, sig] = token.split('.');
  const tamperedPayload = Buffer.from(JSON.stringify({ sub: 'user-123', role: 'Super Administrator', exp: Math.floor(Date.now() / 1000) + 60 })).toString('base64url');
  const tamperedToken = `${header}.${tamperedPayload}.${sig}`;
  assert.throws(() => verifyJwt(tamperedToken, SECRET));
});

test('verifyJwt rejects malformed tokens', () => {
  assert.throws(() => verifyJwt('not.a.jwt.at.all', SECRET));
  assert.throws(() => verifyJwt('garbage', SECRET));
});

test('verifyJwt rejects a token asserting a non-HS256 alg header', () => {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub: 'x', exp: Math.floor(Date.now() / 1000) + 60 })).toString('base64url');
  const forged = `${header}.${payload}.`;
  assert.throws(() => verifyJwt(forged, SECRET));
});
