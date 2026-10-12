import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, needsRehash } from '../../src/security/crypto/passwordHash.js';

test('hashPassword rejects short passwords', async () => {
  await assert.rejects(() => hashPassword('short'));
});

test('hashPassword + verifyPassword round-trip succeeds for correct password', async () => {
  const encoded = await hashPassword('correct-horse-battery-staple');
  const ok = await verifyPassword('correct-horse-battery-staple', encoded);
  assert.equal(ok, true);
});

test('verifyPassword fails for incorrect password', async () => {
  const encoded = await hashPassword('correct-horse-battery-staple');
  const ok = await verifyPassword('wrong-password-entirely', encoded);
  assert.equal(ok, false);
});

test('verifyPassword fails safely on malformed stored hash', async () => {
  const ok = await verifyPassword('anything', 'not-a-real-hash');
  assert.equal(ok, false);
});

test('two hashes of the same password are not identical (salted)', async () => {
  const a = await hashPassword('same-password-twice-1234');
  const b = await hashPassword('same-password-twice-1234');
  assert.notEqual(a, b);
  assert.equal(await verifyPassword('same-password-twice-1234', a), true);
  assert.equal(await verifyPassword('same-password-twice-1234', b), true);
});

test('needsRehash is false immediately after hashing with current params', async () => {
  const encoded = await hashPassword('current-params-password-123');
  assert.equal(needsRehash(encoded), false);
});

test('needsRehash is true for an unrecognised scheme', () => {
  assert.equal(needsRehash('bcrypt$10$somesaltandhash'), true);
});
