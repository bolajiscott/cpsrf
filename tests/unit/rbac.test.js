import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ROLES, PERMISSIONS, roleHasPermission, isKnownRole, ROLE_PERMISSIONS,
  MFA_REQUIRED_ROLES, isMfaRequiredForRole,
} from '../../src/rbac/roles.js';

test('every role listed in V3 content_model.json roles is present', () => {
  const expectedRoles = [
    'Super Administrator', 'Managing Editor', 'Fact Checker', 'Legal Reviewer',
    'Theological Reviewer', 'Authorised Approver', 'Humanitarian Data Officer',
    'Partner Manager', 'Auditor',
  ];
  for (const role of expectedRoles) {
    assert.equal(isKnownRole(role), true, `${role} should be a known role`);
    assert.ok(ROLE_PERMISSIONS[role], `${role} should have a permission entry`);
  }
});

test('Fact Checker can fact-check but cannot approve/publish', () => {
  assert.equal(roleHasPermission(ROLES.FACT_CHECKER, PERMISSIONS.CONTENT_FACT_CHECK), true);
  assert.equal(roleHasPermission(ROLES.FACT_CHECKER, PERMISSIONS.CONTENT_APPROVE_PUBLISH), false);
});

test('Humanitarian Data Officer can access protected humanitarian records, Partner Manager cannot', () => {
  assert.equal(roleHasPermission(ROLES.HUMANITARIAN_DATA_OFFICER, PERMISSIONS.HUMANITARIAN_PROTECTED_READ), true);
  assert.equal(roleHasPermission(ROLES.PARTNER_MANAGER, PERMISSIONS.HUMANITARIAN_PROTECTED_READ), false);
});

test('Auditor can read audit log but cannot approve/publish content', () => {
  assert.equal(roleHasPermission(ROLES.AUDITOR, PERMISSIONS.AUDIT_LOG_READ), true);
  assert.equal(roleHasPermission(ROLES.AUDITOR, PERMISSIONS.CONTENT_APPROVE_PUBLISH), false);
});

test('an unknown role has no permissions', () => {
  assert.equal(roleHasPermission('Made Up Role', PERMISSIONS.AUDIT_LOG_READ), false);
  assert.equal(isKnownRole('Made Up Role'), false);
});

test('MFA is mandatory for exactly the five leadership-confirmed roles, and only known roles', () => {
  const expectedMfaRequired = [
    ROLES.SUPER_ADMINISTRATOR, ROLES.MANAGING_EDITOR, ROLES.AUTHORISED_APPROVER,
    ROLES.LEGAL_REVIEWER, ROLES.HUMANITARIAN_DATA_OFFICER,
  ];
  assert.equal(MFA_REQUIRED_ROLES.length, expectedMfaRequired.length);
  for (const role of expectedMfaRequired) {
    assert.ok(isKnownRole(role), `${role} should be a known role`);
    assert.equal(isMfaRequiredForRole(role), true, `${role} should require MFA`);
  }
});

test('MFA is NOT required for roles leadership did not name', () => {
  const notRequired = [
    ROLES.FACT_CHECKER, ROLES.THEOLOGICAL_REVIEWER, ROLES.PARTNER_MANAGER, ROLES.AUDITOR,
  ];
  for (const role of notRequired) {
    assert.equal(isMfaRequiredForRole(role), false, `${role} should NOT require MFA`);
  }
});

test('Super Administrator has every defined permission explicitly listed (no implicit wildcard)', () => {
  const allPermissions = Object.values(PERMISSIONS);
  for (const permission of allPermissions) {
    assert.equal(roleHasPermission(ROLES.SUPER_ADMINISTRATOR, permission), true, `Super Administrator missing ${permission}`);
  }
});
