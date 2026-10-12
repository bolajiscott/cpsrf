// Role and permission model, derived directly from V3's cms/content_model.json "roles" list.
// This is the single source of truth for what each role may do - the RBAC middleware
// consults ONLY this map, never a client-supplied claim of privilege.

export const ROLES = Object.freeze({
  SUPER_ADMINISTRATOR: 'Super Administrator',
  MANAGING_EDITOR: 'Managing Editor',
  FACT_CHECKER: 'Fact Checker',
  LEGAL_REVIEWER: 'Legal Reviewer',
  THEOLOGICAL_REVIEWER: 'Theological Reviewer',
  AUTHORISED_APPROVER: 'Authorised Approver',
  HUMANITARIAN_DATA_OFFICER: 'Humanitarian Data Officer',
  PARTNER_MANAGER: 'Partner Manager',
  AUDITOR: 'Auditor',
});

// Permissions are named as `resource:action`. Kept flat and explicit rather than
// inferred, so a reviewer can read this file and know exactly what's granted.
export const PERMISSIONS = Object.freeze({
  CONTENT_READ_DRAFT: 'content:read_draft',
  CONTENT_WRITE_DRAFT: 'content:write_draft',
  CONTENT_FACT_CHECK: 'content:fact_check',
  CONTENT_LEGAL_REVIEW: 'content:legal_review',
  CONTENT_THEOLOGICAL_REVIEW: 'content:theological_review',
  CONTENT_APPROVE_PUBLISH: 'content:approve_publish',
  CONTENT_ARCHIVE: 'content:archive',
  CONTENT_CORRECT: 'content:correct',
  USER_MANAGE: 'user:manage',
  ROLE_MANAGE: 'role:manage',
  HUMANITARIAN_PROTECTED_READ: 'humanitarian_protected:read',
  HUMANITARIAN_PROTECTED_WRITE: 'humanitarian_protected:write',
  PARTNER_DOCUMENTS_MANAGE: 'partner_documents:manage',
  PARTNER_DOCUMENTS_READ: 'partner_documents:read',
  AUDIT_LOG_READ: 'audit_log:read',
  SYSTEM_CONFIG: 'system:config',
});

const P = PERMISSIONS;

// Role -> permission grants. A role's absence from a permission's list means denied.
// Super Administrator is intentionally NOT given a blanket wildcard: every grant is
// listed explicitly so an auditor can read this table without trusting a "admin bypass".
export const ROLE_PERMISSIONS = Object.freeze({
  [ROLES.SUPER_ADMINISTRATOR]: [
    P.CONTENT_READ_DRAFT, P.CONTENT_WRITE_DRAFT, P.CONTENT_FACT_CHECK,
    P.CONTENT_LEGAL_REVIEW, P.CONTENT_THEOLOGICAL_REVIEW, P.CONTENT_APPROVE_PUBLISH,
    P.CONTENT_ARCHIVE, P.CONTENT_CORRECT, P.USER_MANAGE, P.ROLE_MANAGE,
    P.HUMANITARIAN_PROTECTED_READ, P.HUMANITARIAN_PROTECTED_WRITE,
    P.PARTNER_DOCUMENTS_MANAGE, P.PARTNER_DOCUMENTS_READ, P.AUDIT_LOG_READ,
    P.SYSTEM_CONFIG,
  ],
  [ROLES.MANAGING_EDITOR]: [
    P.CONTENT_READ_DRAFT, P.CONTENT_WRITE_DRAFT, P.CONTENT_ARCHIVE, P.CONTENT_CORRECT,
  ],
  [ROLES.FACT_CHECKER]: [
    P.CONTENT_READ_DRAFT, P.CONTENT_FACT_CHECK,
  ],
  [ROLES.LEGAL_REVIEWER]: [
    P.CONTENT_READ_DRAFT, P.CONTENT_LEGAL_REVIEW,
  ],
  [ROLES.THEOLOGICAL_REVIEWER]: [
    P.CONTENT_READ_DRAFT, P.CONTENT_THEOLOGICAL_REVIEW,
  ],
  [ROLES.AUTHORISED_APPROVER]: [
    P.CONTENT_READ_DRAFT, P.CONTENT_APPROVE_PUBLISH,
  ],
  [ROLES.HUMANITARIAN_DATA_OFFICER]: [
    P.HUMANITARIAN_PROTECTED_READ, P.HUMANITARIAN_PROTECTED_WRITE,
  ],
  [ROLES.PARTNER_MANAGER]: [
    P.PARTNER_DOCUMENTS_MANAGE, P.PARTNER_DOCUMENTS_READ,
  ],
  [ROLES.AUDITOR]: [
    P.AUDIT_LOG_READ, P.CONTENT_READ_DRAFT,
  ],
});

// MFA enforcement policy - confirmed by CPSRF leadership (Phase 1.1). Roles listed here
// MUST complete MFA enrollment before they receive a full access token; see
// authService.loginWithPassword and docs/PHASE1_HANDOFF.md "MFA enforcement" for the
// enrollment-bootstrap mechanism that makes this possible without a chicken-and-egg
// login problem.
export const MFA_REQUIRED_ROLES = Object.freeze([
  ROLES.SUPER_ADMINISTRATOR,
  ROLES.MANAGING_EDITOR,
  ROLES.AUTHORISED_APPROVER,
  ROLES.LEGAL_REVIEWER,
  ROLES.HUMANITARIAN_DATA_OFFICER,
]);

export function isMfaRequiredForRole(role) {
  return MFA_REQUIRED_ROLES.includes(role);
}

export function roleHasPermission(role, permission) {
  const grants = ROLE_PERMISSIONS[role];
  return Array.isArray(grants) && grants.includes(permission);
}

export function isKnownRole(role) {
  return Object.values(ROLES).includes(role);
}
