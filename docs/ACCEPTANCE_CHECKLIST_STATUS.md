# V3 Security Acceptance Checklist — Phase 1 Status

Mapping each item from `security/ACCEPTANCE_CHECKLIST.md` (V3) to what Phase 1 actually
delivers. Marked honestly — "implemented" means code exists and is unit-tested where
testable without a live DB; it does not mean verified in a live deployment.

| Item | Status | Notes |
|---|---|---|
| MFA enabled for privileged users | Implemented (policy decision confirmed) | Mandatory for Super Administrator, Managing Editor, Authorised Approver, Legal Reviewer, Humanitarian Data Officer — enforced in `loginWithPassword` via a restricted `mfa_setup_required` token; see PHASE1_HANDOFF.md "MFA enforcement mechanism". Not yet exercised against a live DB |
| RBAC tested for every protected route | Partial | RBAC engine implemented + unit-tested; protected routes now include `/admin/audit-log` and `/admin/users`, `/admin/roles`. Full route coverage arrives with Phase 2+ content routes |
| Public API tested to ensure protected data cannot leak | Not yet applicable | No content endpoints exist yet in Phase 1 |
| File URLs private by default | Not started | Partner document room is a later phase |
| Server-side input validation | Implemented | Zod schemas on all Phase 1 auth endpoints |
| Rate limits and abuse controls | Implemented | Login/MFA endpoints rate-limited by IP+email; general rate limiter on all routes |
| Security headers | Implemented | Helmet + CSP + HSTS configured in `src/middleware/security.js` |
| Dependency vulnerability scan | Not done | Run `npm audit` once `npm install` is possible in a networked environment |
| Backup + restoration test | Not started | Infrastructure-level task for your hosting/DB provider |
| Audit logging | Implemented | Structured, append-only audit_events table + logger; schema includes REVOKE guidance |
| Staging/production separation | Not started | Infrastructure/deployment task, not application code |
| Secrets outside source code | Implemented | `.env` pattern, `.env.example` has no real secrets, `getEnv()` refuses to start on placeholder values |
| Data retention/deletion policy approved | Not started | Governance decision needed from CPSRF leadership, not a code task |
| Accessibility test completed | Not applicable to Phase 1 | Applies to frontend, later phase |
| Performance test completed | Not started | Requires a live deployment to test against |
| Privacy/legal review completed | Not started | Especially relevant given humanitarian protected-data plans — recommend legal review before Phase on humanitarian module begins |
| Institutional content approval completed | Not applicable to Phase 1 | No content in this phase; carried forward as a standing rule for Phase 2+ |

**Read this as a live document.** Update it at the end of every phase rather than only
at the end of the project — that's what makes "acceptance testing" mean something
instead of being a final rubber stamp.

## Phase 1.1 addendum

CPSRF leadership confirmed three of Phase 1's four open decisions: mandatory MFA for
the five roles listed above, invite-only user provisioning (`POST /api/v1/admin/users`,
bootstrapped by `npm run seed`), and same-origin hosting (no CORS layer needed). The
`mfa_totp_secret`-at-rest encryption decision remains open pending a KMS/hosting choice.
