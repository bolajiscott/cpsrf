# CPSRF/SRF V4 — Phase 1 Handoff: Auth, MFA, RBAC, Audit, Security Foundation

## Phase 1.1 update — leadership decisions implemented

Three of the four open decisions below have been confirmed and built:

- **MFA enforcement (confirmed)**: Super Administrator, Managing Editor, Authorised
  Approver, Legal Reviewer, and Humanitarian Data Officer now MUST enroll in MFA before
  receiving a usable session. See `src/rbac/roles.js` (`MFA_REQUIRED_ROLES`) and
  `authService.loginWithPassword` for the enforcement mechanism, and "MFA enforcement
  mechanism" below for how the enrollment bootstrap problem was solved.
- **User provisioning (confirmed: invite-only)**: `POST /api/v1/admin/users`, gated by
  `user:manage`, is the only way an account is created — no self-registration route
  exists anywhere in this app. `src/db/seed.js` (`npm run seed`) creates the first Super
  Administrator, since the invite-only route needs an existing admin to call it.
- **CORS/hosting topology (confirmed: same-origin)**: no CORS middleware was added. The
  app assumes the frontend is served from the same origin as this API, which is what
  the cookie-based session design already required — this is a confirmation, not a code
  change. If that ever changes, CORS + cookie `SameSite`/`SameSite=None; Secure` config
  will need to be added before the frontend can authenticate cross-origin.
- **Secrets/KMS approach for `mfa_totp_secret` at rest: still open.** Not yet decided —
  this needs your hosting/KMS choice before it can be implemented. The column remains
  plaintext in `schema.sql`; do not go to production with this unresolved.

## What this is

A real, runnable Node.js/Express + PostgreSQL backend implementing the identity and
access-control layer that every later phase (CMS, editorial workflow, election module,
humanitarian protected data, partner document room) will sit on top of. This is code,
not a mockup — the crypto primitives and RBAC logic are unit-tested and passing (27/27)
inside the build environment. It has **not** been run against a live PostgreSQL instance
or load-tested; that requires your actual infrastructure (see "What's not done" below).

## What's implemented

- **Password auth**: scrypt-based hashing (Node built-in `node:crypto`, OWASP-range cost
  parameters), timing-safe verification, automatic rehash-on-login if cost parameters
  are raised later, account lockout after repeated failures, generic error responses
  that don't reveal whether an email exists (anti-enumeration).
- **MFA (TOTP)**: RFC 6238-compliant, works with Google Authenticator/Authy/1Password/etc.,
  QR-enrollment via `otpauth://` URI, replay protection (a code can't be reused once
  accepted), one-time recovery codes (hashed, shown once).
- **Tokens**: HS256 JWT for short-lived access tokens; opaque, hashed, rotating refresh
  tokens with reuse detection (a stolen-then-replayed refresh token invalidates the
  whole session chain).
- **RBAC**: role → permission matrix built directly from the 9 roles in your V3
  `content_model.json`, enforced server-side in Express middleware, with every grant
  listed explicitly (no implicit "admin bypass" — even Super Administrator's permissions
  are itemised so an auditor can read the table and know exactly what's granted).
- **Audit logging**: structured, append-only events for every login attempt, MFA event,
  RBAC grant/denial, and token refresh; automatic secret-redaction as a defensive
  backstop; schema notes show how to `REVOKE UPDATE/DELETE` on the audit table so even
  a compromised app credential can't rewrite history.
- **Security middleware**: Helmet security headers + CSP, rate limiting on login/MFA
  endpoints (keyed by IP+email to prevent both credential stuffing and cross-account
  lockout abuse), double-submit CSRF protection for the cookie-based session, centralised
  error handling that never leaks stack traces to clients.
- **Unit tests**: 27 tests covering password hashing, TOTP, JWT, and RBAC — run with
  `npm test`.

## Why some crypto is dependency-free

Password hashing, TOTP, and JWT are implemented using only `node:crypto` rather than
`argon2`/`otplib`/`jsonwebtoken`. This was a deliberate choice, not a shortcut — it let
every security-critical primitive be unit-tested inside a sandboxed build environment
with no package registry access, and it removes three packages from the credential-
handling trust boundary. The algorithms used (scrypt per RFC 7914-style parameters,
RFC 6238 TOTP, HS256 JWS) are standard and correctly implemented per spec. If your
security team prefers widely-audited libraries over reference implementations, swapping
`src/security/crypto/*.js` for `argon2`/`otplib`/`jsonwebtoken` is a contained change —
the rest of the codebase only calls the exported functions, not the internals.

## MFA enforcement mechanism (how the bootstrap problem was solved)

Making MFA mandatory for a role creates a chicken-and-egg problem: a user in that role
can't get a full session to reach the enrollment endpoints, because they haven't
enrolled yet. This is solved with a third, narrowly-scoped token purpose:

1. `loginWithPassword` checks `isMfaRequiredForRole(user.role)`. If true and
   `mfa_enabled` is false, it does NOT issue a full access token. Instead it issues a
   short-lived (15 min) `mfa_setup_required` token and returns
   `{ status: 'mfa_setup_required' }`.
2. `requireAuthForMfaSetup` (in `authMiddleware.js`) is applied ONLY to
   `/mfa/enroll/start` and `/mfa/enroll/confirm`. It accepts either a full `access`
   token or an `mfa_setup_required` token.
3. Every OTHER protected route still uses plain `requireAuth`, which accepts only
   `purpose === 'access'` — so an `mfa_setup_required` token is rejected everywhere
   except those two routes. Enforcement doesn't depend on remembering to add a check
   somewhere; it falls out of the existing strict purpose check on every other route.
4. `confirmMfaEnrollment` now issues a full token pair on success, so the user lands
   authenticated immediately after enrollment — no second login round-trip required.

This is unit-testable at the RBAC-policy level without a database (see
`tests/unit/rbac.test.js`), but the full login → setup-required → enroll → authenticated
round-trip through real Postgres has NOT been run — that's still part of the manual
end-to-end check in `docs/SETUP.md`.

## What's NOT done — do not treat this as deployed or complete

- **Never run against a live database.** No network access was available in the build
  environment, so `npm install` and any live PostgreSQL connection were not possible.
  `schema.sql`, `migrate.js`, and every DB-touching function are written and reviewed
  but unexecuted against a real Postgres instance. Run `npm run migrate` against a real
  database and exercise the auth endpoints end-to-end before trusting this in staging.
- **`mfa_totp_secret` is stored in plaintext in the schema as drafted.** It should be
  encrypted at rest (application-level envelope encryption, or pgcrypto column
  encryption) before production. Flagging this explicitly rather than silently
  shipping it — this needs a decision on your KMS/secrets approach. Still open.
- **No content tables yet.** `pages`, `newsroom`, `verified_records`, `humanitarian_public`,
  `humanitarian_protected`, `partner_documents`, etc. from V3's content model are Phase 2.
- **No election module, no humanitarian protected-data module, no partner document room,
  no editorial workflow state machine yet** — these build on top of this RBAC/audit
  foundation in later phases, per the sequencing you approved.
- **Security acceptance testing has not been run** — see
  `docs/ACCEPTANCE_CHECKLIST_STATUS.md` for an honest per-item status against the V3
  checklist. Most items are "not yet applicable" because there's no live deployment to
  test against.

## Content boundary carried forward from V3

Nothing in this codebase asserts or requires any CPSRF/SRF organisational fact — no
registration numbers, donor names, financial figures, office addresses, beneficiary
counts, or legal outcomes. `mandate_pillars` text used in the V3 frontend copy is
carried as-is; nothing was added or embellished. When Phase 2 builds the content tables
and seed data, only content you explicitly supply and mark approved should go in —
placeholders, not invented figures, for anything not yet supplied.

## Setup (for your dev team / hosting environment)

See `docs/SETUP.md`.
