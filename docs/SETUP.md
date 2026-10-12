# Setup — Phase 1

## Prerequisites

- Node.js 20+
- PostgreSQL 14+ (with ability to `CREATE EXTENSION pgcrypto`)

## Steps

1. Install dependencies:
   ```
   npm install
   ```

2. Create a database and app role (as a Postgres superuser):
   ```sql
   CREATE DATABASE cpsrf_srf_v4;
   \c cpsrf_srf_v4
   CREATE EXTENSION IF NOT EXISTS citext;
   ```
   Then run the `CREATE ROLE cpsrf_app ...` / `GRANT ...` block documented at the
   bottom of `src/db/schema.sql`, substituting a real generated password.

3. Copy environment config:
   ```
   cp .env.example .env
   ```
   Fill in `DATABASE_URL` with the app role's credentials, and generate real secrets:
   ```
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"   # JWT_SIGNING_SECRET
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # CSRF_SECRET
   ```

4. Apply the schema:
   ```
   npm run migrate
   ```

5. Run the unit test suite:
   ```
   npm test
   ```
   All 27 tests should pass — these don't require a database connection (they test the
   crypto/RBAC core in isolation).

6. Start the server:
   ```
   npm start
   ```
   Health check: `GET http://localhost:4000/api/v1/health`

## Manual end-to-end check (do this before trusting staging)

1. Seed the first Super Administrator (invite-only provisioning means there is no
   public registration route — this is the one bootstrap exception):
   ```
   SEED_SUPER_ADMIN_EMAIL=you@cpsrf.org \
   SEED_SUPER_ADMIN_PASSWORD='a-real-strong-password-12+chars' \
   SEED_SUPER_ADMIN_NAME='Your Name' \
   npm run seed
   ```
2. `POST /api/v1/auth/login` with that user's email/password. Since Super Administrator
   requires mandatory MFA and this account has none enrolled yet, expect
   `{ status: 'mfa_setup_required' }`, not a usable session.
3. `POST /api/v1/auth/mfa/enroll/start` (the setup cookie from step 2 authenticates
   this) to get a QR/otpauth URI, scan it into an authenticator app, then
   `POST /api/v1/auth/mfa/enroll/confirm` with a live code — this should now return
   recovery codes AND set real session cookies in one step.
4. Log out, log back in, complete `POST /api/v1/auth/mfa/verify` with a fresh code from
   the app — confirm you receive real session cookies.
5. Hit `GET /api/v1/admin/audit-log` as that user and confirm the login/MFA/enrollment
   events you just generated appear.
6. `POST /api/v1/admin/users` as that Super Administrator to create a second account
   (e.g. a Managing Editor) and confirm the invite-only flow works end-to-end.
7. Try `GET /api/v1/admin/audit-log` as a role without `audit_log:read` (e.g. Managing
   Editor) and confirm a 403.

This exact flow has not been run in the build environment (no live Postgres available
there) — running it once against your actual database is the real acceptance test for
Phase 1, more so than anything in this document.
