# CPSRF/SRF V4 Backend — Phase 1 (1.1)

Auth, MFA, RBAC, and audit-logging foundation for the V4 full-stack build. Follows on
from the V3 reference architecture (frontend demo + API contract + CMS content model).

**Phase 1.1**: mandatory MFA for five privileged roles, invite-only user provisioning
(`POST /api/v1/admin/users` + `npm run seed` for the first account), and same-origin
hosting are now implemented per confirmed leadership decisions — see
`docs/PHASE1_HANDOFF.md` for what changed and what's still open.

**Start here:**
- `docs/PHASE1_HANDOFF.md` — what's built, what's deliberately deferred, and every open
  decision that needs your input before the next phase.
- `docs/SETUP.md` — how to install, configure, and run this against a real database.
- `docs/ACCEPTANCE_CHECKLIST_STATUS.md` — honest status against V3's security checklist.

**Quick facts:**
- Node.js + Express + PostgreSQL.
- Password hashing, TOTP MFA, and JWTs are implemented dependency-free using Node's
  built-in `node:crypto` (see PHASE1_HANDOFF.md for why).
- RBAC roles/permissions are built directly from V3's `content_model.json` role list.
- `npm test` runs 27 unit tests covering the crypto and RBAC core — no database needed.
- This has been syntax-checked and unit-tested in a sandboxed build environment without
  network access; it has **not** been run against a live PostgreSQL instance. Do that
  before treating it as staging-ready.

No organisational facts, statistics, registrations, donors, or partners have been
invented anywhere in this codebase or its docs.
