-- CPSRF/SRF V4 - Phase 1 schema: identity, MFA, RBAC, audit.
-- Content-collection tables (pages, newsroom, verified_records, humanitarian_*, etc.)
-- from V3's cms/content_model.json land in Phase 2's schema_content.sql, on top of this.

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid()

CREATE TABLE users (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email             CITEXT UNIQUE NOT NULL,
  display_name      TEXT NOT NULL,
  password_hash     TEXT NOT NULL,           -- scrypt$N$r$p$salt$hash (see src/security/crypto/passwordHash.js)
  role              TEXT NOT NULL,            -- one of src/rbac/roles.js ROLES
  status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deactivated')),
  mfa_enabled       BOOLEAN NOT NULL DEFAULT false,
  mfa_totp_secret   TEXT,                     -- base32 secret; NULL until enrolled. Encrypt at rest (see PHASE1_HANDOFF.md).
  mfa_last_used_step BIGINT,                  -- replay protection: last accepted TOTP counter
  failed_login_count SMALLINT NOT NULL DEFAULT 0,
  locked_until      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mfa_recovery_codes (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash     TEXT NOT NULL,   -- scrypt-hashed recovery code, never plaintext
  used_at       TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE refresh_tokens (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash    TEXT NOT NULL UNIQUE,  -- store only a hash of the refresh token, never the raw value
  issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,
  revoked_at    TIMESTAMPTZ,
  replaced_by   UUID REFERENCES refresh_tokens(id),
  ip_address    INET,
  user_agent    TEXT
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id) WHERE revoked_at IS NULL;

CREATE TABLE audit_events (
  id            BIGSERIAL PRIMARY KEY,
  actor_id      UUID REFERENCES users(id),
  actor_role    TEXT,
  action        TEXT NOT NULL,
  resource      TEXT,
  outcome       TEXT NOT NULL CHECK (outcome IN ('granted','denied','success','failure','info')),
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address    INET,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_id, created_at DESC);
CREATE INDEX idx_audit_events_action ON audit_events(action, created_at DESC);

-- Application role used by the API server. Least-privilege grants only.
-- Run these as a superuser during provisioning, substituting a real generated password:
--
--   CREATE ROLE cpsrf_app WITH LOGIN PASSWORD 'CHANGE_ME';
--   GRANT CONNECT ON DATABASE cpsrf_srf_v4 TO cpsrf_app;
--   GRANT USAGE ON SCHEMA public TO cpsrf_app;
--   GRANT SELECT, INSERT, UPDATE ON users, mfa_recovery_codes, refresh_tokens TO cpsrf_app;
--   GRANT SELECT, INSERT ON audit_events TO cpsrf_app;      -- INSERT only, no UPDATE/DELETE:
--   REVOKE UPDATE, DELETE ON audit_events FROM cpsrf_app;   -- audit log is append-only even to the app itself
--   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cpsrf_app;
