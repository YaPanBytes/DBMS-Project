-- ConsentLedger Database Schema
-- Normalized to 3NF, supports per-field purpose-bound consent with RLS enforcement
-- Applied by Alembic revision 0001 (alembic/versions/0001_initial_schema.py)

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Organizations: NGOs, government agencies, funders, auditors
CREATE TABLE organizations (
    org_id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    type            VARCHAR(50) NOT NULL CHECK (type IN ('ngo', 'government', 'funder', 'auditor')),
    description     TEXT,
    contact_email   VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_organizations_type ON organizations (type);

-- Roles: lookup table for role-based access control. Every user has exactly
-- one role; there are no separate admin/owner/partner tables.
CREATE TABLE roles (
    role_id         SMALLINT PRIMARY KEY,
    name            VARCHAR(30) NOT NULL UNIQUE CHECK (name ~ '^[a-z_]+$'),
    description     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO roles (role_id, name, description) VALUES
    (1, 'owner',   'Data owner: registers datasets, describes fields, grants and revokes consent'),
    (2, 'partner', 'Partner: requests access and reads consented fields for a stated purpose'),
    (3, 'auditor', 'Auditor: read-only reviewer of datasets, grants and the audit trail'),
    (4, 'admin',   'Platform administrator: manages organizations and user accounts');

-- Users acting on behalf of organizations (single table for every role)
CREATE TABLE users (
    user_id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    role_id         SMALLINT NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT,
    email           VARCHAR(255) NOT NULL UNIQUE CHECK (email = lower(email) AND email LIKE '%_@_%'),
    -- NULL for accounts that only sign in with Google
    password_hash   VARCHAR(255),
    -- Google account id ('sub' claim), linked on first Google sign-in
    google_sub      VARCHAR(255) UNIQUE,
    full_name       VARCHAR(255),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_org_id ON users (org_id);
CREATE INDEX idx_users_role_id ON users (role_id);

-- Datasets registered by data owners
CREATE TABLE datasets (
    dataset_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_org_id    UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    title           VARCHAR(255) NOT NULL,
    description     TEXT,
    category        VARCHAR(100),
    status          VARCHAR(50) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    version         INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_datasets_owner_org_id ON datasets (owner_org_id);
CREATE INDEX idx_datasets_status ON datasets (status);

-- Fields/columns within each dataset
CREATE TABLE dataset_fields (
    field_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dataset_id      UUID NOT NULL REFERENCES datasets(dataset_id) ON DELETE CASCADE,
    -- Field names become column names in data_<dataset_id> tables, so restrict them
    -- to safe lowercase identifiers.
    name            VARCHAR(63) NOT NULL CHECK (name ~ '^[a-z_][a-z0-9_]*$'),
    data_type       VARCHAR(50) NOT NULL CHECK (data_type IN ('text', 'integer', 'numeric', 'boolean', 'date', 'timestamp', 'json')),
    sensitivity     VARCHAR(20) NOT NULL DEFAULT 'low' CHECK (sensitivity IN ('low', 'medium', 'high', 'pii')),
    description     TEXT,
    is_encrypted    BOOLEAN NOT NULL DEFAULT false,
    ordinal         INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (dataset_id, name),
    -- Target for the composite FK from consent_grants (field must belong to dataset)
    UNIQUE (field_id, dataset_id)
);

-- ============================================================================
-- CONSENT MANAGEMENT
-- ============================================================================

-- Consent grants: per-field, purpose-bound, expiring, revocable.
-- Organization M:N Dataset (field level) is resolved through this table.
CREATE TABLE consent_grants (
    grant_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    grantor_org_id  UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    grantee_org_id  UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    dataset_id      UUID NOT NULL REFERENCES datasets(dataset_id) ON DELETE CASCADE,
    field_id        UUID NOT NULL,
    purpose         VARCHAR(500) NOT NULL CHECK (length(trim(purpose)) > 0),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID REFERENCES users(user_id) ON DELETE SET NULL,
    revocation_reason TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The granted field must belong to the granted dataset
    FOREIGN KEY (field_id, dataset_id)
        REFERENCES dataset_fields(field_id, dataset_id) ON DELETE CASCADE,
    -- Ensure one grant per grantee/field/purpose combination
    UNIQUE (grantee_org_id, dataset_id, field_id, purpose),
    -- An organization cannot grant consent to itself
    CHECK (grantor_org_id <> grantee_org_id),
    -- Expiry must be later than the grant
    CHECK (expires_at > granted_at),
    -- A revocation cannot predate the grant
    CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

-- Access requests from partners to data owners
CREATE TABLE access_requests (
    request_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    grantee_org_id  UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    requested_by    UUID REFERENCES users(user_id) ON DELETE SET NULL,
    dataset_id      UUID NOT NULL REFERENCES datasets(dataset_id) ON DELETE CASCADE,
    field_ids       UUID[] NOT NULL DEFAULT '{}' CHECK (cardinality(field_ids) > 0),
    purpose         VARCHAR(500) NOT NULL CHECK (length(trim(purpose)) > 0),
    requested_expires_at TIMESTAMPTZ NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    decided_by      UUID REFERENCES users(user_id) ON DELETE SET NULL,
    decided_at      TIMESTAMPTZ,
    decision_note   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (requested_expires_at > created_at),
    -- A decided request must record when it was decided
    CHECK (status IN ('pending', 'expired') OR decided_at IS NOT NULL)
);

-- ============================================================================
-- AUDIT LOG (Append-only, Hash-chained)
-- ============================================================================
-- Foreign keys use ON DELETE RESTRICT: a user, dataset or field that appears in
-- the audit trail cannot be deleted (deactivate users / archive datasets
-- instead), so the history always points at real rows.
-- user_id is NULL for actions performed by the system (no application user set).

CREATE TABLE audit_log (
    log_id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Chain order. Timestamps are not unique (now() is constant within a
    -- transaction), so the chain is defined by this sequence, not by ts.
    -- seq, prev_hash and row_hash are assigned by trg_audit_log_chain
    -- (migration 002); NOT NULL is checked after BEFORE triggers run.
    seq             BIGINT NOT NULL UNIQUE,
    user_id         UUID REFERENCES users(user_id) ON DELETE RESTRICT,
    dataset_id      UUID REFERENCES datasets(dataset_id) ON DELETE RESTRICT,
    field_id        UUID REFERENCES dataset_fields(field_id) ON DELETE RESTRICT,
    -- Fields whose values were returned in clear text by a read
    field_ids       UUID[],
    action          VARCHAR(50) NOT NULL CHECK (action IN (
        'select', 'insert', 'update', 'delete',
        'grant_create', 'grant_update', 'grant_revoke', 'grant_expire',
        'request_create', 'request_update', 'request_approve', 'request_deny',
        'login', 'logout', 'pii_scan', 'anomaly_alert'
    )),
    rows_affected   INTEGER NOT NULL DEFAULT 0 CHECK (rows_affected >= 0),
    query_text      TEXT,
    client_ip       INET,
    user_agent      TEXT,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    prev_hash       BYTEA NOT NULL CHECK (octet_length(prev_hash) = 32),
    row_hash        BYTEA NOT NULL CHECK (octet_length(row_hash) = 32)
);

-- Append-only enforcement: block UPDATE and DELETE for everyone (including the
-- table owner) with a trigger, and remove the privileges from PUBLIC.
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER trg_audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();

REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC;

-- Anomaly alerts from AI detector
CREATE TABLE anomaly_alerts (
    alert_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    dataset_id      UUID REFERENCES datasets(dataset_id) ON DELETE SET NULL,
    score           NUMERIC(5,4) NOT NULL CHECK (score >= 0 AND score <= 1),
    reason          TEXT NOT NULL,
    features        JSONB,
    -- 'isolation_forest' or 'rule' (the baseline detector)
    detector        VARCHAR(30) NOT NULL DEFAULT 'isolation_forest'
                    CHECK (detector IN ('isolation_forest', 'rule', 'manual')),
    status          VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    resolved_by     UUID REFERENCES users(user_id) ON DELETE SET NULL,
    CHECK (status NOT IN ('resolved', 'false_positive') OR resolved_at IS NOT NULL)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Consent grant lookups (critical for RLS performance)
CREATE INDEX idx_consent_grants_grantee_dataset_expires
    ON consent_grants (grantee_org_id, dataset_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_consent_grants_grantor_dataset
    ON consent_grants (grantor_org_id, dataset_id);

CREATE INDEX idx_consent_grants_field
    ON consent_grants (field_id);

-- Access requests
CREATE INDEX idx_access_requests_grantee_status
    ON access_requests (grantee_org_id, status);

CREATE INDEX idx_access_requests_dataset_status
    ON access_requests (dataset_id, status);

-- Audit log queries (timestamps)
CREATE INDEX idx_audit_log_user_ts
    ON audit_log (user_id, ts DESC);

CREATE INDEX idx_audit_log_dataset_ts
    ON audit_log (dataset_id, ts DESC);

CREATE INDEX idx_audit_log_ts
    ON audit_log (ts DESC);

CREATE INDEX idx_audit_log_field
    ON audit_log (field_id) WHERE field_id IS NOT NULL;

-- Anomaly alerts
CREATE INDEX idx_anomaly_alerts_user_status
    ON anomaly_alerts (user_id, status);

CREATE INDEX idx_anomaly_alerts_dataset_status
    ON anomaly_alerts (dataset_id, status);

-- ============================================================================
-- TRIGGERS FOR UPDATED_AT
-- ============================================================================

-- clock_timestamp() (not now()) so updated_at moves forward even when the row
-- was created earlier in the same transaction.
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_datasets_updated_at
    BEFORE UPDATE ON datasets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_dataset_fields_updated_at
    BEFORE UPDATE ON dataset_fields
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_consent_grants_updated_at
    BEFORE UPDATE ON consent_grants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_access_requests_updated_at
    BEFORE UPDATE ON access_requests
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
