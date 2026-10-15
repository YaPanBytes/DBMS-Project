-- ConsentLedger Database Schema
-- Member A: Database Lead
-- Normalized to 3NF, supports per-field purpose-bound consent with RLS enforcement

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Organizations: NGOs, government agencies, funders
CREATE TABLE organizations (
    org_id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    type            VARCHAR(50) NOT NULL CHECK (type IN ('ngo', 'government', 'funder', 'auditor')),
    description     TEXT,
    contact_email   VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users acting on behalf of organizations
CREATE TABLE users (
    user_id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(50) NOT NULL CHECK (role IN ('owner', 'partner', 'auditor', 'admin')),
    full_name       VARCHAR(255),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Datasets registered by data owners
CREATE TABLE datasets (
    dataset_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_org_id    UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    title           VARCHAR(255) NOT NULL,
    description     TEXT,
    category        VARCHAR(100),
    status          VARCHAR(50) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fields/columns within each dataset
CREATE TABLE dataset_fields (
    field_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dataset_id      UUID NOT NULL REFERENCES datasets(dataset_id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,
    data_type       VARCHAR(50) NOT NULL CHECK (data_type IN ('text', 'integer', 'numeric', 'boolean', 'date', 'timestamp', 'json')),
    sensitivity     VARCHAR(20) NOT NULL DEFAULT 'low' CHECK (sensitivity IN ('low', 'medium', 'high', 'pii')),
    description     TEXT,
    is_encrypted    BOOLEAN NOT NULL DEFAULT false,
    ordinal         INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (dataset_id, name)
);

-- ============================================================================
-- CONSENT MANAGEMENT
-- ============================================================================

-- Consent grants: per-field, purpose-bound, expiring, revocable
CREATE TABLE consent_grants (
    grant_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    grantor_org_id  UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    grantee_org_id  UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    dataset_id      UUID NOT NULL REFERENCES datasets(dataset_id) ON DELETE CASCADE,
    field_id        UUID NOT NULL REFERENCES dataset_fields(field_id) ON DELETE CASCADE,
    purpose         VARCHAR(500) NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID REFERENCES users(user_id),
    revocation_reason TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Ensure one grant per grantee/field/purpose combination
    UNIQUE (grantee_org_id, dataset_id, field_id, purpose),
    -- Expiry must be in future
    CHECK (expires_at > created_at)
);

-- Access requests from partners to data owners
CREATE TABLE access_requests (
    request_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    grantee_org_id  UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    dataset_id      UUID NOT NULL REFERENCES datasets(dataset_id) ON DELETE CASCADE,
    field_ids       UUID[] NOT NULL DEFAULT '{}',
    purpose         VARCHAR(500) NOT NULL,
    requested_expires_at TIMESTAMPTZ NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    decided_by      UUID REFERENCES users(user_id),
    decided_at      TIMESTAMPTZ,
    decision_note   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- AUDIT LOG (Append-only, Hash-chained)
-- ============================================================================

CREATE TABLE audit_log (
    log_id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(user_id),
    dataset_id      UUID REFERENCES datasets(dataset_id),
    field_id        UUID REFERENCES dataset_fields(field_id),
    action          VARCHAR(50) NOT NULL CHECK (action IN (
        'select', 'insert', 'update', 'delete',
        'grant_create', 'grant_revoke', 'grant_expire',
        'request_create', 'request_approve', 'request_deny',
        'login', 'logout', 'pii_scan', 'anomaly_alert'
    )),
    rows_affected   INTEGER NOT NULL DEFAULT 0,
    query_text      TEXT,
    client_ip       INET,
    user_agent      TEXT,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    prev_hash       BYTEA NOT NULL,
    row_hash        BYTEA NOT NULL,
    -- Prevent updates and deletes
    CONSTRAINT audit_log_immutable CHECK (false) NO INHERIT
);

-- Make audit_log append-only: revoke UPDATE and DELETE
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;

-- Anomaly alerts from AI detector
CREATE TABLE anomaly_alerts (
    alert_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(user_id),
    dataset_id      UUID REFERENCES datasets(dataset_id),
    score           NUMERIC(5,4) NOT NULL CHECK (score >= 0 AND score <= 1),
    reason          TEXT NOT NULL,
    features        JSONB,
    status          VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    resolved_by     UUID REFERENCES users(user_id)
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

-- Audit log queries
CREATE INDEX idx_audit_log_user_ts
    ON audit_log (user_id, ts DESC);

CREATE INDEX idx_audit_log_dataset_ts
    ON audit_log (dataset_id, ts DESC);

CREATE INDEX idx_audit_log_ts
    ON audit_log (ts DESC);

-- Anomaly alerts
CREATE INDEX idx_anomaly_alerts_user_status
    ON anomaly_alerts (user_id, status);

CREATE INDEX idx_anomaly_alerts_dataset_status
    ON anomaly_alerts (dataset_id, status);

-- ============================================================================
-- TRIGGERS FOR UPDATED_AT
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = now();
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