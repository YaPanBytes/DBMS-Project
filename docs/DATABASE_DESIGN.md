# ConsentLedger Database Design Document

**Member A: Database Lead**  
**Version:** 1.0  
**Date:** 2026-10-15

---

## 1. Introduction

This document describes the database design for ConsentLedger, a PostgreSQL-backed data-sharing hub that enforces per-field, purpose-bound consent at the database level through Row-Level Security (RLS), masked views, and a hash-chained append-only audit log.

### 1.1 Design Goals
- **Database-enforced consent**: No query path can bypass consent checks
- **Instant revocation**: Revoked grants block access on next query
- **Tamper-evident audit**: Hash-chained log detects any modification
- **3NF normalization**: Eliminate redundancy, ensure data integrity
- **Performance**: Indexes optimized for consent checks and audit queries

### 1.2 Scope
- Core schema (8 tables)
- RLS policies (16 policies)
- Triggers and stored procedures (7 functions/procedures)
- Views for anomaly detection (2 views)
- Audit chain verification

---

## 2. Schema Overview

### 2.1 Table Summary

| Table | Purpose | Rows (Demo) |
|-------|---------|-------------|
| `organizations` | NGOs, agencies, funders, auditors | 6 |
| `users` | People acting for organizations | ~18 |
| `datasets` | Registered datasets | 6 |
| `dataset_fields` | Fields/columns per dataset | ~45 |
| `consent_grants` | Per-field, purpose-bound grants | ~15 |
| `access_requests` | Partner requests for access | 2 |
| `audit_log` | Append-only access records | ~500 |
| `anomaly_alerts` | AI detector output | 3 |

### 2.2 Extensions Required
```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;      -- Encryption, hashing
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";   -- UUID generation
```

---

## 3. Detailed Table Design

### 3.1 organizations
```sql
CREATE TABLE organizations (
    org_id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    type            VARCHAR(50) NOT NULL CHECK (type IN ('ngo', 'government', 'funder', 'auditor')),
    description     TEXT,
    contact_email   VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```
**Indexes:** `idx_organizations_type`

### 3.2 users
```sql
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
```
**Indexes:** `idx_users_org_id`, `idx_users_email`

### 3.3 datasets
```sql
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
```
**Indexes:** `idx_datasets_owner_org_id`, `idx_datasets_status`

### 3.4 dataset_fields
```sql
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
```
**Indexes:** `idx_dataset_fields_dataset_id`

### 3.5 consent_grants (Core Consent Model)
```sql
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
    UNIQUE (grantee_org_id, dataset_id, field_id, purpose),
    CHECK (expires_at > created_at)
);
```
**Indexes:**
- `idx_consent_grants_grantee_dataset_expires` (grantee_org_id, dataset_id, expires_at) WHERE revoked_at IS NULL
- `idx_consent_grants_grantor_dataset` (grantor_org_id, dataset_id)
- `idx_consent_grants_field` (field_id)

**Key Design Decisions:**
- One row per (grantee, dataset, field, purpose) combination
- `expires_at` enables automatic expiry
- `revoked_at` enables instant revocation (RLS checks this)
- `purpose` enables purpose-bound access
- Partial index on active grants optimizes RLS checks

### 3.6 access_requests
```sql
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
```
**Indexes:** `idx_access_requests_grantee_status`, `idx_access_requests_dataset_status`

### 3.7 audit_log (Append-Only, Hash-Chained)
```sql
CREATE TABLE audit_log (
    log_id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(user_id),
    dataset_id      UUID REFERENCES datasets(dataset_id),
    field_id        UUID REFERENCES dataset_fields(field_id),
    action          VARCHAR(50) NOT NULL CHECK (action IN (...)),
    rows_affected   INTEGER NOT NULL DEFAULT 0,
    query_text      TEXT,
    client_ip       INET,
    user_agent      TEXT,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    prev_hash       BYTEA NOT NULL,
    row_hash        BYTEA NOT NULL,
    CONSTRAINT audit_log_immutable CHECK (false) NO INHERIT
);

REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;
```

**Hash Chain Formula:**
```
row_hash = SHA256(prev_hash || user_id || dataset_id || action || ts)
```

**Indexes:** `idx_audit_log_user_ts`, `idx_audit_log_dataset_ts`, `idx_audit_log_ts`

### 3.8 anomaly_alerts
```sql
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
```
**Indexes:** `idx_anomaly_alerts_user_status`, `idx_anomaly_alerts_dataset_status`

---

## 4. Row-Level Security (RLS) Design

### 4.1 Session Context Functions
```sql
current_user_org_id()  -- Returns UUID from session variable
current_user_id()      -- Returns UUID from session variable
```

Application sets per-request:
```sql
SET LOCAL consentledger.current_user_id = '...';
SET LOCAL consentledger.current_org_id = '...';
```

### 4.2 RLS Policies (16 Total)

| Table | Policy Name | Target Role | Operation | Condition |
|-------|-------------|-------------|-----------|-----------|
| datasets | pol_datasets_owner_select | owner | SELECT | owner_org_id = current_org |
| datasets | pol_datasets_owner_insert | owner | INSERT | owner_org_id = current_org |
| datasets | pol_datasets_owner_update | owner | UPDATE | owner_org_id = current_org |
| datasets | pol_datasets_partner_select | partner | SELECT | Has active grant on dataset |
| datasets | pol_datasets_auditor_select | auditor | SELECT | user.role = 'auditor' |
| dataset_fields | pol_fields_owner_select | owner | SELECT | Owner of dataset |
| dataset_fields | pol_fields_partner_select | partner | SELECT | has_field_access() |
| dataset_fields | pol_fields_auditor_select | auditor | SELECT | user.role = 'auditor' |
| consent_grants | pol_grants_grantor_select | grantor | SELECT | grantor_org_id = current_org |
| consent_grants | pol_grants_grantee_select | grantee | SELECT | grantee_org_id = current_org |
| consent_grants | pol_grants_grantor_insert | grantor | INSERT | grantor_org_id = current_org |
| consent_grants | pol_grants_grantor_revoke | grantor | UPDATE | grantor_org_id = current_org AND revoking |
| consent_grants | pol_grants_auditor_select | auditor | SELECT | user.role = 'auditor' |
| access_requests | pol_requests_grantee_select | grantee | SELECT | grantee_org_id = current_org |
| access_requests | pol_requests_grantor_select | grantor | SELECT | Owner of dataset |
| access_requests | pol_requests_grantee_insert | grantee | INSERT | grantee_org_id = current_org |
| access_requests | pol_requests_grantor_update | grantor | UPDATE | Owner of dataset AND deciding |
| access_requests | pol_requests_auditor_select | auditor | SELECT | user.role = 'auditor' |

### 4.3 Field-Level Access Function
```sql
has_field_access(grantee_org_id, dataset_id, field_id, purpose) 
    RETURNS BOOLEAN
```
Checks: active grant exists for exact field + purpose, not revoked, not expired.

---

## 5. Masked Views

### 5.1 Partner Dataset View
```sql
CREATE VIEW partner_dataset_view AS
SELECT d.dataset_id, d.title, d.description, d.category,
       cg.grant_id, cg.field_id, df.name AS field_name,
       df.data_type, df.sensitivity, cg.purpose,
       cg.expires_at, cg.revoked_at
FROM datasets d
JOIN consent_grants cg ON cg.dataset_id = d.dataset_id
JOIN dataset_fields df ON df.field_id = cg.field_id
WHERE cg.grantee_org_id = current_user_org_id()
  AND cg.revoked_at IS NULL
  AND cg.expires_at > now()
  AND d.status = 'published';
```

### 5.2 Data Access (Dynamic)
Each published dataset gets a data table `data_<dataset_id>` with RLS.
Partners query through generated views that mask non-consented columns:
- PII fields → `[REDACTED:type]`
- High sensitivity → `[MASKED]`
- Medium sensitivity → `XXXX` (regex replace)
- Low sensitivity → actual value

---

## 6. Triggers & Stored Procedures

### 6.1 Updated_at Trigger (All Tables)
```sql
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;
```

### 6.2 Audit Log Trigger
```sql
CREATE OR REPLACE FUNCTION log_data_access()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
-- Computes hash chain, inserts into audit_log
$$;
```
Attached to: consent_grants, access_requests, datasets, data_* tables

### 6.3 Stored Procedures

| Procedure | Purpose |
|-----------|---------|
| `request_access(user, dataset, field_ids, purpose, expires_at)` | Create access request with validation |
| `approve_access_request(user, request_id, approved_fields, purpose, expires_at, note)` | Approve request, create grants atomically |
| `revoke_grant(user, grant_id, reason)` | Instant revocation (sets revoked_at = now()) |
| `expire_grants()` | Scheduled job: revoke expired grants |

---

## 7. Audit Chain Verification

### 7.1 Verification Function
```sql
CREATE OR REPLACE FUNCTION verify_audit_chain()
RETURNS TABLE (log_id UUID, expected_hash BYTEA, actual_hash BYTEA, 
               is_valid BOOLEAN, error_msg TEXT)
```
- Iterates audit_log in timestamp order
- Verifies `prev_hash` matches previous `row_hash`
- Recomputes `row_hash` from components
- Returns first mismatch with details

### 7.2 Quick Check
```sql
CREATE OR REPLACE FUNCTION is_audit_chain_valid()
RETURNS BOOLEAN
```
Returns TRUE if entire chain valid.

### 7.3 Tamper Detection
Any modification to audit_log breaks the chain:
- UPDATE row_hash → next row's prev_hash mismatch
- DELETE row → next row's prev_hash mismatch
- INSERT row → prev_hash mismatch with previous row

---

## 8. Anomaly Detection Features

### 8.1 access_features_hourly View
```sql
CREATE VIEW access_features_hourly AS
SELECT user_id, date_trunc('hour', ts) AS hour_bucket,
       COUNT(*) AS query_count,
       COUNT(DISTINCT dataset_id) AS distinct_datasets,
       COUNT(DISTINCT field_id) AS distinct_fields,
       SUM(rows_affected) AS total_rows_read,
       COUNT(*) FILTER (WHERE action = 'select') AS select_count,
       COUNT(*) FILTER (WHERE action IN ('insert','update','delete')) AS write_count,
       COUNT(*) FILTER (WHERE EXTRACT(hour FROM ts) NOT BETWEEN 8 AND 18) AS off_hours_count,
       MAX(rows_affected) AS max_rows_per_query
FROM audit_log
WHERE action IN ('select', 'insert', 'update', 'delete')
GROUP BY user_id, date_trunc('hour', ts);
```

### 8.2 grant_usage_latency View
```sql
CREATE VIEW grant_usage_latency AS
SELECT cg.grant_id, cg.grantee_org_id, cg.dataset_id,
       cg.created_at AS grant_time,
       MIN(al.ts) AS first_access_time,
       EXTRACT(EPOCH FROM (MIN(al.ts) - cg.created_at)) / 3600 AS hours_to_first_use
FROM consent_grants cg
LEFT JOIN audit_log al 
    ON al.user_id IN (SELECT user_id FROM users WHERE org_id = cg.grantee_org_id)
   AND al.dataset_id = cg.dataset_id
   AND al.action = 'select'
   AND al.ts >= cg.created_at
WHERE cg.revoked_at IS NULL
GROUP BY cg.grant_id, cg.grantee_org_id, cg.dataset_id, cg.created_at;
```

---

## 9. Field-Level Encryption

### 9.1 pgcrypto Integration
```sql
-- Encrypt on insert
INSERT INTO data_xyz (ssn) VALUES (pgp_sym_encrypt('123-45-6789', 'key'));

-- Decrypt on select (owner only)
SELECT pgp_sym_decrypt(ssn, 'key') FROM data_xyz;
```

### 9.2 Encryption Strategy
- `dataset_fields.is_encrypted = true` marks columns for encryption
- Encryption key managed by application (not stored in DB)
- RLS ensures only authorized roles can decrypt

---

## 10. Performance Considerations

### 10.1 Critical Query: Consent Check (RLS)
```sql
-- RLS policy uses this index
SELECT 1 FROM consent_grants
WHERE grantee_org_id = $1
  AND dataset_id = $2
  AND field_id = $3
  AND revoked_at IS NULL
  AND expires_at > now();
```
**Index:** `(grantee_org_id, dataset_id, expires_at) WHERE revoked_at IS NULL`

### 10.2 Audit Log Queries
- Time-range queries: `idx_audit_log_ts`
- Per-user: `idx_audit_log_user_ts`
- Per-dataset: `idx_audit_log_dataset_ts`

### 10.3 Anomaly Detection
- Hourly aggregation uses window functions
- Materialized view refreshed periodically

---

## 11. Backup & Restore Strategy

### 11.1 Backup Types
| Type | Tool | Use Case |
|------|------|----------|
| Full (custom) | `pg_dump -Fc` | Production backup |
| Schema-only | `pg_dump -Fc --schema-only` | Migration testing |
| Data-only | `pg_dump -Fc --data-only` | Data refresh |

### 11.2 Restore Options
```bash
# Full restore (clean)
pg_restore -c -d consentledger backup.dump

# Schema only
pg_restore --schema-only -d consentledger backup.dump

# Single transaction
pg_restore --single-transaction -d consentledger backup.dump
```

### 11.3 Verification
- Metadata JSON with checksum
- `verify_backup()` checks file integrity
- Test restore to staging environment

---

## 12. Migration Strategy

### 12.1 Migration Files
```
database/migrations/
├── 001_initial_schema.sql      # Core tables, indexes, triggers
├── 002_rls_views_audit.sql     # RLS policies, views, audit chain, procedures
```

### 12.2 Migration Runner
- Tracks applied migrations in `schema_migrations` table
- Runs in transaction (rollback on failure)
- Checksums prevent re-running modified migrations

---

## 13. Seeding & Demo Data

### 13.1 Seed Script
`database/seeds/seed_data.py` creates:
- 6 organizations (3 NGOs, 2 gov, 1 funder, 1 auditor)
- 18 users (3 per org)
- 6 datasets with 45 fields
- 15 consent grants (active)
- 2 access requests (pending)
- 500+ audit log entries (with anomaly patterns)
- 3 anomaly alerts

### 13.2 Anomaly Patterns Injected
- **Bulk export**: 5 queries >5000 rows in 20 minutes
- **Off-hours**: 3 queries at 2:30 AM
- **Immediate use**: Grant used 2 minutes after creation

---

## 14. Security Checklist

- [x] RLS enabled on all sensitive tables
- [x] Policies cover all roles (owner, partner, auditor)
- [x] Audit log immutable (UPDATE/DELETE revoked)
- [x] Hash chain on audit log
- [x] Field-level encryption for PII
- [x] Password hashing (bcrypt)
- [x] Session variables for RLS context
- [x] Prepared statements in application (SQL injection prevention)
- [x] Secrets in environment variables

---

## 15. Future Enhancements

1. **Column-level encryption** with per-field keys
2. **Differential privacy** for aggregate queries
3. **Federated queries** across PostgreSQL instances
4. **Policy-as-code** for consent rules
5. **Automated compliance reports** (GDPR, HIPAA)

---

## Appendix: Quick Reference

### Common Queries
```sql
-- Active grants for org
SELECT * FROM consent_grants 
WHERE grantee_org_id = '...' AND revoked_at IS NULL AND expires_at > now();

-- Verify audit chain
SELECT * FROM verify_audit_chain() WHERE is_valid = false;

-- Hourly access features
SELECT * FROM access_features_hourly WHERE user_id = '...';

-- Grant latency
SELECT * FROM grant_usage_latency WHERE hours_to_first_use < 1;
```

### Demo Credentials (from seed)
| Role | Email | Password |
|------|-------|----------|
| Owner (Hope) | owner@hope.org | demo123 |
| Partner (Health) | partner@health.gov | demo123 |
| Funder | funder@globalfund.org | demo123 |
| Auditor | auditor@transparency.org | demo123 |