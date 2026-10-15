# ConsentLedger Entity-Relationship Diagram

## Overview
Normalized to 3NF. Core entities: Organizations, Users, Datasets, Fields, Consent Grants, Access Requests, Audit Logs, Anomaly Alerts.

## Entities & Relationships

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│  organizations  │       │     users       │       │    datasets     │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ org_id (PK)     │◄──────│ user_id (PK)    │       │ dataset_id (PK) │
│ name            │       │ org_id (FK)     │       │ owner_org_id(FK)│
│ type            │       │ email           │       │ title           │
│ description     │       │ password_hash   │       │ description     │
│ contact_email   │       │ role            │       │ category        │
│ created_at      │       │ full_name       │       │ status          │
│ updated_at      │       │ is_active       │       │ version         │
└─────────────────┘       │ last_login      │       │ created_at      │
                          │ created_at      │       │ updated_at      │
                          │ updated_at      │       └────────┬────────┘
                          └────────┬────────┘                │
                                   │                         │
                                   │              ┌──────────┴──────────┐
                                   │              │                     │
                          ┌────────▼────────┐ ┌───▼───────────────────┐ │
                          │ consent_grants  │ │ dataset_fields        │ │
                          ├─────────────────┤ ├───────────────────────┤ │
                          │ grant_id (PK)   │ │ field_id (PK)         │ │
                          │ grantor_org(FK) │ │ dataset_id (FK)       │ │
                          │ grantee_org(FK) │ │ name                  │ │
                          │ dataset_id (FK) │ │ data_type             │ │
                          │ field_id (FK)   │ │ sensitivity           │ │
                          │ purpose         │ │ description           │ │
                          │ expires_at      │ │ is_encrypted          │ │
                          │ revoked_at      │ │ ordinal               │ │
                          │ revoked_by(FK)  │ │ created_at            │ │
                          │ revocation_rsn  │ │ updated_at            │ │
                          │ created_at      │ └───────────────────────┘ │
                          │ updated_at      │                           │
                          └────────┬────────┘                           │
                                   │                                    │
                          ┌────────▼────────┐                           │
                          │ access_requests │                           │
                          ├─────────────────┤                           │
                          │ request_id (PK) │                           │
                          │ grantee_org(FK) │                           │
                          │ dataset_id (FK) │                           │
                          │ field_ids[]     │                           │
                          │ purpose         │                           │
                          │ req_expires_at  │                           │
                          │ status          │                           │
                          │ decided_by(FK)  │                           │
                          │ decided_at      │                           │
                          │ decision_note   │                           │
                          │ created_at      │                           │
                          │ updated_at      │                           │
                          └─────────────────┘                           │
                                   │                                    │
                                   │              ┌────────────────────┘
                                   │              │
                          ┌────────▼────────┐ ┌───▼───────────────────────┐
                          │   audit_log     │ │    anomaly_alerts        │
                          ├─────────────────┤ ├───────────────────────────┤
                          │ log_id (PK)     │ │ alert_id (PK)            │
                          │ user_id (FK)    │ │ user_id (FK)             │
                          │ dataset_id(FK)  │ │ dataset_id (FK)          │
                          │ field_id (FK)   │ │ score                    │
                          │ action          │ │ reason                   │
                          │ rows_affected   │ │ features (JSONB)         │
                          │ query_text      │ │ status                   │
                          │ client_ip       │ │ created_at               │
                          │ user_agent      │ │ resolved_at              │
                          │ ts              │ │ resolved_by (FK)         │
                          │ prev_hash       │ └───────────────────────────┘
                          │ row_hash        │
                          └─────────────────┘
```

## Relationship Details

### 1. Organization → Users (1:N)
- One organization has many users
- `users.org_id` → `organizations.org_id` (CASCADE DELETE)

### 2. Organization → Datasets as Owner (1:N)
- One organization owns many datasets
- `datasets.owner_org_id` → `organizations.org_id` (CASCADE DELETE)

### 3. Organization → Consent Grants as Grantor (1:N)
- One organization grants many consents
- `consent_grants.grantor_org_id` → `organizations.org_id` (CASCADE DELETE)

### 4. Organization → Consent Grants as Grantee (1:N)
- One organization receives many consents
- `consent_grants.grantee_org_id` → `organizations.org_id` (CASCADE DELETE)

### 5. Organization → Access Requests as Grantee (1:N)
- One organization makes many access requests
- `access_requests.grantee_org_id` → `organizations.org_id` (CASCADE DELETE)

### 6. Dataset → Fields (1:N)
- One dataset has many fields
- `dataset_fields.dataset_id` → `datasets.dataset_id` (CASCADE DELETE)

### 7. Dataset → Consent Grants (1:N)
- One dataset has many consent grants
- `consent_grants.dataset_id` → `datasets.dataset_id` (CASCADE DELETE)

### 8. Dataset → Access Requests (1:N)
- One dataset receives many access requests
- `access_requests.dataset_id` → `datasets.dataset_id` (CASCADE DELETE)

### 9. Dataset → Audit Logs (1:N)
- One dataset has many audit log entries
- `audit_log.dataset_id` → `datasets.dataset_id` (SET NULL)

### 9. Field → Consent Grants (1:N)
- One field can have many consent grants (different grantees/purposes)
- `consent_grants.field_id` → `dataset_fields.field_id` (CASCADE DELETE)

### 10. User → Audit Logs (1:N)
- One user generates many audit log entries
- `audit_log.user_id` → `users.user_id` (RESTRICT DELETE)

### 11. User → Anomaly Alerts (1:N)
- One user can have many anomaly alerts
- `anomaly_alerts.user_id` → `users.user_id` (RESTRICT DELETE)

### 12. User → Consent Grants (Revoked By) (1:N)
- One user can revoke many grants
- `consent_grants.revoked_by` → `users.user_id` (SET NULL)

### 13. User → Access Requests (Decided By) (1:N)
- One user can decide many requests
- `access_requests.decided_by` → `users.user_id` (SET NULL)

### 14. User → Anomaly Alerts (Resolved By) (1:N)
- One user can resolve many alerts
- `anomaly_alerts.resolved_by` → `users.user_id` (SET NULL)

## Normalization Verification (3NF)

### organizations
- PK: org_id
- All non-key attributes depend on the whole key (org_id)
- No transitive dependencies ✓

### users
- PK: user_id
- org_id is FK, not a candidate key
- email is unique but not a PK
- All attributes depend on user_id ✓

### datasets
- PK: dataset_id
- owner_org_id is FK
- All attributes depend on dataset_id ✓

### dataset_fields
- PK: field_id
- dataset_id is FK
- (dataset_id, name) is unique
- All attributes depend on field_id ✓

### consent_grants
- PK: grant_id
- Composite unique: (grantee_org_id, dataset_id, field_id, purpose)
- All attributes depend on grant_id ✓
- No partial dependencies (grant_id is surrogate)

### access_requests
- PK: request_id
- All attributes depend on request_id ✓

### audit_log
- PK: log_id
- All attributes depend on log_id ✓
- Hash chain provides tamper evidence

### anomaly_alerts
- PK: alert_id
- All attributes depend on alert_id ✓

## Key Constraints

### Primary Keys
All tables use UUID (uuid_generate_v4()) as surrogate primary keys.

### Foreign Keys
All FKs have appropriate ON DELETE behavior:
- CASCADE: Child records deleted when parent deleted (users, datasets, fields, grants, requests)
- SET NULL: Reference preserved but nullable (revoked_by, decided_by, resolved_by)
- RESTRICT: Prevent deletion if referenced (audit_log.user_id, anomaly_alerts.user_id)

### Unique Constraints
- organizations: none (name not unique)
- users: email
- datasets: none (title not unique per org)
- dataset_fields: (dataset_id, name)
- consent_grants: (grantee_org_id, dataset_id, field_id, purpose)
- access_requests: none
- audit_log: log_id only
- anomaly_alerts: alert_id only

### Check Constraints
- organizations.type IN ('ngo', 'government', 'funder', 'auditor')
- users.role IN ('owner', 'partner', 'auditor', 'admin')
- datasets.status IN ('draft', 'published', 'archived')
- dataset_fields.data_type IN ('text', 'integer', 'numeric', 'boolean', 'date', 'timestamp', 'json')
- dataset_fields.sensitivity IN ('low', 'medium', 'high', 'pii')
- consent_grants.expires_at > created_at
- access_requests.status IN ('pending', 'approved', 'denied', 'expired')
- audit_log.action IN (14 allowed actions)
- anomaly_alerts.score BETWEEN 0 AND 1
- anomaly_alerts.status IN ('open', 'investigating', 'resolved', 'false_positive')

## Indexes

### Performance Indexes
```sql
-- Consent grant lookups (critical for RLS)
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
```

## Security Model

### Row-Level Security (RLS)
Enabled on: datasets, dataset_fields, consent_grants, access_requests

Policies enforce:
1. **Owners** see/modify their own datasets and fields
2. **Partners** see only consented fields via masked views
3. **Grantors** manage their own grants
4. **Grantees** see grants issued to them
5. **Auditors** read-only access to all

### Session Variables for RLS
```sql
SET LOCAL consentledger.current_user_id = 'uuid';
SET LOCAL consentledger.current_org_id = 'uuid';
```

### Audit Chain
- Append-only: UPDATE/DELETE revoked on audit_log
- Hash chain: row_hash = SHA256(prev_hash || user_id || dataset_id || action || ts)
- Verification function: verify_audit_chain()

## Views for Anomaly Detection

### access_features_hourly
Per-user, per-hour access patterns:
- query_count, distinct_datasets, distinct_fields
- total_rows_read, select_count, write_count
- off_hours_count, max_rows_per_query

### grant_usage_latency
Grant-to-first-use timing:
- grant_time, first_access_time, hours_to_first_use