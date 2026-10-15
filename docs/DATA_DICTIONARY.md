# Data Dictionary

Generated from the live schema by `scripts/data_dictionary.py`; descriptions are maintained in that script. See `ER_DIAGRAM.md` for relationships and the 3NF justification.

## organizations

Organizations taking part: NGOs, government agencies, funders, auditors.

| Column | Type | Null | Default | Keys | Description |
|---|---|---|---|---|---|
| `org_id` | uuid | no | `uuid_generate_v4()` | PK | Surrogate key. |
| `name` | varchar(255) | no |  |  | Display name. |
| `type` | varchar(50) | no |  |  | Kind of organization. |
| `description` | text | yes |  |  | Free-text description. |
| `contact_email` | varchar(255) | yes |  |  | General contact address. |
| `created_at` | timestamptz | no | `now()` |  | When the row was created. |
| `updated_at` | timestamptz | no | `now()` |  | Last change (maintained by trigger). |

Check constraints:

- `CHECK (((type) = ANY ((ARRAY['ngo', 'government', 'funder', 'auditor']))))`

## roles

RBAC lookup table. Every user has exactly one role.

| Column | Type | Null | Default | Keys | Description |
|---|---|---|---|---|---|
| `role_id` | smallint | no |  | PK | Fixed key (1 owner, 2 partner, 3 auditor, 4 admin). |
| `name` | varchar(30) | no |  | UNIQUE | Role name used by the API and RLS policies. |
| `description` | text | no |  |  | What the role may do. |
| `created_at` | timestamptz | no | `now()` |  | When the row was created. |

Check constraints:

- `CHECK (((name) ~ '^[a-z_]+$'))`

## users

People acting for an organization. One table for every role.

| Column | Type | Null | Default | Keys | Description |
|---|---|---|---|---|---|
| `user_id` | uuid | no | `uuid_generate_v4()` | PK | Surrogate key. |
| `org_id` | uuid | no |  | FK -> organizations | Organization the user acts for. |
| `role_id` | smallint | no |  | FK -> roles | The user's role (roles lookup). |
| `email` | varchar(255) | no |  | UNIQUE | Sign-in email, stored lower-case; matched against Google accounts. |
| `password_hash` | varchar(255) | yes |  |  | bcrypt hash for local login; NULL for Google-only accounts. |
| `google_sub` | varchar(255) | yes |  | UNIQUE | Google account id, linked on first Google sign-in. |
| `full_name` | varchar(255) | yes |  |  | Display name. |
| `is_active` | boolean | no | `true` |  | Deactivated users cannot sign in (users are never deleted once audited). |
| `last_login` | timestamptz | yes |  |  | Time of the last successful sign-in. |
| `created_at` | timestamptz | no | `now()` |  | When the row was created. |
| `updated_at` | timestamptz | no | `now()` |  | Last change (maintained by trigger). |

Check constraints:

- `CHECK ((((email) = lower((email))) AND ((email) ~~ '%_@_%')))`

## datasets

Datasets registered by data owners.

| Column | Type | Null | Default | Keys | Description |
|---|---|---|---|---|---|
| `dataset_id` | uuid | no | `uuid_generate_v4()` | PK | Surrogate key; also names the data table data_<id>. |
| `owner_org_id` | uuid | no |  | FK -> organizations | Organization that owns the data. |
| `title` | varchar(255) | no |  |  | Display title. |
| `description` | text | yes |  |  | What the records are. |
| `category` | varchar(100) | yes |  |  | Free-form category (health, education, ...). |
| `status` | varchar(50) | no | `'draft'` |  | draft (not shared), published (in the catalogue), archived (read-only). |
| `version` | integer | no | `1` |  | Incremented on metadata changes. |
| `created_at` | timestamptz | no | `now()` |  | When the row was created. |
| `updated_at` | timestamptz | no | `now()` |  | Last change (maintained by trigger). |

Check constraints:

- `CHECK (((status) = ANY ((ARRAY['draft', 'published', 'archived']))))`
- `CHECK ((version >= 1))`

## dataset_fields

Columns of a dataset, the unit of consent.

| Column | Type | Null | Default | Keys | Description |
|---|---|---|---|---|---|
| `field_id` | uuid | no | `uuid_generate_v4()` | PK, UNIQUE | Surrogate key. |
| `dataset_id` | uuid | no |  | FK -> datasets, UNIQUE, UNIQUE | Dataset the field belongs to. |
| `name` | varchar(63) | no |  | UNIQUE | Column name in the data table (safe identifier). |
| `data_type` | varchar(50) | no |  |  | Logical type; maps to a PostgreSQL type in the data table. |
| `sensitivity` | varchar(20) | no | `'low'` |  | low / medium / high / pii; controls the mask shown when not consented. |
| `description` | text | yes |  |  | What the field holds. |
| `is_encrypted` | boolean | no | `false` |  | Stored as pgcrypto ciphertext (BYTEA) in the data table. |
| `ordinal` | integer | no | `0` |  | Display order. |
| `created_at` | timestamptz | no | `now()` |  | When the row was created. |
| `updated_at` | timestamptz | no | `now()` |  | Last change (maintained by trigger). |

Check constraints:

- `CHECK (((data_type) = ANY ((ARRAY['text', 'integer', 'numeric', 'boolean', 'date', 'timestamp', 'json']))))`
- `CHECK (((name) ~ '^[a-z_][a-z0-9_]*$'))`
- `CHECK (((sensitivity) = ANY ((ARRAY['low', 'medium', 'high', 'pii']))))`

## consent_grants

Per-field, purpose-bound, expiring, revocable consent. Resolves the many-to-many between organizations and datasets.

| Column | Type | Null | Default | Keys | Description |
|---|---|---|---|---|---|
| `grant_id` | uuid | no | `uuid_generate_v4()` | PK | Surrogate key. |
| `grantor_org_id` | uuid | no |  | FK -> organizations | Organization giving consent (the dataset owner). |
| `grantee_org_id` | uuid | no |  | FK -> organizations, UNIQUE | Organization receiving access. |
| `dataset_id` | uuid | no |  | FK -> datasets, FK -> dataset_fields, UNIQUE | Dataset concerned. |
| `field_id` | uuid | no |  | FK -> dataset_fields, UNIQUE | Field concerned (must belong to dataset_id: composite FK). |
| `purpose` | varchar(500) | no |  | UNIQUE | The purpose the grantee must state when reading. |
| `granted_at` | timestamptz | no | `now()` |  | When consent was given. |
| `expires_at` | timestamptz | no |  |  | When consent ends (must be later than granted_at). |
| `revoked_at` | timestamptz | yes |  |  | When consent was revoked; NULL while active. |
| `revoked_by` | uuid | yes |  | FK -> users | User who revoked it. |
| `revocation_reason` | text | yes |  |  | Why it was revoked ('Expired' for the scheduled job). |
| `updated_at` | timestamptz | no | `now()` |  | Last change (maintained by trigger). |

Check constraints:

- `CHECK ((grantor_org_id <> grantee_org_id))`
- `CHECK ((expires_at > granted_at))`
- `CHECK (((revoked_at IS NULL) OR (revoked_at >= granted_at)))`
- `CHECK ((length(TRIM(BOTH FROM purpose)) > 0))`

## access_requests

Partners asking an owner for fields, for a purpose, until a date.

| Column | Type | Null | Default | Keys | Description |
|---|---|---|---|---|---|
| `request_id` | uuid | no | `uuid_generate_v4()` | PK | Surrogate key. |
| `grantee_org_id` | uuid | no |  | FK -> organizations | Requesting organization. |
| `requested_by` | uuid | yes |  | FK -> users | User who made the request. |
| `dataset_id` | uuid | no |  | FK -> datasets | Dataset requested. |
| `field_ids` | uuid[] | no | `'{}'::uuid[]` |  | Requested fields (validated by request_access()). |
| `purpose` | varchar(500) | no |  |  | Stated purpose. |
| `requested_expires_at` | timestamptz | no |  |  | Requested end of access. |
| `status` | varchar(20) | no | `'pending'` |  | pending / approved / denied / expired. |
| `decided_by` | uuid | yes |  | FK -> users | Owner who decided. |
| `decided_at` | timestamptz | yes |  |  | When it was decided. |
| `decision_note` | text | yes |  |  | Note from the owner. |
| `created_at` | timestamptz | no | `now()` |  | When the request was made. |
| `updated_at` | timestamptz | no | `now()` |  | Last change (maintained by trigger). |

Check constraints:

- `CHECK ((requested_expires_at > created_at))`
- `CHECK ((((status) = ANY ((ARRAY['pending', 'expired']))) OR (decided_at IS NOT NULL)))`
- `CHECK ((cardinality(field_ids) > 0))`
- `CHECK ((length(TRIM(BOTH FROM purpose)) > 0))`
- `CHECK (((status) = ANY ((ARRAY['pending', 'approved', 'denied', 'expired']))))`

## audit_log

Append-only, hash-chained record of every read and change.

| Column | Type | Null | Default | Keys | Description |
|---|---|---|---|---|---|
| `log_id` | uuid | no | `uuid_generate_v4()` | PK | Surrogate key. |
| `seq` | bigint | no |  | UNIQUE | Position in the chain (assigned under a lock by trigger). |
| `user_id` | uuid | yes |  | FK -> users | Acting user; NULL for system actions. |
| `dataset_id` | uuid | yes |  | FK -> datasets | Dataset concerned. |
| `field_id` | uuid | yes |  | FK -> dataset_fields | Single field concerned (grants). |
| `field_ids` | uuid[] | yes |  |  | Fields returned in clear text by a read. |
| `action` | varchar(50) | no |  |  | What happened (select, insert, grant_create, grant_revoke, login, ...). |
| `rows_affected` | integer | no | `0` |  | Rows read or written. |
| `query_text` | text | yes |  |  | Description of the access (never row values). |
| `client_ip` | inet | yes |  |  | Client address, when known. |
| `user_agent` | text | yes |  |  | Client user agent, when known. |
| `ts` | timestamptz | no | `now()` |  | When it happened. |
| `prev_hash` | bytea | no |  |  | row_hash of the previous entry (32 zero bytes for the first). |
| `row_hash` | bytea | no |  |  | SHA-256 over prev_hash and every content column. |

Check constraints:

- `CHECK (((action) = ANY ((ARRAY['select', 'insert', 'update', 'delete', 'grant_create', 'grant_update', 'grant_revoke', 'grant_expire', 'request_create', 'request_update', 'request_approve', 'request_deny', 'login', 'logout', 'pii_scan', 'anomaly_alert']))))`
- `CHECK ((octet_length(prev_hash) = 32))`
- `CHECK ((octet_length(row_hash) = 32))`
- `CHECK ((rows_affected >= 0))`

## anomaly_alerts

Unusual access flagged by the AI detector.

| Column | Type | Null | Default | Keys | Description |
|---|---|---|---|---|---|
| `alert_id` | uuid | no | `uuid_generate_v4()` | PK | Surrogate key. |
| `user_id` | uuid | no |  | FK -> users | User whose access was flagged. |
| `dataset_id` | uuid | yes |  | FK -> datasets | Dataset most read in the flagged hour. |
| `score` | numeric(5,4) | no |  |  | Anomaly score in [0, 1]. |
| `reason` | text | no |  |  | Human-readable explanation. |
| `features` | jsonb | yes |  |  | Feature values for the flagged hour (JSON). |
| `detector` | varchar(30) | no | `'isolation_forest'` |  | isolation_forest, rule (baseline) or manual. |
| `status` | varchar(20) | no | `'open'` |  | open / investigating / resolved / false_positive. |
| `created_at` | timestamptz | no | `now()` |  | When the alert was raised. |
| `resolved_at` | timestamptz | yes |  |  | When it was resolved. |
| `resolved_by` | uuid | yes |  | FK -> users | User who resolved it. |

Check constraints:

- `CHECK ((((status) <> ALL ((ARRAY['resolved', 'false_positive']))) OR (resolved_at IS NOT NULL)))`
- `CHECK (((detector) = ANY ((ARRAY['isolation_forest', 'rule', 'manual']))))`
- `CHECK (((score >= (0)::numeric) AND (score <= (1)::numeric)))`
- `CHECK (((status) = ANY ((ARRAY['open', 'investigating', 'resolved', 'false_positive']))))`

## revoked_tokens

JWT ids invalidated by logout (rejected until they expire).

| Column | Type | Null | Default | Keys | Description |
|---|---|---|---|---|---|
| `jti` | uuid | no |  | PK | Token id from the JWT. |
| `user_id` | uuid | no |  | FK -> users | Token owner. |
| `expires_at` | timestamptz | no |  |  | Token expiry (rows can be purged after this). |
| `revoked_at` | timestamptz | no | `now()` |  | When the user signed out. |

Check constraints:

- `CHECK ((expires_at > (revoked_at - '1 day'::interval)))`
