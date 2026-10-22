# ConsentLedger Database Design

PostgreSQL 16 is the single enforcement point: every client (the web app, the
API, a script, a SQL console using the application role) gets the same consent
rules, because they are implemented as row-level security, privileges, masked
views and functions inside the database.

- Entities, relationships, relational schema, 3NF: [`ER_DIAGRAM.md`](ER_DIAGRAM.md)
- Every column: [`DATA_DICTIONARY.md`](DATA_DICTIONARY.md)
- Example CRUD, joins, aggregates, window functions: [`../database/queries/demo_queries.sql`](../database/queries/demo_queries.sql)

## 1. Migrations

The schema is written in SQL because it relies on features SQLAlchemy cannot
express (policies, plpgsql functions, triggers, procedures). Alembic applies it:

| Revision | File | Contents |
|---|---|---|
| `0001` | `database/migrations/001_initial_schema.sql` | Tables, keys, constraints, indexes, `updated_at` triggers, append-only trigger, role rows |
| `0002` | `database/migrations/002_rls_views_audit.sql` | RLS, hash chain, audit triggers, masked views, read path, procedures, feature views, application role |
| `0003` | `database/migrations/003_auth_tokens.sql` | `revoked_tokens` for logout |
| `0004` | `database/migrations/004_performance_and_fixes.sql` | Faster policies and read path (same rules), salted AES-256 encryption, `verify_chain_summary()`, `request_access` returns the new id, admins can read alerts and dataset metadata |
| `0005` | `database/migrations/005_app_role_membership.sql` | Lets the database login switch to `consentledger_app` on managed PostgreSQL, where the login is not a superuser |

Each revision has a matching downgrade in `database/migrations/down/`. Commands:
`alembic upgrade head` or `python -m database.migrate` (also `status`,
`downgrade <rev>`). The ORM models in `database/models` match the database
exactly: `alembic revision --autogenerate` finds no differences.

## 2. Request context and the application role

At the start of every API request the backend runs, inside the request's transaction:

```sql
SELECT set_config('consentledger.current_user_id', :user, true),
       set_config('consentledger.current_org_id',  :org,  true),
       set_config('consentledger.encryption_key',  :key,  true);
SET LOCAL ROLE consentledger_app;
```

`true` makes the settings transaction-local (the bind-parameter equivalent of
`SET LOCAL`). RLS is bypassed by superusers and table owners, so requests switch
to `consentledger_app`, which owns nothing. On managed PostgreSQL (Render and the
like) the login is an ordinary user; migration 0005 grants it the right to
switch to `consentledger_app` (`SET TRUE, INHERIT FALSE`), which PostgreSQL 16
does not give a role's creator automatically. The backend re-applies the context at
the start of every transaction a request opens (`backend/app/db.py`).

Helpers: `current_user_id()`, `current_user_org_id()`, `current_user_role()`,
`current_user_has_role(...)`, `current_purpose()`, `is_dataset_owner(ds)`.

## 3. Row-level security

RLS is enabled on `datasets`, `dataset_fields`, `consent_grants`,
`access_requests`, `audit_log` and `anomaly_alerts`.

| Table | Who sees / changes what |
|---|---|
| datasets | Members of the owning org see their datasets; only the **owner role** inserts/updates; owners and partners see the catalogue of *published* datasets; auditors and admins see all (metadata only). No delete policy (archive instead). |
| dataset_fields | Owners see and (owner role) edit their fields; field *descriptions* of published datasets are visible to partners so they know what to request; auditors see all. |
| consent_grants | Grantor and grantee orgs see a grant; only the owner role of the dataset's org can insert or update; auditors see all. A trigger stops a grant's identity (who/what/purpose/when) from changing. |
| access_requests | Requesting org and dataset owner see it; partners/owners create pending requests; owners decide; auditors see all. |
| audit_log | Auditors see everything; an org sees its own users' actions and everything done to its datasets; the app may append events only for the session user. |
| anomaly_alerts | Auditors and admins see all; owners see (and with auditors, triage) alerts on their datasets. |

The app role has no privileges on the per-dataset data tables, their masked
views, or the feature views.

Policies wrap their helper calls in scalar subqueries, e.g.
`owner_org_id = (SELECT current_user_org_id())` and
`dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[])`. An uncorrelated
subquery becomes an InitPlan, so each helper runs once per query rather than
once per row (counting 60k audit rows as an owner went from ~400 ms to ~15 ms).

## 4. Reading data: the masked, logged read path

Publishing a dataset (`publish_dataset(ds)`, owner only) creates:

- `data_<id>`: one column per field; encrypted fields hold `pgp_sym_encrypt` ciphertext;
- `data_<id>_masked`: a `security_barrier` view. For every field:
  `CASE WHEN (SELECT can_see_field(ds, field)) THEN value ELSE '[REDACTED]' (pii) / '[MASKED]' END`,
  so non-consented values never leave the database, not even whether they are empty.
  Each check is an InitPlan, evaluated once per query.

`can_see_field` is true for the owning organization, or for a partner with an
active, unexpired grant on that field **for the declared purpose**. One view
serves every partner because it reads the session's organization and purpose.

Partners read only through:

```sql
SELECT access_dataset(dataset_id, purpose, limit, offset);  -- rows as JSON
```

It requires a purpose (for partners), refuses if there is no active grant for
it, and works out once which fields the caller may see. It then takes the
requested page from the data table (`ORDER BY row_id LIMIT/OFFSET`) and builds
each output column as either the value (decrypted if needed) or a constant
mask, so only the returned rows are ever decrypted. It applies exactly the
rules of the masked view, and **writes an audit entry** with the number of
rows and the list of fields returned in clear text. Revoking a grant therefore
takes effect on the very next call; there is nothing to cache.

Before 0004 the function read the masked view, which evaluated every cell of
every row before `LIMIT`; a 100-row page of a 20k-row dataset took 3.6 s for a
partner and 9.5 s for an owner (decryption). It now takes under 10 ms and about
140 ms (or ~6 ms with ciphertext written since 0004).

Writes go through `ingest_dataset_rows(ds, rows_json)` (owner only), which
encrypts flagged fields with the request's key. Statement-level triggers write
one audit entry per write statement with the row count (never the values).

## 5. Hash-chained, append-only audit log

- `trg_audit_log_immutable` rejects `UPDATE`/`DELETE` for everyone (including the
  owner); `UPDATE, DELETE, TRUNCATE` are revoked from PUBLIC.
- `trg_audit_log_chain` (BEFORE INSERT) runs for *every* insert: it takes a
  transaction-level advisory lock, assigns the next `seq`, and sets
  `prev_hash` (previous row's hash; 32 zero bytes for the first) and
  `row_hash = SHA-256(json_build_array(hex(prev_hash), user_id, dataset_id,
  field_id, field_ids, action, rows_affected, query_text, client_ip, user_agent,
  ts in UTC)::text)`. Client-supplied hashes are ignored. Ordering by `seq`
  (not `ts`, which repeats within a transaction) keeps the chain well defined.
- Business triggers record grants (`grant_create/update/revoke/expire`),
  requests (`request_create/approve/deny`) and dataset changes. They run in the
  same transaction as the change, so **a grant or revocation and its audit entry
  commit or roll back together**.
- `verify_chain()` walks the chain in `seq` order, returning one row per entry
  up to the first whose link or content does not match.
  `verify_chain_summary()` does the same walk and returns a single row
  (`is_valid, total_rows, verified_rows, first_bad_log_id, error_msg`); the API
  and `is_audit_chain_valid()` use it. An independent
  Python re-implementation lives in `database/scripts/verify_audit.py`
  (`--detailed`), and `--tamper-test` demonstrates detection inside a rolled-back
  transaction.

## 6. Stored procedures

| Procedure | What it does |
|---|---|
| `request_access(user, dataset, field_ids, purpose, expires_at, INOUT request_id)` | Partner asks for fields of a published dataset; validates fields, purpose, expiry; returns the new request id |
| `approve_access_request(user, request, field_ids, purpose, expires_at, note)` | Owner approves, optionally narrowing fields/expiry; creates the grants atomically |
| `deny_access_request(user, request, note)` | Owner denies |
| `revoke_grant(user, grant, reason)` | Instant revocation |
| `expire_grants()` | Scheduled job: expires old grants and stale requests |

All are `SECURITY DEFINER` with a fixed `search_path`. `assert_actor()` checks
that the acting user is the session user and has a permitted role, and the
procedures record that user in the audit trail.

## 7. Feature views for the anomaly detector (window functions)

- `access_event_features`: per read, `ROW_NUMBER`, `LAG` (seconds since the
  user's previous read), `COUNT`/`SUM` over a one-hour `RANGE` window, the user's
  average rows and off-hours share, and `PERCENT_RANK` of the read size.
- `access_features_hourly`: per user-hour, query/read/write counts, distinct
  datasets and fields, rows per request, off-hours share, a rolling baseline over
  the user's previous 24 active hours (`ROWS BETWEEN 24 PRECEDING AND 1
  PRECEDING`), the ratio to that baseline, hours since previous activity, and the
  hour's `RANK` across users.
- `grant_usage_latency`: time from a grant to its first use (`ROW_NUMBER` per grant).

Hours are computed in UTC; off-hours means outside 08:00-18:59 UTC.

## 8. Field-level encryption

Fields flagged `is_encrypted` are stored with `pgp_sym_encrypt` (pgcrypto),
using AES-256 with a salted S2K (`cipher-algo=aes256, s2k-mode=1`). The key is a
long random secret, so pgcrypto's default iterated key stretching only added
about 1 ms per value; ciphertext written before 0004 still decrypts. The
key is never stored in the database: the API passes `ENCRYPTION_KEY` per request
in a transaction-local setting. `decrypt_field()` is only called for fields the
viewer may see (in `access_dataset` and the masked view).

## 9. Backup and restore

`database/scripts/backup_restore.py` wraps `pg_dump`/`pg_restore`:

```bash
python -m database.scripts.backup_restore backup                 # custom format (.dump)
python -m database.scripts.backup_restore backup --format plain  # .sql.gz
python -m database.scripts.backup_restore backup --list
python -m database.scripts.backup_restore verify <file>          # pg_restore --list / header check
python -m database.scripts.backup_restore restore <file> [--clean]
```

Data-only restores use `--disable-triggers` so restored rows don't generate new
audit entries. The test suite includes a full round trip
(`test_backup_and_restore_round_trip`): dump the seeded database, restore it into
a fresh one, compare counts, verify the chain, and check new entries still chain.

## 10. Seed data

`python -m database.seeds.seed_data` creates 6 organizations, 17 users, 7
datasets (6 published with 60-120 rows each, PII columns encrypted), 49 fields,
25 grants, 3 pending requests and ~1,400 access events from
`ai/log_generator.py` (30 days, with injected bulk-export, off-hours and slow
exfiltration patterns), then runs the anomaly detector.

## 11. Security checklist

- [x] RLS on all consent-related tables, driven by per-request session settings
- [x] API runs as a non-owner role; no direct access to data tables or feature views
- [x] Purpose-bound reads; non-consented values masked inside the database
- [x] Every read and write recorded in an append-only, hash-chained log
- [x] Audit history protected by `RESTRICT` foreign keys and an immutability trigger
- [x] Procedures check the acting user and role; `IS DISTINCT FROM` for authorization
- [x] PII encrypted at rest with pgcrypto; key held outside the database
- [x] Passwords hashed with bcrypt; secrets only in `.env`
