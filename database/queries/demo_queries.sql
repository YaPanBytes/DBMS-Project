-- ConsentLedger demo queries: joins, aggregates, views, window functions,
-- consent enforcement, audit verification, CRUD and a transaction.
-- Run against the seeded database:  psql "$DATABASE_URL" -f database/queries/demo_queries.sql
-- (psql users: replace postgresql+psycopg:// with postgresql://)

-- ---------------------------------------------------------------- 1. JOINS
-- Every active grant with the dataset, field, grantor and grantee (5-way join)
SELECT d.title            AS dataset,
       f.name             AS field,
       f.sensitivity,
       grantor.name       AS shared_by,
       grantee.name       AS shared_with,
       g.purpose,
       g.expires_at::date AS expires
FROM consent_grants g
JOIN datasets d            ON d.dataset_id = g.dataset_id
JOIN dataset_fields f      ON f.field_id = g.field_id
JOIN organizations grantor ON grantor.org_id = g.grantor_org_id
JOIN organizations grantee ON grantee.org_id = g.grantee_org_id
WHERE g.revoked_at IS NULL AND g.expires_at > now()
ORDER BY d.title, grantee.name, f.ordinal;

-- Users with their organization and role (users -> roles lookup)
SELECT u.email, r.name AS role, o.name AS organization, u.is_active
FROM users u
JOIN roles r         ON r.role_id = u.role_id
JOIN organizations o ON o.org_id = u.org_id
ORDER BY o.name, r.role_id;

-- Datasets nobody has been granted anything on yet (anti-join)
SELECT d.title, o.name AS owner
FROM datasets d
JOIN organizations o ON o.org_id = d.owner_org_id
LEFT JOIN consent_grants g ON g.dataset_id = d.dataset_id
WHERE g.grant_id IS NULL;

-- ---------------------------------------------------------------- 2. AGGREGATES
-- Fields per dataset by sensitivity (conditional aggregation)
SELECT d.title,
       count(*)                                    AS fields,
       count(*) FILTER (WHERE f.sensitivity = 'pii')  AS pii_fields,
       count(*) FILTER (WHERE f.is_encrypted)          AS encrypted_fields
FROM datasets d
JOIN dataset_fields f ON f.dataset_id = d.dataset_id
GROUP BY d.title
ORDER BY pii_fields DESC;

-- Reads per organization and dataset over the last 30 days, busiest first
SELECT o.name AS organization, d.title AS dataset,
       count(*)                AS reads,
       sum(a.rows_affected)    AS rows_read,
       max(a.rows_affected)    AS largest_read
FROM audit_log a
JOIN users u         ON u.user_id = a.user_id
JOIN organizations o ON o.org_id = u.org_id
JOIN datasets d      ON d.dataset_id = a.dataset_id
WHERE a.action = 'select' AND a.ts > now() - interval '30 days'
GROUP BY o.name, d.title
HAVING count(*) >= 5
ORDER BY rows_read DESC;

-- Request decisions per dataset owner
SELECT owner.name AS owner, r.status, count(*) AS requests
FROM access_requests r
JOIN datasets d          ON d.dataset_id = r.dataset_id
JOIN organizations owner ON owner.org_id = d.owner_org_id
GROUP BY ROLLUP (owner.name, r.status)
ORDER BY owner.name NULLS LAST, r.status NULLS LAST;

-- ---------------------------------------------------------------- 3. WINDOW FUNCTIONS
-- Each user's busiest hours and how they compare with that user's own baseline
SELECT user_id, hour_bucket, query_count, total_rows_read, baseline_rows_read,
       rows_vs_baseline, off_hours_share
FROM access_features_hourly
WHERE rows_vs_baseline > 5 OR off_hours_share > 0.5
ORDER BY rows_vs_baseline DESC NULLS LAST
LIMIT 10;

-- Running total of rows read per user, and the gap since their previous read
SELECT u.email, a.ts, a.rows_affected,
       sum(a.rows_affected) OVER (PARTITION BY a.user_id ORDER BY a.ts) AS running_rows,
       a.ts - lag(a.ts) OVER (PARTITION BY a.user_id ORDER BY a.ts)     AS since_previous,
       rank() OVER (PARTITION BY a.user_id ORDER BY a.rows_affected DESC) AS size_rank
FROM audit_log a
JOIN users u ON u.user_id = a.user_id
WHERE a.action = 'select'
ORDER BY u.email, a.ts
LIMIT 20;

-- How quickly partners used new grants
SELECT * FROM grant_usage_latency ORDER BY hours_to_first_use NULLS LAST LIMIT 10;

-- ---------------------------------------------------------------- 4. VIEWS & ENFORCEMENT
-- What Global Fund can see, through the masked read path (session context set
-- the way the API sets it at the start of every request)
SELECT set_config('consentledger.current_user_id', (SELECT user_id::text FROM users WHERE email = 'funder@globalfund.org'), false),
       set_config('consentledger.current_org_id',  (SELECT org_id::text  FROM users WHERE email = 'funder@globalfund.org'), false);
SELECT * FROM partner_dataset_view ORDER BY title, field_name;
SELECT access_dataset((SELECT dataset_id FROM datasets WHERE title = 'Poverty Relief Beneficiaries 2024'),
                      'impact_evaluation', 3, 0);
SELECT set_config('consentledger.current_user_id', '', false), set_config('consentledger.current_org_id', '', false);

-- ---------------------------------------------------------------- 5. AUDIT CHAIN
SELECT is_audit_chain_valid() AS chain_valid, count(*) AS entries_checked FROM verify_chain();

-- ---------------------------------------------------------------- 6. CRUD + TRANSACTION
-- Create, read, update an organization; the whole block is rolled back.
BEGIN;
INSERT INTO organizations (name, type, contact_email)
VALUES ('Demo Cooperative', 'ngo', 'hello@demo.coop');
SELECT org_id, name, type FROM organizations WHERE name = 'Demo Cooperative';
UPDATE organizations SET description = 'Updated in a transaction' WHERE name = 'Demo Cooperative';
DELETE FROM organizations WHERE name = 'Demo Cooperative';
ROLLBACK;
