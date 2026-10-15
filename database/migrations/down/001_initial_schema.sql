-- Reverts 001_initial_schema.sql
DROP TABLE IF EXISTS anomaly_alerts, audit_log, access_requests, consent_grants,
                     dataset_fields, datasets, users, roles, organizations CASCADE;
DROP FUNCTION IF EXISTS prevent_audit_log_modification() CASCADE;
DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;
