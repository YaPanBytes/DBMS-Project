-- Downgrade of 005_app_role_membership.sql: nothing to undo. The membership is
-- harmless, and revoking it would break a running API on managed PostgreSQL.
SELECT 1;
