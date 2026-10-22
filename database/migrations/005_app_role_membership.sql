-- ConsentLedger: let the database login switch to the application role
-- Applied by Alembic revision 0005 (database/alembic_env/versions/0005_app_role_membership.py)
--
-- Every API request runs SET LOCAL ROLE consentledger_app so that row-level
-- security applies. A superuser may switch to any role, but on managed
-- PostgreSQL (Render, Neon, RDS, ...) the login is an ordinary user. Since
-- PostgreSQL 16, a user who creates a role gets ADMIN on it but not the right
-- to SET ROLE to it, so requests failed with
-- "permission denied to set role consentledger_app".
-- INHERIT FALSE: the login does not silently gain the role's privileges; it
-- only gains the right to switch to it.

DO $$
DECLARE
    v_super BOOLEAN;
BEGIN
    SELECT rolsuper INTO v_super FROM pg_roles WHERE rolname = current_user;
    IF v_super OR pg_has_role(current_user, 'consentledger_app', 'SET') THEN
        RETURN;  -- superusers, or already allowed
    END IF;
    IF current_setting('server_version_num')::int >= 160000 THEN
        EXECUTE format('GRANT consentledger_app TO %I WITH INHERIT FALSE, SET TRUE', current_user);
    ELSE
        EXECUTE format('GRANT consentledger_app TO %I', current_user);
    END IF;
END;
$$;
