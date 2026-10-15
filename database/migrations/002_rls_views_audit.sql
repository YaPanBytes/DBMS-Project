-- ConsentLedger Row-Level Security, Masked Views, Audit Chain, Procedures & Features
-- Enforces per-field, purpose-bound consent at the database level
-- Applied by Alembic revision 0002 (alembic/versions/0002_rls_views_audit.py)
--
-- Request context: the API sets these transaction-local settings at the start
-- of every request (database.connection.set_rls_context):
--   consentledger.current_user_id   the signed-in user
--   consentledger.current_org_id    that user's organization
-- and runs as the non-owner role `consentledger_app` (created at the end of
-- this file). RLS does not apply to superusers or to table owners.

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

CREATE OR REPLACE FUNCTION current_user_org_id()
RETURNS UUID LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_setting TEXT;
BEGIN
    -- After RESET the setting is '' rather than NULL, hence NULLIF.
    v_setting := NULLIF(current_setting('consentledger.current_org_id', true), '');
    IF v_setting IS NOT NULL THEN
        RETURN v_setting::UUID;
    END IF;
    -- Fallback: database roles named like 'org_<uuid>'
    IF current_user ~ '^org_[0-9a-fA-F-]{36}$' THEN
        RETURN substring(current_user FROM 5)::UUID;
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION current_user_id()
RETURNS UUID LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_setting TEXT;
BEGIN
    v_setting := NULLIF(current_setting('consentledger.current_user_id', true), '');
    IF v_setting IS NOT NULL THEN
        RETURN v_setting::UUID;
    END IF;
    IF current_user ~ '^user_[0-9a-fA-F-]{36}$' THEN
        RETURN substring(current_user FROM 6)::UUID;
    END IF;
    RETURN NULL;
END;
$$;

-- Purpose declared for the current read (set by access_dataset)
CREATE OR REPLACE FUNCTION current_purpose()
RETURNS TEXT LANGUAGE sql STABLE AS $$
    SELECT NULLIF(current_setting('consentledger.current_purpose', true), '');
$$;

-- Role name of the current application user (via the roles lookup table)
CREATE OR REPLACE FUNCTION current_user_role()
RETURNS TEXT LANGUAGE sql STABLE AS $$
    SELECT r.name
    FROM users u
    JOIN roles r ON r.role_id = u.role_id
    WHERE u.user_id = current_user_id()
      AND u.is_active;
$$;

CREATE OR REPLACE FUNCTION current_user_has_role(VARIADIC p_roles TEXT[])
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT COALESCE(current_user_role() = ANY (p_roles), false);
$$;

CREATE OR REPLACE FUNCTION current_user_is_auditor()
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT current_user_has_role('auditor');
$$;

-- True if the current organization owns the dataset. SECURITY DEFINER so it
-- can be used inside other tables' policies without recursing through the
-- datasets policies.
CREATE OR REPLACE FUNCTION is_dataset_owner(p_dataset_id UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM datasets
        WHERE dataset_id = p_dataset_id
          AND owner_org_id = current_user_org_id()
    );
$$;

-- Check if a consent grant is active (not revoked, not expired)
CREATE OR REPLACE FUNCTION is_grant_active(p_grant_id UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM consent_grants
        WHERE grant_id = p_grant_id
          AND revoked_at IS NULL
          AND expires_at > now()
    );
$$;

-- Check if grantee has an active grant for a field (optionally for a purpose)
CREATE OR REPLACE FUNCTION has_field_access(
    p_grantee_org_id UUID,
    p_dataset_id UUID,
    p_field_id UUID,
    p_purpose TEXT DEFAULT NULL
)
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM consent_grants
        WHERE grantee_org_id = p_grantee_org_id
          AND dataset_id = p_dataset_id
          AND field_id = p_field_id
          AND (p_purpose IS NULL OR purpose = p_purpose)
          AND revoked_at IS NULL
          AND expires_at > now()
    );
$$;

-- Physical data table / masked view names for a dataset
CREATE OR REPLACE FUNCTION dataset_data_table_name(p_dataset_id UUID)
RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
    SELECT 'data_' || replace(p_dataset_id::TEXT, '-', '_');
$$;

CREATE OR REPLACE FUNCTION dataset_masked_view_name(p_dataset_id UUID)
RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
    SELECT dataset_data_table_name(p_dataset_id) || '_masked';
$$;

-- ============================================================================
-- ROW-LEVEL SECURITY
-- ============================================================================

ALTER TABLE datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE dataset_fields ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE anomaly_alerts ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------- datasets
-- Members of the owning organization see its datasets
CREATE POLICY pol_datasets_owner_select ON datasets
    FOR SELECT TO PUBLIC
    USING (owner_org_id = current_user_org_id());

-- Only users with the owner role register and edit datasets. There is no
-- DELETE policy: datasets referenced by the audit trail are archived instead.
CREATE POLICY pol_datasets_owner_insert ON datasets
    FOR INSERT TO PUBLIC
    WITH CHECK (owner_org_id = current_user_org_id() AND current_user_has_role('owner'));

CREATE POLICY pol_datasets_owner_update ON datasets
    FOR UPDATE TO PUBLIC
    USING (owner_org_id = current_user_org_id() AND current_user_has_role('owner'))
    WITH CHECK (owner_org_id = current_user_org_id() AND current_user_has_role('owner'));

-- Partners and owners can browse the catalogue of published datasets to
-- request access (metadata only; field values are never in this table)
CREATE POLICY pol_datasets_catalogue_select ON datasets
    FOR SELECT TO PUBLIC
    USING (status = 'published' AND current_user_has_role('partner', 'owner'));

-- Auditors can see all datasets (read-only)
CREATE POLICY pol_datasets_auditor_select ON datasets
    FOR SELECT TO PUBLIC
    USING (current_user_is_auditor());

-- ---------------------------------------------------------- dataset_fields
CREATE POLICY pol_fields_owner_select ON dataset_fields
    FOR SELECT TO PUBLIC
    USING (is_dataset_owner(dataset_id));

CREATE POLICY pol_fields_owner_insert ON dataset_fields
    FOR INSERT TO PUBLIC
    WITH CHECK (is_dataset_owner(dataset_id) AND current_user_has_role('owner'));

CREATE POLICY pol_fields_owner_update ON dataset_fields
    FOR UPDATE TO PUBLIC
    USING (is_dataset_owner(dataset_id) AND current_user_has_role('owner'))
    WITH CHECK (is_dataset_owner(dataset_id) AND current_user_has_role('owner'));

CREATE POLICY pol_fields_owner_delete ON dataset_fields
    FOR DELETE TO PUBLIC
    USING (is_dataset_owner(dataset_id) AND current_user_has_role('owner'));

-- Field *descriptions* of published datasets are visible to partners so they
-- can choose what to request (names, types, sensitivity - never values)
CREATE POLICY pol_fields_catalogue_select ON dataset_fields
    FOR SELECT TO PUBLIC
    USING (
        current_user_has_role('partner', 'owner')
        AND EXISTS (SELECT 1 FROM datasets d
                    WHERE d.dataset_id = dataset_fields.dataset_id AND d.status = 'published')
    );

CREATE POLICY pol_fields_auditor_select ON dataset_fields
    FOR SELECT TO PUBLIC
    USING (current_user_is_auditor());

-- ---------------------------------------------------------- consent_grants
CREATE POLICY pol_grants_grantor_select ON consent_grants
    FOR SELECT TO PUBLIC
    USING (grantor_org_id = current_user_org_id());

CREATE POLICY pol_grants_grantee_select ON consent_grants
    FOR SELECT TO PUBLIC
    USING (grantee_org_id = current_user_org_id());

-- Owners grant consent only on datasets their organization owns
CREATE POLICY pol_grants_grantor_insert ON consent_grants
    FOR INSERT TO PUBLIC
    WITH CHECK (
        grantor_org_id = current_user_org_id()
        AND is_dataset_owner(dataset_id)
        AND current_user_has_role('owner')
    );

-- Owners revoke / extend their grants. Policies cannot see OLD values; which
-- columns may change is enforced by trg_consent_grants_guard.
CREATE POLICY pol_grants_grantor_update ON consent_grants
    FOR UPDATE TO PUBLIC
    USING (grantor_org_id = current_user_org_id() AND current_user_has_role('owner'))
    WITH CHECK (grantor_org_id = current_user_org_id() AND current_user_has_role('owner'));

CREATE POLICY pol_grants_auditor_select ON consent_grants
    FOR SELECT TO PUBLIC
    USING (current_user_is_auditor());

-- --------------------------------------------------------- access_requests
CREATE POLICY pol_requests_grantee_select ON access_requests
    FOR SELECT TO PUBLIC
    USING (grantee_org_id = current_user_org_id());

CREATE POLICY pol_requests_grantor_select ON access_requests
    FOR SELECT TO PUBLIC
    USING (is_dataset_owner(dataset_id));

CREATE POLICY pol_requests_grantee_insert ON access_requests
    FOR INSERT TO PUBLIC
    WITH CHECK (
        grantee_org_id = current_user_org_id()
        AND status = 'pending'
        AND current_user_has_role('partner', 'owner')
    );

CREATE POLICY pol_requests_grantor_update ON access_requests
    FOR UPDATE TO PUBLIC
    USING (is_dataset_owner(dataset_id) AND current_user_has_role('owner'))
    WITH CHECK (is_dataset_owner(dataset_id) AND current_user_has_role('owner')
                AND status IN ('approved', 'denied'));

CREATE POLICY pol_requests_auditor_select ON access_requests
    FOR SELECT TO PUBLIC
    USING (current_user_is_auditor());

-- --------------------------------------------------------------- audit_log
-- Auditors see everything; an organization sees what its own users did and
-- everything that happened to its own datasets.
CREATE POLICY pol_audit_auditor_select ON audit_log
    FOR SELECT TO PUBLIC
    USING (current_user_is_auditor());

CREATE POLICY pol_audit_org_select ON audit_log
    FOR SELECT TO PUBLIC
    USING (
        user_id IN (SELECT u.user_id FROM users u WHERE u.org_id = current_user_org_id())
        OR (dataset_id IS NOT NULL AND is_dataset_owner(dataset_id))
    );

-- The application may append events (login, logout, ...) for the session user
CREATE POLICY pol_audit_self_insert ON audit_log
    FOR INSERT TO PUBLIC
    WITH CHECK (user_id = current_user_id());

-- ---------------------------------------------------------- anomaly_alerts
CREATE POLICY pol_alerts_select ON anomaly_alerts
    FOR SELECT TO PUBLIC
    USING (
        current_user_is_auditor()
        OR (dataset_id IS NOT NULL AND is_dataset_owner(dataset_id))
    );

CREATE POLICY pol_alerts_update ON anomaly_alerts
    FOR UPDATE TO PUBLIC
    USING (current_user_is_auditor()
           OR (dataset_id IS NOT NULL AND is_dataset_owner(dataset_id) AND current_user_has_role('owner')))
    WITH CHECK (current_user_is_auditor()
           OR (dataset_id IS NOT NULL AND is_dataset_owner(dataset_id) AND current_user_has_role('owner')));

-- A grant's identity (who, what, why, when) is fixed once created; only expiry
-- and revocation details may change.
CREATE OR REPLACE FUNCTION guard_consent_grant_update()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.grantor_org_id IS DISTINCT FROM OLD.grantor_org_id
       OR NEW.grantee_org_id IS DISTINCT FROM OLD.grantee_org_id
       OR NEW.dataset_id IS DISTINCT FROM OLD.dataset_id
       OR NEW.field_id IS DISTINCT FROM OLD.field_id
       OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
        RAISE EXCEPTION 'Only expiry and revocation fields of a consent grant can be changed';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_consent_grants_guard
    BEFORE UPDATE ON consent_grants
    FOR EACH ROW EXECUTE FUNCTION guard_consent_grant_update();

-- ============================================================================
-- AUDIT LOG: HASH CHAIN
-- ============================================================================

CREATE SEQUENCE audit_log_chain_seq OWNED BY audit_log.seq;

-- Timestamps are rendered in UTC so hashes do not depend on the session TimeZone
CREATE OR REPLACE FUNCTION audit_ts_text(p_ts TIMESTAMPTZ)
RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
    SELECT to_char(p_ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
$$;

-- Hash of one audit record. Every content column is covered. The input is a
-- JSON array of text values: unambiguous, and easy to reproduce outside SQL
-- (see database/scripts/verify_audit.py).
CREATE OR REPLACE FUNCTION compute_audit_hash(
    p_prev_hash BYTEA,
    p_user_id UUID,
    p_dataset_id UUID,
    p_field_id UUID,
    p_field_ids UUID[],
    p_action TEXT,
    p_rows_affected INTEGER,
    p_query_text TEXT,
    p_client_ip INET,
    p_user_agent TEXT,
    p_ts TIMESTAMPTZ
)
RETURNS BYTEA LANGUAGE sql IMMUTABLE AS $$
    SELECT digest(
        json_build_array(
            encode(p_prev_hash, 'hex'),
            p_user_id::TEXT,
            p_dataset_id::TEXT,
            p_field_id::TEXT,
            p_field_ids::TEXT,
            p_action,
            p_rows_affected::TEXT,
            p_query_text,
            p_client_ip::TEXT,
            p_user_agent,
            audit_ts_text(p_ts)
        )::TEXT,
        'sha256'
    );
$$;

-- Every insert into audit_log is chained here, whoever performs it: the
-- trigger takes a transaction-level lock (so concurrent writers cannot fork the
-- chain), assigns the next sequence number, and stores the previous row's hash.
-- Hash values supplied by the client are ignored.
CREATE OR REPLACE FUNCTION audit_log_chain()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_prev_hash BYTEA;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('consentledger.audit_log_chain'));

    SELECT row_hash INTO v_prev_hash
    FROM audit_log
    ORDER BY seq DESC
    LIMIT 1;

    IF v_prev_hash IS NULL THEN
        v_prev_hash := decode(repeat('00', 32), 'hex');  -- genesis
    END IF;

    NEW.seq := nextval('audit_log_chain_seq');
    NEW.ts := COALESCE(NEW.ts, now());
    NEW.rows_affected := COALESCE(NEW.rows_affected, 0);
    NEW.prev_hash := v_prev_hash;
    NEW.row_hash := compute_audit_hash(
        v_prev_hash, NEW.user_id, NEW.dataset_id, NEW.field_id, NEW.field_ids, NEW.action,
        NEW.rows_affected, NEW.query_text, NEW.client_ip, NEW.user_agent, NEW.ts
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_log_chain
    BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_chain();

-- Convenience wrapper for trusted server-side code (not exposed to the app role)
CREATE OR REPLACE FUNCTION append_audit_log(
    p_user_id UUID,
    p_action TEXT,
    p_dataset_id UUID DEFAULT NULL,
    p_field_id UUID DEFAULT NULL,
    p_rows_affected INTEGER DEFAULT 0,
    p_query_text TEXT DEFAULT NULL,
    p_client_ip INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL,
    p_ts TIMESTAMPTZ DEFAULT NULL,
    p_field_ids UUID[] DEFAULT NULL
)
RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_log_id UUID;
BEGIN
    INSERT INTO audit_log (user_id, dataset_id, field_id, field_ids, action, rows_affected,
                           query_text, client_ip, user_agent, ts)
    VALUES (p_user_id, p_dataset_id, p_field_id, p_field_ids, p_action, COALESCE(p_rows_affected, 0),
            p_query_text, p_client_ip, p_user_agent, COALESCE(p_ts, now()))
    RETURNING log_id INTO v_log_id;
    RETURN v_log_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION append_audit_log(UUID, TEXT, UUID, UUID, INTEGER, TEXT, INET, TEXT, TIMESTAMPTZ, UUID[]) FROM PUBLIC;

-- ============================================================================
-- AUDIT TRIGGERS ON BUSINESS TABLES
-- ============================================================================
-- These run inside the same transaction as the change they record, so a
-- consent grant/revocation and its audit entry commit (or roll back) together.

CREATE OR REPLACE FUNCTION log_data_access()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_dataset_id UUID;
    v_field_id UUID;
    v_action TEXT := lower(TG_OP);   -- insert / update
BEGIN
    IF TG_TABLE_NAME = 'datasets' THEN
        v_dataset_id := NEW.dataset_id;

    ELSIF TG_TABLE_NAME = 'consent_grants' THEN
        v_dataset_id := NEW.dataset_id;
        v_field_id := NEW.field_id;
        IF TG_OP = 'INSERT' THEN
            v_action := 'grant_create';
        ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
            v_action := CASE WHEN NEW.revocation_reason = 'Expired'
                             THEN 'grant_expire' ELSE 'grant_revoke' END;
        ELSE
            v_action := 'grant_update';
        END IF;

    ELSIF TG_TABLE_NAME = 'access_requests' THEN
        v_dataset_id := NEW.dataset_id;
        IF TG_OP = 'INSERT' THEN
            v_action := 'request_create';
        ELSIF NEW.status IS DISTINCT FROM OLD.status AND NEW.status = 'approved' THEN
            v_action := 'request_approve';
        ELSIF NEW.status IS DISTINCT FROM OLD.status AND NEW.status = 'denied' THEN
            v_action := 'request_deny';
        ELSE
            v_action := 'request_update';
        END IF;
    END IF;

    INSERT INTO audit_log (user_id, dataset_id, field_id, action, rows_affected, ts)
    VALUES (current_user_id(), v_dataset_id, v_field_id, v_action, 1, now());

    RETURN NULL; -- AFTER trigger
END;
$$;

CREATE TRIGGER trg_audit_consent_grants
    AFTER INSERT OR UPDATE ON consent_grants
    FOR EACH ROW EXECUTE FUNCTION log_data_access();

CREATE TRIGGER trg_audit_access_requests
    AFTER INSERT OR UPDATE ON access_requests
    FOR EACH ROW EXECUTE FUNCTION log_data_access();

CREATE TRIGGER trg_audit_datasets
    AFTER INSERT OR UPDATE ON datasets
    FOR EACH ROW EXECUTE FUNCTION log_data_access();

-- Statement-level audit for per-dataset data tables: one entry per statement
-- with the number of rows written (row values are never copied into the log).
CREATE OR REPLACE FUNCTION log_data_table_write()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT count(*) INTO v_count FROM changed_rows;
    IF v_count > 0 THEN
        INSERT INTO audit_log (user_id, dataset_id, action, rows_affected, ts)
        VALUES (current_user_id(),
                replace(substring(TG_TABLE_NAME FROM 6), '_', '-')::UUID,
                lower(TG_OP), v_count, now());
    END IF;
    RETURN NULL;
END;
$$;

-- ============================================================================
-- AUDIT CHAIN VERIFICATION
-- ============================================================================

-- Walks the whole chain in seq order (SECURITY DEFINER: RLS must not hide rows
-- from the walk). Returns one row per verified entry; stops at (and returns)
-- the first broken entry.
CREATE OR REPLACE FUNCTION verify_chain()
RETURNS TABLE (
    log_id UUID,
    expected_hash BYTEA,
    actual_hash BYTEA,
    is_valid BOOLEAN,
    error_msg TEXT
) LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_prev_hash BYTEA := decode(repeat('00', 32), 'hex');
    v_computed BYTEA;
    v_rec RECORD;
BEGIN
    FOR v_rec IN
        SELECT a.log_id, a.user_id, a.dataset_id, a.field_id, a.field_ids, a.action,
               a.rows_affected, a.query_text, a.client_ip, a.user_agent, a.ts,
               a.prev_hash, a.row_hash
        FROM audit_log a
        ORDER BY a.seq ASC
    LOOP
        IF v_rec.prev_hash IS DISTINCT FROM v_prev_hash THEN
            RETURN QUERY SELECT v_rec.log_id, v_prev_hash, v_rec.prev_hash, false,
                'Chain broken: prev_hash does not match previous row_hash (row altered, deleted or inserted)'::TEXT;
            RETURN;
        END IF;

        v_computed := compute_audit_hash(
            v_rec.prev_hash, v_rec.user_id, v_rec.dataset_id, v_rec.field_id, v_rec.field_ids,
            v_rec.action, v_rec.rows_affected, v_rec.query_text, v_rec.client_ip,
            v_rec.user_agent, v_rec.ts
        );
        IF v_rec.row_hash IS DISTINCT FROM v_computed THEN
            RETURN QUERY SELECT v_rec.log_id, v_computed, v_rec.row_hash, false,
                'Hash mismatch: row content was modified'::TEXT;
            RETURN;
        END IF;

        v_prev_hash := v_rec.row_hash;
        RETURN QUERY SELECT v_rec.log_id, v_computed, v_rec.row_hash, true, 'OK'::TEXT;
    END LOOP;
    RETURN;
END;
$$;

-- Backwards-compatible name
CREATE OR REPLACE FUNCTION verify_audit_chain()
RETURNS TABLE (log_id UUID, expected_hash BYTEA, actual_hash BYTEA, is_valid BOOLEAN, error_msg TEXT)
LANGUAGE sql STABLE AS $$
    SELECT * FROM verify_chain();
$$;

CREATE OR REPLACE FUNCTION is_audit_chain_valid()
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT NOT EXISTS (SELECT 1 FROM verify_chain() v WHERE NOT v.is_valid);
$$;

-- ============================================================================
-- PER-DATASET DATA TABLES, MASKED VIEWS AND THE LOGGED READ PATH
-- ============================================================================
-- Partners never touch data tables directly. The app role has no privileges
-- on them; it reads through access_dataset() (which checks consent and writes
-- an audit entry) and writes through ingest_dataset_rows().

-- Decrypt a pgcrypto-encrypted field with the key the API set for this request
CREATE OR REPLACE FUNCTION decrypt_field(p_value BYTEA)
RETURNS TEXT LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_key TEXT := NULLIF(current_setting('consentledger.encryption_key', true), '');
BEGIN
    IF p_value IS NULL THEN
        RETURN NULL;
    END IF;
    IF v_key IS NULL THEN
        RETURN '[ENCRYPTED]';
    END IF;
    RETURN pgp_sym_decrypt(p_value, v_key);
EXCEPTION WHEN OTHERS THEN
    RETURN '[DECRYPTION FAILED]';
END;
$$;

-- May the current session see this field of this dataset in clear text?
-- Owners: always. Partners: only with an active grant for the declared purpose.
CREATE OR REPLACE FUNCTION can_see_field(p_dataset_id UUID, p_field_id UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT is_dataset_owner(p_dataset_id)
        OR (current_purpose() IS NOT NULL
            AND has_field_access(current_user_org_id(), p_dataset_id, p_field_id, current_purpose()));
$$;

-- May the current session read rows of this dataset at all?
CREATE OR REPLACE FUNCTION can_read_dataset(p_dataset_id UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT is_dataset_owner(p_dataset_id)
        OR EXISTS (
            SELECT 1 FROM consent_grants cg
            WHERE cg.dataset_id = p_dataset_id
              AND cg.grantee_org_id = current_user_org_id()
              AND (current_purpose() IS NULL OR cg.purpose = current_purpose())
              AND cg.revoked_at IS NULL
              AND cg.expires_at > now()
        );
$$;

-- (Re)build the physical data table and its masked view for a dataset.
-- Internal: called by publish_dataset(); not executable by the app role.
CREATE OR REPLACE FUNCTION create_dataset_data_table(p_dataset_id UUID)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_table TEXT := dataset_data_table_name(p_dataset_id);
    v_view TEXT := dataset_masked_view_name(p_dataset_id);
    v_field RECORD;
    v_type TEXT;
    v_value TEXT;
    v_cols TEXT[] := ARRAY['m.row_id'];
BEGIN
    IF NOT EXISTS (SELECT 1 FROM datasets WHERE dataset_id = p_dataset_id) THEN
        RAISE EXCEPTION 'Dataset % not found', p_dataset_id;
    END IF;

    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I ('
        'row_id BIGSERIAL PRIMARY KEY, '
        'created_at TIMESTAMPTZ NOT NULL DEFAULT now(), '
        'updated_at TIMESTAMPTZ NOT NULL DEFAULT now())', v_table);

    FOR v_field IN
        SELECT field_id, name, data_type, sensitivity, is_encrypted
        FROM dataset_fields
        WHERE dataset_id = p_dataset_id
        ORDER BY ordinal, name
    LOOP
        v_type := CASE
            WHEN v_field.is_encrypted THEN 'BYTEA'   -- pgp_sym_encrypt ciphertext
            WHEN v_field.data_type = 'text' THEN 'TEXT'
            WHEN v_field.data_type = 'integer' THEN 'INTEGER'
            WHEN v_field.data_type = 'numeric' THEN 'NUMERIC'
            WHEN v_field.data_type = 'boolean' THEN 'BOOLEAN'
            WHEN v_field.data_type = 'date' THEN 'DATE'
            WHEN v_field.data_type = 'timestamp' THEN 'TIMESTAMPTZ'
            WHEN v_field.data_type = 'json' THEN 'JSONB'
            ELSE 'TEXT'
        END;
        EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS %I %s', v_table, v_field.name, v_type);

        v_value := CASE WHEN v_field.is_encrypted
                        THEN format('decrypt_field(m.%I)', v_field.name)
                        ELSE format('m.%I::text', v_field.name) END;
        -- Non-consented values are always replaced (even NULLs), so nothing
        -- about them leaks, not even whether they are empty.
        v_cols := v_cols || format(
            'CASE WHEN can_see_field(%L::uuid, %L::uuid) THEN %s ELSE %L END AS %I',
            p_dataset_id, v_field.field_id, v_value,
            CASE WHEN v_field.sensitivity = 'pii' THEN '[REDACTED]' ELSE '[MASKED]' END,
            v_field.name);
    END LOOP;

    -- Only the owner (definer) may touch the table directly
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', v_table);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', v_table);

    -- Masked view: one view serves every partner, because it evaluates the
    -- session's organization and purpose. Revocation applies on the next query.
    EXECUTE format('DROP VIEW IF EXISTS %I', v_view);
    EXECUTE format(
        'CREATE VIEW %I WITH (security_barrier) AS SELECT %s FROM %I m WHERE can_read_dataset(%L::uuid)',
        v_view, array_to_string(v_cols, ', '), v_table, p_dataset_id);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', v_view);

    -- Statement-level audit of writes
    EXECUTE format('DROP TRIGGER IF EXISTS trg_audit_data_ins ON %I', v_table);
    EXECUTE format('CREATE TRIGGER trg_audit_data_ins AFTER INSERT ON %I '
                   'REFERENCING NEW TABLE AS changed_rows FOR EACH STATEMENT '
                   'EXECUTE FUNCTION log_data_table_write()', v_table);
    EXECUTE format('DROP TRIGGER IF EXISTS trg_audit_data_upd ON %I', v_table);
    EXECUTE format('CREATE TRIGGER trg_audit_data_upd AFTER UPDATE ON %I '
                   'REFERENCING NEW TABLE AS changed_rows FOR EACH STATEMENT '
                   'EXECUTE FUNCTION log_data_table_write()', v_table);
    EXECUTE format('DROP TRIGGER IF EXISTS trg_audit_data_del ON %I', v_table);
    EXECUTE format('CREATE TRIGGER trg_audit_data_del AFTER DELETE ON %I '
                   'REFERENCING OLD TABLE AS changed_rows FOR EACH STATEMENT '
                   'EXECUTE FUNCTION log_data_table_write()', v_table);

    EXECUTE format('DROP TRIGGER IF EXISTS trg_data_updated_at ON %I', v_table);
    EXECUTE format('CREATE TRIGGER trg_data_updated_at BEFORE UPDATE ON %I '
                   'FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()', v_table);

    RETURN v_table;
END;
$$;

REVOKE EXECUTE ON FUNCTION create_dataset_data_table(UUID) FROM PUBLIC;

-- Publish a dataset: owner only. Creates/refreshes its data table and view.
CREATE OR REPLACE FUNCTION publish_dataset(p_dataset_id UUID)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_status TEXT;
BEGIN
    IF NOT (is_dataset_owner(p_dataset_id) AND current_user_has_role('owner')) THEN
        RAISE EXCEPTION 'Only an owner of this dataset can publish it'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT status INTO v_status FROM datasets WHERE dataset_id = p_dataset_id;
    IF v_status = 'archived' THEN
        RAISE EXCEPTION 'Archived datasets cannot be published';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM dataset_fields WHERE dataset_id = p_dataset_id) THEN
        RAISE EXCEPTION 'Add at least one field before publishing';
    END IF;

    IF v_status <> 'published' THEN
        UPDATE datasets SET status = 'published' WHERE dataset_id = p_dataset_id;
    END IF;
    RETURN create_dataset_data_table(p_dataset_id);
END;
$$;

-- Bulk-load rows (a JSON array of objects keyed by field name) into a
-- published dataset. Owner only. Encrypted fields are encrypted with the key
-- the API set for the request. Unknown keys are ignored. Returns rows loaded.
CREATE OR REPLACE FUNCTION ingest_dataset_rows(p_dataset_id UUID, p_rows JSONB)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_table TEXT := dataset_data_table_name(p_dataset_id);
    v_key TEXT := NULLIF(current_setting('consentledger.encryption_key', true), '');
    v_field RECORD;
    v_cols TEXT[] := '{}';
    v_exprs TEXT[] := '{}';
    v_count INTEGER;
BEGIN
    IF NOT (is_dataset_owner(p_dataset_id) AND current_user_has_role('owner')) THEN
        RAISE EXCEPTION 'Only an owner of this dataset can load data'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF to_regclass(v_table) IS NULL THEN
        RAISE EXCEPTION 'Publish the dataset before loading data';
    END IF;
    IF jsonb_typeof(p_rows) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'Rows must be a JSON array of objects';
    END IF;

    FOR v_field IN
        SELECT name, data_type, is_encrypted FROM dataset_fields
        WHERE dataset_id = p_dataset_id ORDER BY ordinal, name
    LOOP
        IF v_field.is_encrypted AND v_key IS NULL THEN
            RAISE EXCEPTION 'Field % is encrypted but no encryption key is configured', v_field.name;
        END IF;
        v_cols := v_cols || quote_ident(v_field.name);
        v_exprs := v_exprs || CASE
            WHEN v_field.is_encrypted THEN
                format('CASE WHEN r.doc->>%L IS NULL THEN NULL ELSE pgp_sym_encrypt(r.doc->>%L, $1) END',
                       v_field.name, v_field.name)
            WHEN v_field.data_type = 'json' THEN format('r.doc->%L', v_field.name)
            ELSE format('NULLIF(r.doc->>%L, %L)::%s', v_field.name, '',
                CASE v_field.data_type
                    WHEN 'integer' THEN 'INTEGER' WHEN 'numeric' THEN 'NUMERIC'
                    WHEN 'boolean' THEN 'BOOLEAN' WHEN 'date' THEN 'DATE'
                    WHEN 'timestamp' THEN 'TIMESTAMPTZ' ELSE 'TEXT' END)
        END;
    END LOOP;

    EXECUTE format('INSERT INTO %I (%s) SELECT %s FROM jsonb_array_elements($2) AS r(doc)',
                   v_table, array_to_string(v_cols, ', '), array_to_string(v_exprs, ', '))
        USING v_key, p_rows;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

-- THE read path for dataset rows ("check consent, then log"). Owners read
-- everything; partners must state a purpose and only see fields granted for
-- that purpose (others come back masked). Every call writes an audit entry
-- with the number of rows returned and the fields returned in clear text.
CREATE OR REPLACE FUNCTION access_dataset(
    p_dataset_id UUID,
    p_purpose TEXT DEFAULT NULL,
    p_limit INTEGER DEFAULT 100,
    p_offset INTEGER DEFAULT 0
)
RETURNS SETOF JSONB LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_org UUID := current_user_org_id();
    v_owner BOOLEAN;
    v_fields UUID[];
    v_count INTEGER;
    v_prev_purpose TEXT := current_setting('consentledger.current_purpose', true);
    v_limit INTEGER := LEAST(GREATEST(COALESCE(p_limit, 100), 0), 1000);
    v_offset INTEGER := GREATEST(COALESCE(p_offset, 0), 0);
BEGIN
    IF v_org IS NULL OR current_user_id() IS NULL THEN
        RAISE EXCEPTION 'No user context for this request' USING ERRCODE = 'insufficient_privilege';
    END IF;

    SELECT owner_org_id = v_org INTO v_owner FROM datasets WHERE dataset_id = p_dataset_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Dataset not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF to_regclass(dataset_masked_view_name(p_dataset_id)) IS NULL THEN
        RAISE EXCEPTION 'Dataset has no data yet (publish it first)';
    END IF;

    IF v_owner THEN
        SELECT array_agg(field_id ORDER BY ordinal) INTO v_fields
        FROM dataset_fields WHERE dataset_id = p_dataset_id;
    ELSE
        IF p_purpose IS NULL OR trim(p_purpose) = '' THEN
            RAISE EXCEPTION 'A purpose is required to read a shared dataset'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        SELECT array_agg(cg.field_id ORDER BY df.ordinal) INTO v_fields
        FROM consent_grants cg JOIN dataset_fields df ON df.field_id = cg.field_id
        WHERE cg.grantee_org_id = v_org AND cg.dataset_id = p_dataset_id
          AND cg.purpose = p_purpose AND cg.revoked_at IS NULL AND cg.expires_at > now();
        IF v_fields IS NULL THEN
            RAISE EXCEPTION 'No active consent for this dataset and purpose'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;

    PERFORM set_config('consentledger.current_purpose', COALESCE(p_purpose, ''), true);
    RETURN QUERY EXECUTE format(
        'SELECT to_jsonb(m) FROM %I m ORDER BY m.row_id LIMIT %s OFFSET %s',
        dataset_masked_view_name(p_dataset_id), v_limit, v_offset);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    PERFORM set_config('consentledger.current_purpose', COALESCE(v_prev_purpose, ''), true);

    INSERT INTO audit_log (user_id, dataset_id, field_ids, action, rows_affected, query_text)
    VALUES (current_user_id(), p_dataset_id, v_fields, 'select', v_count,
            format('access_dataset(purpose=%s, limit=%s, offset=%s)',
                   COALESCE(p_purpose, '-'), v_limit, v_offset));
    RETURN;
END;
$$;

-- Row count for pagination (no values are returned, so it is not audited)
CREATE OR REPLACE FUNCTION dataset_row_count(p_dataset_id UUID)
RETURNS BIGINT LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_count BIGINT;
BEGIN
    IF NOT can_read_dataset(p_dataset_id) THEN
        RAISE EXCEPTION 'No access to this dataset' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF to_regclass(dataset_data_table_name(p_dataset_id)) IS NULL THEN
        RETURN 0;
    END IF;
    EXECUTE format('SELECT count(*) FROM %I', dataset_data_table_name(p_dataset_id)) INTO v_count;
    RETURN v_count;
END;
$$;

-- Catalog view of what the current organization has been granted
CREATE OR REPLACE VIEW partner_dataset_view AS
SELECT
    d.dataset_id,
    d.title,
    d.description,
    d.category,
    cg.grant_id,
    cg.field_id,
    df.name AS field_name,
    df.data_type,
    df.sensitivity,
    cg.purpose,
    cg.granted_at,
    cg.expires_at,
    cg.revoked_at
FROM datasets d
JOIN consent_grants cg ON cg.dataset_id = d.dataset_id
JOIN dataset_fields df ON df.field_id = cg.field_id
WHERE cg.grantee_org_id = current_user_org_id()
  AND cg.revoked_at IS NULL
  AND cg.expires_at > now()
  AND d.status = 'published';

-- ============================================================================
-- STORED PROCEDURES (consent workflow)
-- ============================================================================

-- The acting user passed to a procedure must be the session user (when the
-- API has set one), so one user cannot act in another's name. Returns the
-- actor's organization.
CREATE OR REPLACE FUNCTION assert_actor(p_user_id UUID, VARIADIC p_roles TEXT[])
RETURNS UUID LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_org UUID;
    v_role TEXT;
BEGIN
    IF current_user_id() IS NOT NULL AND current_user_id() IS DISTINCT FROM p_user_id THEN
        RAISE EXCEPTION 'Acting user does not match the session user'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT u.org_id, r.name INTO v_org, v_role
    FROM users u JOIN roles r ON r.role_id = u.role_id
    WHERE u.user_id = p_user_id AND u.is_active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'User not found or inactive' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT (v_role = ANY (p_roles)) THEN
        RAISE EXCEPTION 'Role % may not perform this action', v_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN v_org;
END;
$$;

-- Make p_user_id the acting user for audit triggers fired inside a procedure.
-- Returns the previous value so the caller can restore it afterwards.
CREATE OR REPLACE FUNCTION set_acting_user(p_user_id UUID)
RETURNS TEXT LANGUAGE plpgsql AS $$
DECLARE
    v_prev TEXT := current_setting('consentledger.current_user_id', true);
BEGIN
    PERFORM set_config('consentledger.current_user_id', p_user_id::TEXT, true);
    RETURN COALESCE(v_prev, '');
END;
$$;

CREATE OR REPLACE FUNCTION restore_acting_user(p_prev TEXT)
RETURNS VOID LANGUAGE sql AS $$
    SELECT set_config('consentledger.current_user_id', COALESCE(p_prev, ''), true);
$$;

-- Partner asks a data owner for access to some fields for a purpose
CREATE OR REPLACE PROCEDURE request_access(
    p_user_id UUID,
    p_dataset_id UUID,
    p_field_ids UUID[],
    p_purpose TEXT,
    p_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_request_id UUID;
    v_grantee_org_id UUID;
    v_prev_user TEXT;
BEGIN
    v_grantee_org_id := assert_actor(p_user_id, 'partner', 'owner');

    IF NOT EXISTS (SELECT 1 FROM datasets WHERE dataset_id = p_dataset_id AND status = 'published') THEN
        RAISE EXCEPTION 'Dataset not found or not published';
    END IF;
    IF EXISTS (SELECT 1 FROM datasets WHERE dataset_id = p_dataset_id AND owner_org_id = v_grantee_org_id) THEN
        RAISE EXCEPTION 'Organizations cannot request access to their own datasets';
    END IF;
    IF p_field_ids IS NULL OR cardinality(p_field_ids) = 0 THEN
        RAISE EXCEPTION 'At least one field must be requested';
    END IF;
    IF EXISTS (
        SELECT fid FROM unnest(p_field_ids) AS fid
        EXCEPT
        SELECT field_id FROM dataset_fields WHERE dataset_id = p_dataset_id
    ) THEN
        RAISE EXCEPTION 'One or more fields do not belong to this dataset';
    END IF;
    IF p_purpose IS NULL OR trim(p_purpose) = '' THEN
        RAISE EXCEPTION 'A purpose is required';
    END IF;
    IF p_expires_at <= now() THEN
        RAISE EXCEPTION 'Requested expiry must be in the future';
    END IF;

    v_prev_user := set_acting_user(p_user_id);

    INSERT INTO access_requests (grantee_org_id, requested_by, dataset_id, field_ids, purpose, requested_expires_at)
    VALUES (v_grantee_org_id, p_user_id, p_dataset_id, p_field_ids, trim(p_purpose), p_expires_at)
    RETURNING request_id INTO v_request_id;

    PERFORM restore_acting_user(v_prev_user);
    RAISE NOTICE 'Access request % created', v_request_id;
END;
$$;

-- Owner approves a request, optionally narrowing fields/expiry; creates grants
CREATE OR REPLACE PROCEDURE approve_access_request(
    p_user_id UUID,
    p_request_id UUID,
    p_approved_field_ids UUID[],
    p_purpose TEXT,
    p_expires_at TIMESTAMPTZ,
    p_note TEXT DEFAULT NULL
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_request access_requests%ROWTYPE;
    v_grantor_org_id UUID;
    v_actor_org UUID;
    v_field_id UUID;
    v_prev_user TEXT;
BEGIN
    v_actor_org := assert_actor(p_user_id, 'owner');

    SELECT * INTO v_request FROM access_requests WHERE request_id = p_request_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Request not found';
    END IF;

    SELECT owner_org_id INTO v_grantor_org_id FROM datasets WHERE dataset_id = v_request.dataset_id;
    IF v_grantor_org_id IS DISTINCT FROM v_actor_org THEN
        RAISE EXCEPTION 'Not authorized to approve this request' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF v_request.status <> 'pending' THEN
        RAISE EXCEPTION 'Request already decided';
    END IF;
    IF p_approved_field_ids IS NULL OR cardinality(p_approved_field_ids) = 0 THEN
        RAISE EXCEPTION 'At least one field must be approved (use deny_access_request to deny)';
    END IF;
    IF NOT (p_approved_field_ids <@ v_request.field_ids) THEN
        RAISE EXCEPTION 'Approved fields must be a subset of the requested fields';
    END IF;
    IF p_expires_at <= now() THEN
        RAISE EXCEPTION 'Grant expiry must be in the future';
    END IF;

    v_prev_user := set_acting_user(p_user_id);

    FOREACH v_field_id IN ARRAY p_approved_field_ids
    LOOP
        INSERT INTO consent_grants (grantor_org_id, grantee_org_id, dataset_id, field_id, purpose, expires_at)
        VALUES (v_grantor_org_id, v_request.grantee_org_id, v_request.dataset_id, v_field_id,
                COALESCE(NULLIF(trim(p_purpose), ''), v_request.purpose), p_expires_at)
        ON CONFLICT (grantee_org_id, dataset_id, field_id, purpose) DO UPDATE SET
            expires_at = GREATEST(consent_grants.expires_at, EXCLUDED.expires_at),
            revoked_at = NULL,
            revoked_by = NULL,
            revocation_reason = NULL;
    END LOOP;

    UPDATE access_requests
    SET status = 'approved', decided_by = p_user_id, decided_at = now(), decision_note = p_note
    WHERE request_id = p_request_id;

    PERFORM restore_acting_user(v_prev_user);
    RAISE NOTICE 'Request % approved with % grants', p_request_id, cardinality(p_approved_field_ids);
END;
$$;

CREATE OR REPLACE PROCEDURE deny_access_request(
    p_user_id UUID,
    p_request_id UUID,
    p_note TEXT DEFAULT NULL
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_request access_requests%ROWTYPE;
    v_actor_org UUID;
    v_prev_user TEXT;
BEGIN
    v_actor_org := assert_actor(p_user_id, 'owner');

    SELECT * INTO v_request FROM access_requests WHERE request_id = p_request_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Request not found';
    END IF;
    IF (SELECT owner_org_id FROM datasets WHERE dataset_id = v_request.dataset_id) IS DISTINCT FROM v_actor_org THEN
        RAISE EXCEPTION 'Not authorized to deny this request' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF v_request.status <> 'pending' THEN
        RAISE EXCEPTION 'Request already decided';
    END IF;

    v_prev_user := set_acting_user(p_user_id);

    UPDATE access_requests
    SET status = 'denied', decided_by = p_user_id, decided_at = now(), decision_note = p_note
    WHERE request_id = p_request_id;

    PERFORM restore_acting_user(v_prev_user);
    RAISE NOTICE 'Request % denied', p_request_id;
END;
$$;

-- Revoke a grant instantly: the next read through access_dataset is blocked
CREATE OR REPLACE PROCEDURE revoke_grant(
    p_user_id UUID,
    p_grant_id UUID,
    p_reason TEXT DEFAULT NULL
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_grant consent_grants%ROWTYPE;
    v_actor_org UUID;
    v_prev_user TEXT;
BEGIN
    v_actor_org := assert_actor(p_user_id, 'owner');

    SELECT * INTO v_grant FROM consent_grants WHERE grant_id = p_grant_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Grant not found';
    END IF;
    IF v_grant.grantor_org_id IS DISTINCT FROM v_actor_org THEN
        RAISE EXCEPTION 'Not authorized to revoke this grant' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF v_grant.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'Grant already revoked';
    END IF;

    v_prev_user := set_acting_user(p_user_id);

    UPDATE consent_grants
    SET revoked_at = now(), revoked_by = p_user_id, revocation_reason = p_reason
    WHERE grant_id = p_grant_id;

    PERFORM restore_acting_user(v_prev_user);
    RAISE NOTICE 'Grant % revoked', p_grant_id;
END;
$$;

-- Expire old grants and stale pending requests (run as a scheduled job)
CREATE OR REPLACE PROCEDURE expire_grants()
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_grants INTEGER;
    v_requests INTEGER;
BEGIN
    UPDATE consent_grants
    SET revoked_at = now(), revocation_reason = 'Expired'
    WHERE revoked_at IS NULL
      AND expires_at <= now();
    GET DIAGNOSTICS v_grants = ROW_COUNT;

    UPDATE access_requests
    SET status = 'expired'
    WHERE status = 'pending'
      AND requested_expires_at <= now();
    GET DIAGNOSTICS v_requests = ROW_COUNT;

    RAISE NOTICE 'Expired % grants and % pending requests', v_grants, v_requests;
END;
$$;

-- ============================================================================
-- FEATURE VIEWS FOR THE ANOMALY DETECTOR (window functions)
-- ============================================================================
-- Hours are taken in UTC so features do not depend on the session TimeZone.
-- Off-hours = outside 08:00-18:59 UTC.

-- One row per read, with per-user context computed by window functions
CREATE OR REPLACE VIEW access_event_features AS
SELECT
    a.log_id,
    a.seq,
    a.user_id,
    u.org_id,
    a.dataset_id,
    a.ts,
    a.rows_affected,
    COALESCE(cardinality(a.field_ids), 0) AS fields_touched,
    (EXTRACT(hour FROM a.ts AT TIME ZONE 'UTC') NOT BETWEEN 8 AND 18) AS is_off_hours,
    ROW_NUMBER() OVER w_seq AS user_event_no,
    EXTRACT(EPOCH FROM a.ts - LAG(a.ts) OVER w_seq) AS seconds_since_prev,
    COUNT(*) OVER w_hour AS queries_last_hour,
    SUM(a.rows_affected) OVER w_hour AS rows_last_hour,
    AVG(a.rows_affected) OVER w_user AS user_avg_rows,
    a.rows_affected / NULLIF(AVG(a.rows_affected) OVER w_user, 0) AS rows_vs_user_avg,
    AVG((EXTRACT(hour FROM a.ts AT TIME ZONE 'UTC') NOT BETWEEN 8 AND 18)::INT) OVER w_user
        AS user_off_hours_share,
    PERCENT_RANK() OVER (ORDER BY a.rows_affected) AS rows_percentile
FROM audit_log a
JOIN users u ON u.user_id = a.user_id
WHERE a.action = 'select'
WINDOW
    w_seq  AS (PARTITION BY a.user_id ORDER BY a.ts, a.seq),
    w_hour AS (PARTITION BY a.user_id ORDER BY a.ts
               RANGE BETWEEN INTERVAL '1 hour' PRECEDING AND CURRENT ROW),
    w_user AS (PARTITION BY a.user_id);

-- One row per user per hour of activity, plus rolling per-user baselines
CREATE OR REPLACE VIEW access_features_hourly AS
WITH hourly AS (
    SELECT
        a.user_id,
        date_trunc('hour', a.ts AT TIME ZONE 'UTC') AS hour_bucket,
        COUNT(*) AS query_count,
        COUNT(DISTINCT a.dataset_id) AS distinct_datasets,
        COALESCE(SUM(a.rows_affected) FILTER (WHERE a.action = 'select'), 0) AS total_rows_read,
        COALESCE(MAX(a.rows_affected) FILTER (WHERE a.action = 'select'), 0) AS max_rows_per_query,
        COUNT(*) FILTER (WHERE a.action = 'select') AS select_count,
        COUNT(*) FILTER (WHERE a.action IN ('insert', 'update', 'delete')) AS write_count,
        COUNT(*) FILTER (WHERE EXTRACT(hour FROM a.ts AT TIME ZONE 'UTC') NOT BETWEEN 8 AND 18)
            AS off_hours_count
    FROM audit_log a
    WHERE a.action IN ('select', 'insert', 'update', 'delete')
      AND a.user_id IS NOT NULL
    GROUP BY a.user_id, date_trunc('hour', a.ts AT TIME ZONE 'UTC')
),
fields AS (
    SELECT a.user_id,
           date_trunc('hour', a.ts AT TIME ZONE 'UTC') AS hour_bucket,
           COUNT(DISTINCT f.field_id) AS distinct_fields
    FROM audit_log a
    CROSS JOIN LATERAL unnest(a.field_ids) AS f(field_id)
    WHERE a.action = 'select' AND a.user_id IS NOT NULL
    GROUP BY 1, 2
)
SELECT
    h.user_id,
    h.hour_bucket,
    h.query_count,
    h.distinct_datasets,
    COALESCE(f.distinct_fields, 0) AS distinct_fields,
    h.total_rows_read,
    h.select_count,
    h.write_count,
    h.off_hours_count,
    h.max_rows_per_query,
    ROUND(h.off_hours_count::NUMERIC / h.query_count, 4) AS off_hours_share,
    ROUND(h.total_rows_read::NUMERIC / NULLIF(h.select_count, 0), 2) AS rows_per_request,
    -- rolling baseline over the user's previous 24 active hours
    ROUND(AVG(h.query_count) OVER w_prev24, 2) AS baseline_query_count,
    ROUND(AVG(h.total_rows_read) OVER w_prev24, 2) AS baseline_rows_read,
    ROUND(h.total_rows_read / NULLIF(AVG(h.total_rows_read) OVER w_prev24, 0), 2) AS rows_vs_baseline,
    EXTRACT(EPOCH FROM h.hour_bucket - LAG(h.hour_bucket) OVER w_user) / 3600 AS hours_since_prev_active,
    RANK() OVER (PARTITION BY h.hour_bucket ORDER BY h.total_rows_read DESC) AS rows_rank_in_hour
FROM hourly h
LEFT JOIN fields f ON f.user_id = h.user_id AND f.hour_bucket = h.hour_bucket
WINDOW
    w_user   AS (PARTITION BY h.user_id ORDER BY h.hour_bucket),
    w_prev24 AS (PARTITION BY h.user_id ORDER BY h.hour_bucket
                 ROWS BETWEEN 24 PRECEDING AND 1 PRECEDING);

-- Grant-to-first-use latency (how quickly a partner used a new grant)
CREATE OR REPLACE VIEW grant_usage_latency AS
WITH uses AS (
    SELECT
        cg.grant_id,
        al.user_id,
        al.ts,
        ROW_NUMBER() OVER (PARTITION BY cg.grant_id ORDER BY al.ts, al.seq) AS use_no
    FROM consent_grants cg
    JOIN users u ON u.org_id = cg.grantee_org_id
    JOIN audit_log al
      ON al.user_id = u.user_id
     AND al.dataset_id = cg.dataset_id
     AND al.action = 'select'
     AND al.ts >= cg.granted_at
     AND cg.field_id = ANY (al.field_ids)
)
SELECT
    cg.grant_id,
    cg.grantee_org_id,
    cg.dataset_id,
    cg.field_id,
    cg.granted_at AS grant_time,
    us.user_id AS first_user_id,
    us.ts AS first_access_time,
    EXTRACT(EPOCH FROM (us.ts - cg.granted_at)) / 3600 AS hours_to_first_use
FROM consent_grants cg
LEFT JOIN uses us ON us.grant_id = cg.grant_id AND us.use_no = 1
WHERE cg.revoked_at IS NULL;

-- ============================================================================
-- APPLICATION ROLE
-- ============================================================================
-- RLS is bypassed by superusers and table owners, so the API runs as this role
-- (`SET LOCAL ROLE consentledger_app` per request, or a LOGIN role that is a
-- member of it). It cannot touch data_* tables or the feature views directly.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentledger_app') THEN
        CREATE ROLE consentledger_app NOLOGIN;
    END IF;
END;
$$;

GRANT USAGE ON SCHEMA public TO consentledger_app;
GRANT SELECT ON roles TO consentledger_app;
GRANT SELECT, INSERT, UPDATE ON organizations, users TO consentledger_app;
GRANT SELECT, INSERT, UPDATE ON datasets TO consentledger_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON dataset_fields TO consentledger_app;
GRANT SELECT, INSERT, UPDATE ON consent_grants, access_requests TO consentledger_app;
GRANT SELECT, UPDATE ON anomaly_alerts TO consentledger_app;
GRANT SELECT, INSERT ON audit_log TO consentledger_app;
GRANT SELECT ON partner_dataset_view TO consentledger_app;
REVOKE ALL ON access_event_features, access_features_hourly, grant_usage_latency FROM PUBLIC;
