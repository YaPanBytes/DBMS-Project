-- ConsentLedger: performance and correctness fixes from the code review
-- Applied by Alembic revision 0004 (database/alembic_env/versions/0004_performance_and_fixes.py)
--
-- 1. Masked reads page first, then mask/decrypt only the returned rows, with
--    each field's permission decided once per query (was: every cell of every
--    row of the table, before LIMIT).
-- 2. The masked views evaluate their permission checks once per query
--    (uncorrelated scalar subqueries become InitPlans).
-- 3. RLS policies call their helper functions once per query instead of once
--    per row, and ownership checks use a precomputed array.
-- 4. New ciphertext uses salted AES-256 S2K (the key is a long random secret,
--    so iterated key stretching only added cost). Old ciphertext still decrypts.
-- 5. verify_chain_summary(): one row instead of one row per audit entry.
-- 6. request_access returns the new request id (INOUT parameter).
-- 7. Admins can read anomaly alerts (they run the detector) and the metadata
--    of the datasets those alerts are about.

-- ============================================================================
-- HELPERS
-- ============================================================================

-- Datasets owned by the current organization, computed once per query when
-- used as  dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[])
CREATE OR REPLACE FUNCTION current_org_dataset_ids()
RETURNS UUID[] LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT COALESCE(array_agg(dataset_id), '{}')
    FROM datasets
    WHERE owner_org_id = current_user_org_id();
$$;

-- ============================================================================
-- RLS POLICIES (same rules as 002, cheaper evaluation)
-- ============================================================================

DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT policyname, tablename FROM pg_policies
             WHERE schemaname = 'public'
               AND tablename IN ('datasets', 'dataset_fields', 'consent_grants',
                                 'access_requests', 'audit_log', 'anomaly_alerts')
    LOOP
        EXECUTE format('DROP POLICY %I ON %I', r.policyname, r.tablename);
    END LOOP;
END;
$$;

-- ---------------------------------------------------------------- datasets
CREATE POLICY pol_datasets_owner_select ON datasets
    FOR SELECT TO PUBLIC
    USING (owner_org_id = (SELECT current_user_org_id()));

CREATE POLICY pol_datasets_owner_insert ON datasets
    FOR INSERT TO PUBLIC
    WITH CHECK (owner_org_id = (SELECT current_user_org_id())
                AND (SELECT current_user_has_role('owner')));

CREATE POLICY pol_datasets_owner_update ON datasets
    FOR UPDATE TO PUBLIC
    USING (owner_org_id = (SELECT current_user_org_id()) AND (SELECT current_user_has_role('owner')))
    WITH CHECK (owner_org_id = (SELECT current_user_org_id()) AND (SELECT current_user_has_role('owner')));

CREATE POLICY pol_datasets_catalogue_select ON datasets
    FOR SELECT TO PUBLIC
    USING (status = 'published' AND (SELECT current_user_has_role('partner', 'owner')));

-- Auditors, and admins (who run the anomaly detector and read its alerts),
-- see dataset metadata. Values stay behind access_dataset().
CREATE POLICY pol_datasets_auditor_select ON datasets
    FOR SELECT TO PUBLIC
    USING ((SELECT current_user_has_role('auditor', 'admin')));

-- ---------------------------------------------------------- dataset_fields
CREATE POLICY pol_fields_owner_select ON dataset_fields
    FOR SELECT TO PUBLIC
    USING (dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[]));

CREATE POLICY pol_fields_owner_insert ON dataset_fields
    FOR INSERT TO PUBLIC
    WITH CHECK (dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[])
                AND (SELECT current_user_has_role('owner')));

CREATE POLICY pol_fields_owner_update ON dataset_fields
    FOR UPDATE TO PUBLIC
    USING (dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[]) AND (SELECT current_user_has_role('owner')))
    WITH CHECK (dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[]) AND (SELECT current_user_has_role('owner')));

CREATE POLICY pol_fields_owner_delete ON dataset_fields
    FOR DELETE TO PUBLIC
    USING (dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[]) AND (SELECT current_user_has_role('owner')));

CREATE POLICY pol_fields_catalogue_select ON dataset_fields
    FOR SELECT TO PUBLIC
    USING (
        (SELECT current_user_has_role('partner', 'owner'))
        AND EXISTS (SELECT 1 FROM datasets d
                    WHERE d.dataset_id = dataset_fields.dataset_id AND d.status = 'published')
    );

CREATE POLICY pol_fields_auditor_select ON dataset_fields
    FOR SELECT TO PUBLIC
    USING ((SELECT current_user_is_auditor()));

-- ---------------------------------------------------------- consent_grants
CREATE POLICY pol_grants_grantor_select ON consent_grants
    FOR SELECT TO PUBLIC
    USING (grantor_org_id = (SELECT current_user_org_id()));

CREATE POLICY pol_grants_grantee_select ON consent_grants
    FOR SELECT TO PUBLIC
    USING (grantee_org_id = (SELECT current_user_org_id()));

CREATE POLICY pol_grants_grantor_insert ON consent_grants
    FOR INSERT TO PUBLIC
    WITH CHECK (
        grantor_org_id = (SELECT current_user_org_id())
        AND dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[])
        AND (SELECT current_user_has_role('owner'))
    );

CREATE POLICY pol_grants_grantor_update ON consent_grants
    FOR UPDATE TO PUBLIC
    USING (grantor_org_id = (SELECT current_user_org_id()) AND (SELECT current_user_has_role('owner')))
    WITH CHECK (grantor_org_id = (SELECT current_user_org_id()) AND (SELECT current_user_has_role('owner')));

CREATE POLICY pol_grants_auditor_select ON consent_grants
    FOR SELECT TO PUBLIC
    USING ((SELECT current_user_is_auditor()));

-- --------------------------------------------------------- access_requests
CREATE POLICY pol_requests_grantee_select ON access_requests
    FOR SELECT TO PUBLIC
    USING (grantee_org_id = (SELECT current_user_org_id()));

CREATE POLICY pol_requests_grantor_select ON access_requests
    FOR SELECT TO PUBLIC
    USING (dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[]));

CREATE POLICY pol_requests_grantee_insert ON access_requests
    FOR INSERT TO PUBLIC
    WITH CHECK (
        grantee_org_id = (SELECT current_user_org_id())
        AND status = 'pending'
        AND (SELECT current_user_has_role('partner', 'owner'))
    );

CREATE POLICY pol_requests_grantor_update ON access_requests
    FOR UPDATE TO PUBLIC
    USING (dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[]) AND (SELECT current_user_has_role('owner')))
    WITH CHECK (dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[]) AND (SELECT current_user_has_role('owner'))
                AND status IN ('approved', 'denied'));

CREATE POLICY pol_requests_auditor_select ON access_requests
    FOR SELECT TO PUBLIC
    USING ((SELECT current_user_is_auditor()));

-- --------------------------------------------------------------- audit_log
CREATE POLICY pol_audit_auditor_select ON audit_log
    FOR SELECT TO PUBLIC
    USING ((SELECT current_user_is_auditor()));

CREATE POLICY pol_audit_org_select ON audit_log
    FOR SELECT TO PUBLIC
    USING (
        user_id IN (SELECT u.user_id FROM users u WHERE u.org_id = (SELECT current_user_org_id()))
        OR dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[])
    );

CREATE POLICY pol_audit_self_insert ON audit_log
    FOR INSERT TO PUBLIC
    WITH CHECK (user_id = (SELECT current_user_id()));

-- ---------------------------------------------------------- anomaly_alerts
CREATE POLICY pol_alerts_select ON anomaly_alerts
    FOR SELECT TO PUBLIC
    USING (
        (SELECT current_user_has_role('auditor', 'admin'))
        OR dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[])
    );

CREATE POLICY pol_alerts_update ON anomaly_alerts
    FOR UPDATE TO PUBLIC
    USING ((SELECT current_user_is_auditor())
           OR (dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[]) AND (SELECT current_user_has_role('owner'))))
    WITH CHECK ((SELECT current_user_is_auditor())
           OR (dataset_id = ANY ((SELECT current_org_dataset_ids())::uuid[]) AND (SELECT current_user_has_role('owner'))));

-- ============================================================================
-- DATA TABLES, MASKED VIEWS, READ AND WRITE PATHS
-- ============================================================================

-- Masked view: permission checks are uncorrelated scalar subqueries, so
-- PostgreSQL evaluates each once per query (InitPlan), not once per cell.
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
            WHEN v_field.is_encrypted THEN 'BYTEA'
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
        v_cols := v_cols || format(
            'CASE WHEN (SELECT can_see_field(%L::uuid, %L::uuid)) THEN %s ELSE %L END AS %I',
            p_dataset_id, v_field.field_id, v_value,
            CASE WHEN v_field.sensitivity = 'pii' THEN '[REDACTED]' ELSE '[MASKED]' END,
            v_field.name);
    END LOOP;

    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', v_table);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', v_table);

    EXECUTE format('DROP VIEW IF EXISTS %I', v_view);
    EXECUTE format(
        'CREATE VIEW %I WITH (security_barrier) AS SELECT %s FROM %I m '
        'WHERE (SELECT can_read_dataset(%L::uuid))',
        v_view, array_to_string(v_cols, ', '), v_table, p_dataset_id);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', v_view);

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

-- Salted AES-256 S2K for new ciphertext (pgp_sym_decrypt reads the mode from
-- each message, so older values keep decrypting).
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
                format('CASE WHEN r.doc->>%L IS NULL THEN NULL '
                       'ELSE pgp_sym_encrypt(r.doc->>%L, $1, %L) END',
                       v_field.name, v_field.name, 'cipher-algo=aes256, s2k-mode=1')
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

-- The read path. Same rules as before, but: visibility is decided once per
-- field, the page (ORDER BY row_id LIMIT/OFFSET) is taken from the base table
-- first, and only the returned rows are masked or decrypted.
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
    v_field RECORD;
    v_cols TEXT[] := ARRAY['p.row_id'];
    v_count INTEGER;
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
    IF to_regclass(dataset_data_table_name(p_dataset_id)) IS NULL THEN
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

    -- One projection expression per field: the value (decrypted if needed) for
    -- visible fields, a constant mask for the rest.
    -- (A field added after the last publish has no column yet: it reads as NULL.)
    FOR v_field IN
        SELECT df.field_id, df.name, df.sensitivity, df.is_encrypted,
               EXISTS (SELECT 1 FROM pg_attribute a
                       WHERE a.attrelid = to_regclass(dataset_data_table_name(p_dataset_id))
                         AND a.attname = df.name AND a.attnum > 0 AND NOT a.attisdropped) AS has_col
        FROM dataset_fields df WHERE df.dataset_id = p_dataset_id
        ORDER BY df.ordinal, df.name
    LOOP
        v_cols := v_cols || CASE
            WHEN v_field.field_id = ANY (v_fields) AND NOT v_field.has_col THEN
                format('NULL::text AS %I', v_field.name)
            WHEN v_field.field_id = ANY (v_fields) THEN
                CASE WHEN v_field.is_encrypted
                     THEN format('decrypt_field(p.%I) AS %I', v_field.name, v_field.name)
                     ELSE format('p.%I::text AS %I', v_field.name, v_field.name) END
            ELSE format('%L::text AS %I',
                        CASE WHEN v_field.sensitivity = 'pii' THEN '[REDACTED]' ELSE '[MASKED]' END,
                        v_field.name)
        END;
    END LOOP;

    RETURN QUERY EXECUTE format(
        'SELECT to_jsonb(m) FROM (SELECT %s FROM (SELECT * FROM %I ORDER BY row_id LIMIT %s OFFSET %s) p) m',
        array_to_string(v_cols, ', '), dataset_data_table_name(p_dataset_id), v_limit, v_offset);
    GET DIAGNOSTICS v_count = ROW_COUNT;

    INSERT INTO audit_log (user_id, dataset_id, field_ids, action, rows_affected, query_text)
    VALUES (current_user_id(), p_dataset_id, v_fields, 'select', v_count,
            format('access_dataset(purpose=%s, limit=%s, offset=%s)',
                   COALESCE(p_purpose, '-'), v_limit, v_offset));
    RETURN;
END;
$$;

-- Rebuild the masked views of existing datasets with the cheaper definition
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT dataset_id FROM datasets
             WHERE to_regclass(dataset_data_table_name(dataset_id)) IS NOT NULL
    LOOP
        PERFORM create_dataset_data_table(r.dataset_id);
    END LOOP;
END;
$$;

-- ============================================================================
-- AUDIT CHAIN SUMMARY
-- ============================================================================

-- Same walk as verify_chain(), returning a single summary row.
CREATE OR REPLACE FUNCTION verify_chain_summary()
RETURNS TABLE (
    is_valid BOOLEAN,
    total_rows BIGINT,
    verified_rows BIGINT,
    first_bad_log_id UUID,
    error_msg TEXT
) LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_prev_hash BYTEA := decode(repeat('00', 32), 'hex');
    v_ok BIGINT := 0;
    v_rec RECORD;
BEGIN
    total_rows := (SELECT count(*) FROM audit_log);
    FOR v_rec IN
        SELECT a.log_id, a.user_id, a.dataset_id, a.field_id, a.field_ids, a.action,
               a.rows_affected, a.query_text, a.client_ip, a.user_agent, a.ts,
               a.prev_hash, a.row_hash
        FROM audit_log a
        ORDER BY a.seq ASC
    LOOP
        IF v_rec.prev_hash IS DISTINCT FROM v_prev_hash THEN
            RETURN QUERY SELECT false, total_rows, v_ok, v_rec.log_id,
                'Chain broken: prev_hash does not match previous row_hash (row altered, deleted or inserted)'::TEXT;
            RETURN;
        END IF;
        IF v_rec.row_hash IS DISTINCT FROM compute_audit_hash(
                v_rec.prev_hash, v_rec.user_id, v_rec.dataset_id, v_rec.field_id, v_rec.field_ids,
                v_rec.action, v_rec.rows_affected, v_rec.query_text, v_rec.client_ip,
                v_rec.user_agent, v_rec.ts) THEN
            RETURN QUERY SELECT false, total_rows, v_ok, v_rec.log_id,
                'Hash mismatch: row content was modified'::TEXT;
            RETURN;
        END IF;
        v_prev_hash := v_rec.row_hash;
        v_ok := v_ok + 1;
    END LOOP;
    RETURN QUERY SELECT true, total_rows, v_ok, NULL::UUID, NULL::TEXT;
END;
$$;

CREATE OR REPLACE FUNCTION is_audit_chain_valid()
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT is_valid FROM verify_chain_summary();
$$;

-- ============================================================================
-- request_access RETURNS THE NEW REQUEST ID
-- ============================================================================

DROP PROCEDURE IF EXISTS request_access(UUID, UUID, UUID[], TEXT, TIMESTAMPTZ);

CREATE OR REPLACE PROCEDURE request_access(
    p_user_id UUID,
    p_dataset_id UUID,
    p_field_ids UUID[],
    p_purpose TEXT,
    p_expires_at TIMESTAMPTZ,
    INOUT p_request_id UUID DEFAULT NULL
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
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
    RETURNING request_id INTO p_request_id;

    PERFORM restore_acting_user(v_prev_user);
END;
$$;
