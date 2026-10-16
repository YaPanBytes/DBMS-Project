"""
ConsentLedger database tests: schema and constraints, ORM, procedures,
hash-chained audit log, row-level security, masked views and encryption,
feature views, demo queries, and a pg_dump/pg_restore round trip.

Each test runs inside a transaction that is rolled back (see the ``conn``
fixture), on the throwaway test database created by the root conftest.py.
"""

import json
import shutil
import subprocess
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import bcrypt
import pytest
from sqlalchemy import Connection, Engine, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from database.models import (
    AccessRequest,
    AlertStatus,
    AnomalyAlert,
    AuditAction,
    AuditLog,
    ConsentGrant,
    Dataset,
    DatasetField,
    DatasetStatus,
    DataType,
    Organization,
    OrgType,
    RequestStatus,
    Role,
    SensitivityLevel,
    User,
    UserRole,
)

ENC_KEY = "test-encryption-key"


def utcnow() -> datetime:
    return datetime.now(UTC)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def conn(migrated_engine: Engine) -> Generator[Connection, None, None]:
    connection = migrated_engine.connect()
    trans = connection.begin()
    yield connection
    trans.rollback()
    connection.close()


@pytest.fixture
def db(conn: Connection) -> Generator[Session, None, None]:
    session = Session(bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False)
    yield session
    session.close()


def make_user(db: Session, org: Organization, role: UserRole) -> User:
    u = User(
        org_id=org.id, email=f"{role.value}-{uuid4().hex[:10]}@t.org", password_hash="x", role=role
    )
    db.add(u)
    db.flush()
    return u


@pytest.fixture
def world(db: Session) -> dict:
    """Owner org with a published 4-field dataset, a partner org, an auditor."""
    owner_org = Organization(name="Owner NGO", type=OrgType.NGO)
    partner_org = Organization(name="Partner Funder", type=OrgType.FUNDER)
    auditor_org = Organization(name="Auditor", type=OrgType.AUDITOR)
    db.add_all([owner_org, partner_org, auditor_org])
    db.flush()
    w = {
        "owner_org": owner_org,
        "partner_org": partner_org,
        "auditor_org": auditor_org,
        "owner": make_user(db, owner_org, UserRole.OWNER),
        "partner": make_user(db, partner_org, UserRole.PARTNER),
        "auditor": make_user(db, auditor_org, UserRole.AUDITOR),
    }
    ds = Dataset(owner_org_id=owner_org.id, title="Beneficiaries", status=DatasetStatus.PUBLISHED)
    db.add(ds)
    db.flush()
    spec = [
        ("full_name", DataType.TEXT, SensitivityLevel.PII, True),
        ("income", DataType.NUMERIC, SensitivityLevel.HIGH, False),
        ("household_size", DataType.INTEGER, SensitivityLevel.MEDIUM, False),
        ("region", DataType.TEXT, SensitivityLevel.LOW, False),
    ]
    w["fields"] = {}
    for i, (name, dtype, sens, enc) in enumerate(spec):
        f = DatasetField(
            dataset_id=ds.id,
            name=name,
            data_type=dtype,
            sensitivity=sens,
            is_encrypted=enc,
            ordinal=i,
        )
        db.add(f)
        w["fields"][name] = f
    db.flush()
    w["dataset"] = ds
    return w


def grant(w: dict, field: str, purpose: str = "analytics", days: int = 30) -> ConsentGrant:
    return ConsentGrant(
        grantor_org_id=w["owner_org"].id,
        grantee_org_id=w["partner_org"].id,
        dataset_id=w["dataset"].id,
        field_id=w["fields"][field].id,
        purpose=purpose,
        expires_at=utcnow() + timedelta(days=days),
    )


def act_as(conn: Connection, user: User | None, *, app_role: bool = True) -> None:
    """Set the request context like the API does (optionally as the app role)."""
    if user is not None:
        conn.execute(
            text(
                "SELECT set_config('consentledger.current_user_id', :u, true), "
                "set_config('consentledger.current_org_id', :o, true), "
                "set_config('consentledger.encryption_key', :k, true)"
            ),
            {"u": str(user.id), "o": str(user.org_id), "k": ENC_KEY},
        )
    if app_role:
        conn.execute(text("SET LOCAL ROLE consentledger_app"))


def reset(conn: Connection) -> None:
    conn.execute(text("RESET ROLE"))
    conn.execute(
        text(
            "SELECT set_config('consentledger.current_user_id', '', true), "
            "set_config('consentledger.current_org_id', '', true)"
        )
    )


def publish_with_rows(conn: Connection, w: dict, rows: list[dict]) -> None:
    """Publish the world's dataset and load rows, as its owner."""
    act_as(conn, w["owner"], app_role=False)
    conn.execute(text("SELECT publish_dataset(:d)"), {"d": w["dataset"].id})
    conn.execute(
        text("SELECT ingest_dataset_rows(:d, CAST(:r AS jsonb))"),
        {"d": w["dataset"].id, "r": json.dumps(rows)},
    )
    reset(conn)


ROWS = [
    {"full_name": "Jane Doe", "income": 1234.5, "household_size": 4, "region": "north"},
    {"full_name": "Ravi Kumar", "income": 800, "household_size": 2, "region": "south"},
]


def sp_raises(conn: Connection, match: str, stmt: str, params: dict | None = None) -> None:
    """Assert a statement fails, without aborting the outer test transaction."""
    sp = conn.begin_nested()
    with pytest.raises(DBAPIError, match=match):
        conn.execute(text(stmt), params or {})
    sp.rollback()


# ============================================================================
# SCHEMA, CONSTRAINTS, ORM
# ============================================================================


class TestSchema:
    def test_roles_lookup_table(self, db: Session) -> None:
        names = db.scalars(select(Role.name).order_by(Role.role_id)).all()
        assert names == ["owner", "partner", "auditor", "admin"]

    def test_user_role_is_a_foreign_key(self, db: Session, world: dict) -> None:
        u = world["owner"]
        db.refresh(u)
        assert u.role_ref.name == "owner" and u.role == UserRole.OWNER
        db.add(User(org_id=world["owner_org"].id, email="bad@t.org", role_id=99))
        with pytest.raises(IntegrityError):
            db.flush()

    def test_organizations_crud(self, db: Session) -> None:
        org = Organization(name="Test NGO", type=OrgType.NGO, contact_email="test@ngo.org")
        db.add(org)
        db.commit()
        db.refresh(org)
        org.description = "Updated"
        db.commit()
        db.refresh(org)
        assert org.updated_at > org.created_at  # trigger
        db.delete(org)
        db.commit()
        assert db.get(Organization, org.id) is None

    def test_enums_stored_as_lowercase_values(self, db: Session, conn: Connection) -> None:
        org = Organization(name="Gov", type=OrgType.GOVERNMENT)
        db.add(org)
        db.flush()
        assert (
            conn.execute(
                text("SELECT type FROM organizations WHERE org_id = :i"), {"i": org.id}
            ).scalar()
            == "government"
        )

    def test_email_must_be_lowercase(self, conn: Connection, world: dict) -> None:
        sp_raises(
            conn,
            "check",
            "INSERT INTO users (org_id, role_id, email) VALUES (:o, 2, 'Mixed@T.org')",
            {"o": world["owner_org"].id},
        )

    def test_passwords_are_bcrypt(self) -> None:
        h = bcrypt.hashpw(b"secret", bcrypt.gensalt(rounds=4))
        assert bcrypt.checkpw(b"secret", h)

    def test_field_name_must_be_identifier(self, db: Session, world: dict) -> None:
        db.add(
            DatasetField(
                dataset_id=world["dataset"].id, name="bad name; drop", data_type=DataType.TEXT
            )
        )
        with pytest.raises(IntegrityError):
            db.flush()

    def test_expiry_must_be_after_grant(self, db: Session, world: dict) -> None:
        g = grant(world, "income")
        g.granted_at = utcnow()
        g.expires_at = utcnow() - timedelta(days=1)
        db.add(g)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_grant_field_must_belong_to_dataset(self, db: Session, world: dict) -> None:
        other = Dataset(owner_org_id=world["owner_org"].id, title="Other")
        db.add(other)
        db.flush()
        g = grant(world, "income")
        g.dataset_id = other.id
        db.add(g)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_org_cannot_grant_itself(self, db: Session, world: dict) -> None:
        g = grant(world, "income")
        g.grantee_org_id = g.grantor_org_id
        db.add(g)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_unique_grant(self, db: Session, world: dict) -> None:
        db.add(grant(world, "income", "p1"))
        db.flush()
        db.add(grant(world, "income", "p1"))
        with pytest.raises(IntegrityError):
            db.flush()

    def test_request_needs_fields(self, db: Session, world: dict) -> None:
        db.add(
            AccessRequest(
                grantee_org_id=world["partner_org"].id,
                dataset_id=world["dataset"].id,
                field_ids=[],
                purpose="x research",
                requested_expires_at=utcnow() + timedelta(days=3),
            )
        )
        with pytest.raises(IntegrityError):
            db.flush()

    def test_grant_identity_is_immutable(self, db: Session, world: dict) -> None:
        g = grant(world, "income")
        db.add(g)
        db.flush()
        g.purpose = "something else"
        with pytest.raises(DBAPIError, match="Only expiry and revocation"):
            db.flush()

    def test_hybrid_is_active(self, db: Session, world: dict) -> None:
        g = grant(world, "income")
        db.add(g)
        db.flush()
        assert g.is_active
        assert db.scalars(
            select(ConsentGrant).where(ConsentGrant.is_active, ConsentGrant.id == g.id)
        ).all() == [g]
        g.revoked_at = utcnow()
        db.flush()
        assert not g.is_active

    def test_alert_score_range(self, db: Session, world: dict) -> None:
        db.add(AnomalyAlert(user_id=world["partner"].id, score=1.5, reason="x"))
        with pytest.raises(IntegrityError):
            db.flush()

    def test_alert_resolution_needs_timestamp(self, db: Session, world: dict) -> None:
        db.add(
            AnomalyAlert(
                user_id=world["partner"].id, score=0.5, reason="x", status=AlertStatus.RESOLVED
            )
        )
        with pytest.raises(IntegrityError):
            db.flush()


# ============================================================================
# AUDIT LOG
# ============================================================================


class TestAuditLog:
    def test_inserts_are_chained(self, db: Session, conn: Connection, world: dict) -> None:
        logs = []
        for _ in range(4):
            log = AuditLog(
                user_id=world["partner"].id,
                dataset_id=world["dataset"].id,
                action=AuditAction.SELECT,
                rows_affected=10,
            )
            db.add(log)
            db.flush()
            logs.append(log)
        for prev, cur in zip(logs, logs[1:], strict=False):
            assert cur.seq > prev.seq and cur.prev_hash == prev.row_hash
        assert conn.execute(text("SELECT is_audit_chain_valid()")).scalar() is True

    def test_client_supplied_hashes_are_ignored(self, db: Session, conn: Connection) -> None:
        log = AuditLog(action=AuditAction.LOGIN, prev_hash=b"\x01" * 32, row_hash=b"\x02" * 32)
        db.add(log)
        db.flush()
        db.refresh(log)
        assert log.row_hash != b"\x02" * 32
        assert conn.execute(text("SELECT is_audit_chain_valid()")).scalar() is True

    def test_append_only(self, db: Session, conn: Connection) -> None:
        db.add(AuditLog(action=AuditAction.LOGIN))
        db.flush()
        sp_raises(conn, "append-only", "UPDATE audit_log SET rows_affected = 99")
        sp_raises(conn, "append-only", "DELETE FROM audit_log")

    def test_audited_rows_cannot_be_deleted(
        self, db: Session, conn: Connection, world: dict
    ) -> None:
        # the dataset insert was audited -> RESTRICT foreign key blocks deletion
        sp_raises(
            conn,
            "foreign key",
            "DELETE FROM datasets WHERE dataset_id = :d",
            {"d": world["dataset"].id},
        )
        db.add(AuditLog(user_id=world["partner"].id, action=AuditAction.LOGIN))
        db.flush()
        sp_raises(
            conn, "foreign key", "DELETE FROM users WHERE user_id = :u", {"u": world["partner"].id}
        )

    def test_tamper_detection(self, db: Session, conn: Connection, world: dict) -> None:
        logs = [
            AuditLog(user_id=world["partner"].id, action=AuditAction.SELECT, rows_affected=1)
            for _ in range(3)
        ]
        db.add_all(logs)
        db.flush()
        conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER trg_audit_log_immutable"))
        conn.execute(
            text("UPDATE audit_log SET rows_affected = 1000 WHERE log_id = :i"), {"i": logs[1].id}
        )
        errors = conn.execute(text("SELECT * FROM verify_chain() WHERE NOT is_valid")).all()
        assert len(errors) == 1 and errors[0].log_id == logs[1].id
        assert "modified" in errors[0].error_msg

    def test_deleted_row_breaks_chain(self, db: Session, conn: Connection, world: dict) -> None:
        logs = [AuditLog(user_id=world["partner"].id, action=AuditAction.LOGIN) for _ in range(3)]
        db.add_all(logs)
        db.flush()
        conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER trg_audit_log_immutable"))
        conn.execute(text("DELETE FROM audit_log WHERE log_id = :i"), {"i": logs[1].id})
        bad = conn.execute(
            text("SELECT log_id, error_msg FROM verify_chain() WHERE NOT is_valid")
        ).one()
        assert bad.log_id == logs[2].id and "Chain broken" in bad.error_msg

    def test_python_verifier_matches_sql(self, db: Session, conn: Connection, world: dict) -> None:
        from database.scripts.verify_audit import compute_row_hash

        db.add(
            AuditLog(
                user_id=world["partner"].id,
                dataset_id=world["dataset"].id,
                field_ids=[world["fields"]["income"].id],
                action=AuditAction.SELECT,
                rows_affected=7,
                query_text="q 'ünïcødé'\nline",
                client_ip="192.168.0.1",
                user_agent="agent/1.0",
            )
        )
        db.flush()
        row = conn.execute(text("""
            SELECT prev_hash, row_hash, user_id::text, dataset_id::text, field_id::text,
                   field_ids::text, action, rows_affected::text, query_text, client_ip::text,
                   user_agent, audit_ts_text(ts)
            FROM audit_log ORDER BY seq DESC LIMIT 1""")).one()
        assert compute_row_hash(bytes(row[0]), *row[2:]) == bytes(row[1])

    def test_grant_and_audit_commit_together(self, conn: Connection, world: dict) -> None:
        before = conn.execute(text("SELECT count(*) FROM audit_log")).scalar()
        sp = conn.begin_nested()
        act_as(conn, world["owner"], app_role=False)
        conn.execute(
            text(
                "INSERT INTO consent_grants (grantor_org_id, grantee_org_id, dataset_id, "
                "field_id, purpose, expires_at) VALUES (:a, :b, :d, :f, 'x', now() + interval '1 day')"
            ),
            {
                "a": world["owner_org"].id,
                "b": world["partner_org"].id,
                "d": world["dataset"].id,
                "f": world["fields"]["region"].id,
            },
        )
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar() == before + 1
        sp.rollback()  # the grant is rolled back -> so is its audit entry
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar() == before

    def test_business_tables_are_audited(self, db: Session, conn: Connection, world: dict) -> None:
        act_as(conn, world["owner"], app_role=False)
        db.add(grant(world, "region"))
        db.flush()
        last = conn.execute(
            text("SELECT action, user_id, field_id FROM audit_log ORDER BY seq DESC LIMIT 1")
        ).one()
        assert last.action == "grant_create" and last.user_id == world["owner"].id
        assert last.field_id == world["fields"]["region"].id


# ============================================================================
# STORED PROCEDURES
# ============================================================================


class TestProcedures:
    def _request(self, conn: Connection, w: dict, fields: list[str]) -> None:
        conn.execute(
            text("CALL request_access(:u, :d, CAST(:f AS uuid[]), :p, :e)"),
            {
                "u": w["partner"].id,
                "d": w["dataset"].id,
                "f": [str(w["fields"][f].id) for f in fields],
                "p": "research",
                "e": utcnow() + timedelta(days=30),
            },
        )

    def _rid(self, conn: Connection, w: dict):
        return conn.execute(
            text(
                "SELECT request_id FROM access_requests WHERE dataset_id = :d "
                "ORDER BY created_at DESC LIMIT 1"
            ),
            {"d": w["dataset"].id},
        ).scalar()

    def test_request_approve_narrowed(self, conn: Connection, world: dict) -> None:
        self._request(conn, world, ["income", "region"])
        rid = self._rid(conn, world)
        conn.execute(
            text("CALL approve_access_request(:u, :r, CAST(:f AS uuid[]), :p, :e, 'ok')"),
            {
                "u": world["owner"].id,
                "r": rid,
                "f": [str(world["fields"]["income"].id)],
                "p": "research",
                "e": utcnow() + timedelta(days=10),
            },
        )
        assert (
            conn.execute(
                text("SELECT status FROM access_requests WHERE request_id = :r"), {"r": rid}
            ).scalar()
            == "approved"
        )
        assert conn.execute(
            text("SELECT field_id FROM consent_grants WHERE dataset_id = :d"),
            {"d": world["dataset"].id},
        ).scalars().all() == [world["fields"]["income"].id]
        actions = conn.execute(
            text("SELECT action, user_id FROM audit_log WHERE dataset_id = :d ORDER BY seq"),
            {"d": world["dataset"].id},
        ).all()
        assert [a for a, _ in actions][-3:] == ["request_create", "grant_create", "request_approve"]
        assert (
            actions[-3].user_id == world["partner"].id and actions[-1].user_id == world["owner"].id
        )

    def test_approve_rejects_unrequested_fields(self, conn: Connection, world: dict) -> None:
        self._request(conn, world, ["region"])
        sp_raises(
            conn,
            "subset",
            "CALL approve_access_request(:u, :r, CAST(:f AS uuid[]), 'x', :e)",
            {
                "u": world["owner"].id,
                "r": self._rid(conn, world),
                "f": [str(world["fields"]["full_name"].id)],
                "e": utcnow() + timedelta(days=1),
            },
        )

    @pytest.mark.parametrize("who", ["partner", "unknown"])
    def test_approve_requires_owner(self, conn: Connection, world: dict, who: str) -> None:
        self._request(conn, world, ["region"])
        uid = world["partner"].id if who == "partner" else uuid4()
        sp_raises(
            conn,
            "may not|not found",
            "CALL approve_access_request(:u, :r, CAST(:f AS uuid[]), 'x', :e)",
            {
                "u": uid,
                "r": self._rid(conn, world),
                "f": [str(world["fields"]["region"].id)],
                "e": utcnow() + timedelta(days=1),
            },
        )

    def test_actor_must_match_session_user(self, conn: Connection, world: dict) -> None:
        self._request(conn, world, ["region"])
        act_as(conn, world["partner"], app_role=False)  # partner tries to act as the owner
        sp_raises(
            conn,
            "does not match",
            "CALL deny_access_request(:u, :r)",
            {"u": world["owner"].id, "r": self._rid(conn, world)},
        )

    def test_auditor_cannot_request(self, conn: Connection, world: dict) -> None:
        sp_raises(
            conn,
            "may not",
            "CALL request_access(:u, :d, CAST(:f AS uuid[]), 'x', :e)",
            {
                "u": world["auditor"].id,
                "d": world["dataset"].id,
                "f": [str(world["fields"]["region"].id)],
                "e": utcnow() + timedelta(days=1),
            },
        )

    def test_deny(self, conn: Connection, world: dict) -> None:
        self._request(conn, world, ["region"])
        rid = self._rid(conn, world)
        conn.execute(
            text("CALL deny_access_request(:u, :r, 'no')"), {"u": world["owner"].id, "r": rid}
        )
        assert (
            conn.execute(
                text("SELECT status FROM access_requests WHERE request_id = :r"), {"r": rid}
            ).scalar()
            == "denied"
        )

    def test_revoke(self, db: Session, conn: Connection, world: dict) -> None:
        g = grant(world, "income")
        db.add(g)
        db.flush()
        sp_raises(conn, "not found|may not", "CALL revoke_grant(:u, :g)", {"u": uuid4(), "g": g.id})
        conn.execute(text("CALL revoke_grant(:u, :g, 'done')"), {"u": world["owner"].id, "g": g.id})
        assert conn.execute(text("SELECT is_grant_active(:g)"), {"g": g.id}).scalar() is False
        assert (
            conn.execute(text("SELECT action FROM audit_log ORDER BY seq DESC LIMIT 1")).scalar()
            == "grant_revoke"
        )

    def test_expire_grants(self, db: Session, conn: Connection, world: dict) -> None:
        g = grant(world, "income")
        g.granted_at = utcnow() - timedelta(days=10)
        g.expires_at = utcnow() - timedelta(days=1)
        db.add(g)
        db.flush()
        conn.execute(text("CALL expire_grants()"))
        assert (
            conn.execute(
                text("SELECT revocation_reason FROM consent_grants WHERE grant_id = :g"),
                {"g": g.id},
            ).scalar()
            == "Expired"
        )
        assert (
            conn.execute(text("SELECT action FROM audit_log ORDER BY seq DESC LIMIT 1")).scalar()
            == "grant_expire"
        )


# ============================================================================
# ROW-LEVEL SECURITY, MASKED VIEWS, ENCRYPTION, LOGGED READS
# ============================================================================


class TestEnforcement:
    def _read(self, conn: Connection, w: dict, purpose: str | None) -> list[dict]:
        return list(
            conn.execute(
                text("SELECT access_dataset(:d, :p)"), {"d": w["dataset"].id, "p": purpose}
            ).scalars()
        )

    def test_owner_reads_everything_decrypted(self, conn: Connection, world: dict) -> None:
        publish_with_rows(conn, world, ROWS)
        act_as(conn, world["owner"])
        rows = self._read(conn, world, None)
        assert rows[0]["full_name"] == "Jane Doe" and rows[0]["income"] == "1234.5"

    def test_encrypted_at_rest(self, conn: Connection, world: dict) -> None:
        publish_with_rows(conn, world, ROWS)
        table = conn.execute(
            text("SELECT dataset_data_table_name(:d)"), {"d": world["dataset"].id}
        ).scalar()
        raw = conn.execute(text(f"SELECT full_name FROM {table} ORDER BY row_id LIMIT 1")).scalar()
        assert isinstance(raw, bytes) and b"Jane" not in raw

    def test_partner_sees_only_granted_fields_for_purpose(
        self, db: Session, conn: Connection, world: dict
    ) -> None:
        db.add_all([grant(world, "income", "analytics"), grant(world, "full_name", "outreach")])
        db.flush()
        publish_with_rows(conn, world, ROWS)
        act_as(conn, world["partner"])
        row = self._read(conn, world, "analytics")[0]
        assert row["income"] == "1234.5"
        assert row["full_name"] == "[REDACTED]"  # granted only for another purpose
        assert row["household_size"] == "[MASKED]" and row["region"] == "[MASKED]"
        sp_raises(
            conn,
            "purpose is required",
            "SELECT access_dataset(:d, NULL)",
            {"d": world["dataset"].id},
        )
        sp_raises(
            conn,
            "No active consent",
            "SELECT access_dataset(:d, 'marketing')",
            {"d": world["dataset"].id},
        )

    def test_reads_are_logged_with_fields_and_rows(
        self, db: Session, conn: Connection, world: dict
    ) -> None:
        db.add(grant(world, "income"))
        db.flush()
        publish_with_rows(conn, world, ROWS)
        act_as(conn, world["partner"])
        self._read(conn, world, "analytics")
        reset(conn)
        last = conn.execute(
            text(
                "SELECT action, user_id, rows_affected, field_ids FROM audit_log "
                "ORDER BY seq DESC LIMIT 1"
            )
        ).one()
        assert (last.action, last.user_id, last.rows_affected) == ("select", world["partner"].id, 2)
        assert last.field_ids == [world["fields"]["income"].id]

    def test_revocation_applies_on_next_query(
        self, db: Session, conn: Connection, world: dict
    ) -> None:
        g = grant(world, "income")
        db.add(g)
        db.flush()
        publish_with_rows(conn, world, ROWS)
        act_as(conn, world["partner"])
        assert self._read(conn, world, "analytics")
        reset(conn)
        conn.execute(text("CALL revoke_grant(:u, :g)"), {"u": world["owner"].id, "g": g.id})
        act_as(conn, world["partner"])
        sp_raises(
            conn,
            "No active consent",
            "SELECT access_dataset(:d, 'analytics')",
            {"d": world["dataset"].id},
        )

    def test_app_role_cannot_bypass_the_read_path(
        self, db: Session, conn: Connection, world: dict
    ) -> None:
        db.add(grant(world, "income"))
        db.flush()
        publish_with_rows(conn, world, ROWS)
        table = conn.execute(
            text("SELECT dataset_data_table_name(:d)"), {"d": world["dataset"].id}
        ).scalar()
        act_as(conn, world["partner"])
        sp_raises(conn, "permission denied", f"SELECT * FROM {table}")
        sp_raises(conn, "permission denied", f"SELECT * FROM {table}_masked")
        sp_raises(conn, "permission denied", "SELECT * FROM access_features_hourly")

    def test_writes_audited_per_statement(self, conn: Connection, world: dict) -> None:
        publish_with_rows(conn, world, ROWS)
        last = conn.execute(
            text(
                "SELECT action, rows_affected, dataset_id FROM audit_log "
                "ORDER BY seq DESC LIMIT 1"
            )
        ).one()
        assert (last.action, last.rows_affected, last.dataset_id) == (
            "insert",
            2,
            world["dataset"].id,
        )

    def test_only_owner_role_can_publish(self, db: Session, conn: Connection, world: dict) -> None:
        colleague = make_user(db, world["owner_org"], UserRole.PARTNER)  # same org, partner role
        act_as(conn, colleague)
        sp_raises(conn, "Only an owner", "SELECT publish_dataset(:d)", {"d": world["dataset"].id})

    def test_catalogue_visibility(self, db: Session, conn: Connection, world: dict) -> None:
        draft = Dataset(owner_org_id=world["owner_org"].id, title="Secret draft")
        db.add(draft)
        db.flush()
        act_as(conn, world["partner"])
        visible = set(conn.execute(text("SELECT dataset_id FROM datasets")).scalars())
        assert world["dataset"].id in visible and draft.id not in visible

    def test_owner_and_auditor_see_all_fields(self, conn: Connection, world: dict) -> None:
        for who in ("owner", "auditor"):
            sp = conn.begin_nested()
            act_as(conn, world[who])
            n = conn.execute(
                text("SELECT count(*) FROM dataset_fields WHERE dataset_id = :d"),
                {"d": world["dataset"].id},
            ).scalar()
            assert n == 4, who
            sp.rollback()

    def test_partner_cannot_grant(self, conn: Connection, world: dict) -> None:
        act_as(conn, world["partner"])
        sp_raises(
            conn,
            "row-level security",
            "INSERT INTO consent_grants (grantor_org_id, grantee_org_id, dataset_id, field_id, purpose, "
            "expires_at) VALUES (:a, :b, :d, :f, 'x', now() + interval '1 day')",
            {
                "a": world["partner_org"].id,
                "b": world["auditor_org"].id,
                "d": world["dataset"].id,
                "f": world["fields"]["income"].id,
            },
        )

    def test_audit_log_rls(self, db: Session, conn: Connection, world: dict) -> None:
        other_org = Organization(name="Stranger", type=OrgType.NGO)
        db.add(other_org)
        db.flush()
        stranger = make_user(db, other_org, UserRole.PARTNER)
        db.add_all(
            [
                AuditLog(user_id=world["partner"].id, action=AuditAction.LOGIN),
                AuditLog(user_id=stranger.id, action=AuditAction.LOGIN),
            ]
        )
        db.flush()
        act_as(conn, world["partner"])
        users = set(
            conn.execute(text("SELECT user_id FROM audit_log WHERE action = 'login'")).scalars()
        )
        assert world["partner"].id in users and stranger.id not in users
        reset(conn)
        act_as(conn, world["auditor"])
        users = set(
            conn.execute(text("SELECT user_id FROM audit_log WHERE action = 'login'")).scalars()
        )
        assert {world["partner"].id, stranger.id} <= users


# ============================================================================
# FEATURES, DEMO QUERIES, BACKUP
# ============================================================================


class TestReviewFixes:
    """Migration 0004: cheaper reads with the same rules, and small fixes."""

    def test_new_ciphertext_is_salted_aes256(self, conn: Connection, world: dict) -> None:
        publish_with_rows(conn, world, ROWS)
        table = conn.execute(
            text("SELECT dataset_data_table_name(:d)"), {"d": world["dataset"].id}
        ).scalar()
        raw = conn.execute(text(f"SELECT full_name FROM {table} LIMIT 1")).scalar()
        assert raw[2:5] == b"\x04\x09\x01"  # OpenPGP v4, AES-256, salted S2K

    def test_old_ciphertext_still_decrypts(self, conn: Connection, world: dict) -> None:
        publish_with_rows(conn, world, ROWS)
        table = conn.execute(
            text("SELECT dataset_data_table_name(:d)"), {"d": world["dataset"].id}
        ).scalar()
        conn.execute(
            text(f"UPDATE {table} SET full_name = pgp_sym_encrypt('Old Style', :k)"),
            {"k": ENC_KEY},
        )
        act_as(conn, world["owner"])
        rows = list(conn.execute(text("SELECT access_dataset(:d)"), {"d": world["dataset"].id}))
        assert rows[0][0]["full_name"] == "Old Style"

    def test_paging_reads_only_the_page(self, db: Session, conn: Connection, world: dict) -> None:
        publish_with_rows(conn, world, ROWS)
        act_as(conn, world["owner"])
        rows = conn.execute(
            text("SELECT access_dataset(:d, NULL, 1, 1)"), {"d": world["dataset"].id}
        ).scalars()
        assert [r["full_name"] for r in rows] == ["Ravi Kumar"]

    def test_masked_view_still_enforces_consent(
        self, db: Session, conn: Connection, world: dict
    ) -> None:
        db.add(grant(world, "income", "analytics"))
        db.flush()
        publish_with_rows(conn, world, ROWS)
        view = conn.execute(
            text("SELECT dataset_masked_view_name(:d)"), {"d": world["dataset"].id}
        ).scalar()
        act_as(conn, world["partner"], app_role=False)  # table owner: may query the view
        conn.execute(text("SELECT set_config('consentledger.current_purpose', 'analytics', true)"))
        row = conn.execute(text(f"SELECT * FROM {view} ORDER BY row_id LIMIT 1")).mappings().one()
        assert row["income"] == "1234.5" and row["full_name"] == "[REDACTED]"
        assert row["region"] == "[MASKED]"
        conn.execute(text("SELECT set_config('consentledger.current_purpose', 'other', true)"))
        assert conn.execute(text(f"SELECT count(*) FROM {view}")).scalar() == 0
        plan = "\n".join(conn.execute(text(f"EXPLAIN SELECT * FROM {view}")).scalars())
        assert "InitPlan" in plan  # permission checks run once per query

    def test_policies_evaluate_helpers_once(self, conn: Connection, world: dict) -> None:
        act_as(conn, world["owner"])
        plan = "\n".join(conn.execute(text("EXPLAIN SELECT * FROM dataset_fields")).scalars())
        assert "InitPlan" in plan

    def test_field_without_column_reads_as_null(
        self, db: Session, conn: Connection, world: dict
    ) -> None:
        publish_with_rows(conn, world, ROWS)
        db.add(
            DatasetField(
                dataset_id=world["dataset"].id, name="late", data_type=DataType.TEXT, ordinal=9
            )
        )
        db.flush()
        act_as(conn, world["owner"])
        rows = conn.execute(text("SELECT access_dataset(:d)"), {"d": world["dataset"].id})
        assert rows.scalars().first()["late"] is None

    def test_request_access_returns_id(self, conn: Connection, world: dict) -> None:
        rid = conn.execute(
            text("CALL request_access(:u, :d, CAST(:f AS uuid[]), 'research', :e, NULL)"),
            {
                "u": world["partner"].id,
                "d": world["dataset"].id,
                "f": [str(world["fields"]["income"].id)],
                "e": utcnow() + timedelta(days=5),
            },
        ).scalar_one()
        assert (
            conn.execute(
                text("SELECT purpose FROM access_requests WHERE request_id = :r"), {"r": rid}
            ).scalar()
            == "research"
        )

    def test_verify_chain_summary(self, db: Session, conn: Connection, world: dict) -> None:
        logs = [AuditLog(user_id=world["partner"].id, action=AuditAction.LOGIN) for _ in range(3)]
        db.add_all(logs)
        db.flush()
        ok = conn.execute(text("SELECT * FROM verify_chain_summary()")).one()
        assert ok.is_valid and ok.total_rows == ok.verified_rows and ok.first_bad_log_id is None
        conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER trg_audit_log_immutable"))
        conn.execute(
            text("UPDATE audit_log SET rows_affected = 9 WHERE log_id = :i"), {"i": logs[1].id}
        )
        bad = conn.execute(text("SELECT * FROM verify_chain_summary()")).one()
        assert not bad.is_valid and bad.first_bad_log_id == logs[1].id
        assert bad.verified_rows == bad.total_rows - 2  # stopped at the modified row
        assert conn.execute(text("SELECT is_audit_chain_valid()")).scalar() is False

    def test_admin_sees_alerts(self, db: Session, conn: Connection, world: dict) -> None:
        admin = make_user(db, world["auditor_org"], UserRole.ADMIN)
        db.add(AnomalyAlert(user_id=world["partner"].id, score=0.9, reason="test"))
        db.flush()
        act_as(conn, admin)
        assert conn.execute(text("SELECT count(*) FROM anomaly_alerts")).scalar() >= 1
        title = conn.execute(
            text("SELECT title FROM datasets WHERE dataset_id = :d"), {"d": world["dataset"].id}
        ).scalar()
        assert title == "Beneficiaries"  # metadata, for reading alerts
        assert conn.execute(text("SELECT count(*) FROM consent_grants")).scalar() == 0
        reset(conn)
        act_as(conn, world["partner"])
        assert conn.execute(text("SELECT count(*) FROM anomaly_alerts")).scalar() == 0


class TestFeaturesAndOps:
    def test_window_feature_views(self, db: Session, conn: Connection, world: dict) -> None:
        base = utcnow().replace(hour=10, minute=0, second=0, microsecond=0) - timedelta(days=1)
        for i, rows in enumerate([10, 20, 5000]):
            db.add(
                AuditLog(
                    user_id=world["partner"].id,
                    dataset_id=world["dataset"].id,
                    field_ids=[world["fields"]["income"].id],
                    action=AuditAction.SELECT,
                    rows_affected=rows,
                    ts=base + timedelta(minutes=10 * i),
                )
            )
        db.flush()
        ev = conn.execute(
            text(
                "SELECT rows_affected, queries_last_hour, rows_last_hour, seconds_since_prev "
                "FROM access_event_features WHERE user_id = :u ORDER BY ts"
            ),
            {"u": world["partner"].id},
        ).all()
        assert [e.queries_last_hour for e in ev] == [1, 2, 3]
        assert ev[-1].rows_last_hour == 5030 and float(ev[1].seconds_since_prev) == 600
        hourly = conn.execute(
            text(
                "SELECT query_count, total_rows_read, distinct_fields "
                "FROM access_features_hourly WHERE user_id = :u"
            ),
            {"u": world["partner"].id},
        ).one()
        assert (hourly.query_count, hourly.total_rows_read, hourly.distinct_fields) == (3, 5030, 1)

    def test_demo_queries_run(self, conn: Connection, seeded) -> None:
        sql = (Path(__file__).parent / "queries" / "demo_queries.sql").read_text()
        conn.connection.dbapi_connection.cursor().execute(sql)

    def test_alembic_is_at_head(self, migrated_engine: Engine) -> None:
        from database.migrate import current_revision, head_revision

        assert current_revision(migrated_engine) == head_revision()

    @pytest.mark.skipif(
        not shutil.which("pg_dump") or not shutil.which("pg_restore"),
        reason="PostgreSQL client tools not installed",
    )
    def test_backup_and_restore_round_trip(self, migrated_engine: Engine, seeded, tmp_path) -> None:
        """pg_dump the seeded test database, pg_restore it into a new database,
        and check the data and the audit chain survived."""
        from sqlalchemy import create_engine

        url = migrated_engine.url
        restore_db = f"{url.database}_restore"
        admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
        env = {"PGPASSWORD": url.password or "", "PATH": "/usr/bin:/bin:/usr/local/bin"}
        args = ["-h", url.host or "localhost", "-p", str(url.port or 5432), "-U", url.username]
        dump = tmp_path / "backup.dump"
        try:
            subprocess.run(
                ["pg_dump", *args, "-d", url.database, "-F", "custom", "-f", str(dump)],
                check=True,
                env=env,
                capture_output=True,
            )
            with admin.connect() as c:
                c.execute(text(f'DROP DATABASE IF EXISTS "{restore_db}" WITH (FORCE)'))
                c.execute(text(f'CREATE DATABASE "{restore_db}"'))
            subprocess.run(
                [
                    "pg_restore",
                    *args,
                    "-d",
                    restore_db,
                    "--no-owner",
                    "--single-transaction",
                    str(dump),
                ],
                check=True,
                env=env,
                capture_output=True,
            )
            restored = create_engine(url.set(database=restore_db))
            with migrated_engine.connect() as a, restored.connect() as b:
                for q in (
                    "SELECT count(*) FROM audit_log",
                    "SELECT count(*) FROM consent_grants",
                    "SELECT max(seq) FROM audit_log",
                ):
                    assert a.execute(text(q)).scalar() == b.execute(text(q)).scalar(), q
                assert b.execute(text("SELECT is_audit_chain_valid()")).scalar() is True
                # the chain continues correctly after a restore
                b.execute(text("INSERT INTO audit_log (action) VALUES ('login')"))
                assert b.execute(text("SELECT is_audit_chain_valid()")).scalar() is True
                b.rollback()
            restored.dispose()
        finally:
            with admin.connect() as c:
                c.execute(text(f'DROP DATABASE IF EXISTS "{restore_db}" WITH (FORCE)'))
            admin.dispose()


class TestSeed:
    def test_seed_is_large_enough(self, conn: Connection, seeded) -> None:
        counts = {
            t: conn.execute(text(f"SELECT count(*) FROM {t}")).scalar()
            for t in (
                "organizations",
                "users",
                "datasets",
                "dataset_fields",
                "consent_grants",
                "access_requests",
                "audit_log",
            )
        }
        assert counts["audit_log"] > 1000 and counts["dataset_fields"] > 40
        assert conn.execute(text("SELECT is_audit_chain_valid()")).scalar() is True

    def test_seed_requests_pending(self, db: Session, seeded) -> None:
        assert (
            db.scalar(
                select(AccessRequest).where(AccessRequest.status == RequestStatus.PENDING).limit(1)
            )
            is not None
        )
