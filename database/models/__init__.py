"""
ConsentLedger ORM Models
SQLAlchemy 2.0 style models matching database/migrations (applied by Alembic).

The schema is owned by the SQL migrations (``python -m database.migrate`` /
``alembic upgrade head``); these models map onto it and are not meant to
create tables themselves. Each model's primary key attribute is named after
its column (``org_id``, ``user_id``, ...) and is also available as ``.id``.
"""

from datetime import UTC, datetime
from enum import Enum as PyEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    FetchedValue,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    and_,
    func,
    literal_column,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, synonym


class Base(DeclarativeBase):
    """Base class for all table models."""


class ViewBase(DeclarativeBase):
    """Base class for read-only view models.

    Kept on separate metadata so ``Base.metadata.create_all``/``drop_all`` and
    Alembic autogenerate never treat the views as tables.
    """

    metadata = MetaData()


# ============================================================================
# ENUMS
# ============================================================================


class OrgType(str, PyEnum):
    NGO = "ngo"
    GOVERNMENT = "government"
    FUNDER = "funder"
    AUDITOR = "auditor"


class UserRole(str, PyEnum):
    """Names of the rows in the ``roles`` lookup table."""

    OWNER = "owner"
    PARTNER = "partner"
    AUDITOR = "auditor"
    ADMIN = "admin"


# Fixed ids seeded by migration 001 (roles is a lookup table)
ROLE_IDS: dict[UserRole, int] = {
    UserRole.OWNER: 1,
    UserRole.PARTNER: 2,
    UserRole.AUDITOR: 3,
    UserRole.ADMIN: 4,
}
ROLE_BY_ID: dict[int, UserRole] = {v: k for k, v in ROLE_IDS.items()}


class DatasetStatus(str, PyEnum):
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"


class SensitivityLevel(str, PyEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PII = "pii"


class DataType(str, PyEnum):
    TEXT = "text"
    INTEGER = "integer"
    NUMERIC = "numeric"
    BOOLEAN = "boolean"
    DATE = "date"
    TIMESTAMP = "timestamp"
    JSON = "json"


class RequestStatus(str, PyEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class AuditAction(str, PyEnum):
    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    GRANT_CREATE = "grant_create"
    GRANT_UPDATE = "grant_update"
    GRANT_REVOKE = "grant_revoke"
    GRANT_EXPIRE = "grant_expire"
    REQUEST_CREATE = "request_create"
    REQUEST_UPDATE = "request_update"
    REQUEST_APPROVE = "request_approve"
    REQUEST_DENY = "request_deny"
    LOGIN = "login"
    LOGOUT = "logout"
    PII_SCAN = "pii_scan"
    ANOMALY_ALERT = "anomaly_alert"


class AlertStatus(str, PyEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertDetector(str, PyEnum):
    ISOLATION_FOREST = "isolation_forest"
    RULE = "rule"
    MANUAL = "manual"


def str_enum(enum_cls: type[PyEnum], length: int) -> Enum:
    """Store a Python enum as its *value* in a VARCHAR column.

    SQLAlchemy's default is a native PostgreSQL ENUM holding member *names*
    ("NGO"), which does not match the VARCHAR + CHECK columns in the schema.
    """
    return Enum(
        enum_cls,
        native_enum=False,
        create_constraint=False,  # the CHECK constraints live in the migration
        length=length,
        values_callable=lambda cls: [m.value for m in cls],
        validate_strings=True,
    )


def utcnow() -> datetime:
    return datetime.now(UTC)


# ============================================================================
# MIXINS
# ============================================================================


class TimestampMixin:
    """Mixin for created_at/updated_at timestamps (updated_at is set by a trigger)."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        server_onupdate=FetchedValue(),
        nullable=False,
    )


def uuid_pk(column_name: str) -> Mapped[UUID]:
    return mapped_column(column_name, PG_UUID(as_uuid=True), primary_key=True, default=uuid4)


# ============================================================================
# MODELS
# ============================================================================


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"

    org_id: Mapped[UUID] = uuid_pk("org_id")
    id = synonym("org_id")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[OrgType] = mapped_column(str_enum(OrgType, 50), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    contact_email: Mapped[str | None] = mapped_column(String(255))

    users: Mapped[list["User"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", passive_deletes=True
    )
    owned_datasets: Mapped[list["Dataset"]] = relationship(
        back_populates="owner_org", foreign_keys="Dataset.owner_org_id", passive_deletes=True
    )
    granted_consents: Mapped[list["ConsentGrant"]] = relationship(
        back_populates="grantor_org",
        foreign_keys="ConsentGrant.grantor_org_id",
        passive_deletes=True,
    )
    received_consents: Mapped[list["ConsentGrant"]] = relationship(
        back_populates="grantee_org",
        foreign_keys="ConsentGrant.grantee_org_id",
        passive_deletes=True,
    )
    sent_requests: Mapped[list["AccessRequest"]] = relationship(
        back_populates="grantee_org",
        foreign_keys="AccessRequest.grantee_org_id",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint("type IN ('ngo', 'government', 'funder', 'auditor')"),
        Index("idx_organizations_type", "type"),
    )

    def __repr__(self) -> str:
        return f"<Organization(id={self.org_id}, name={self.name!r}, type={self.type})>"


class Role(Base):
    """RBAC lookup table: owner, partner, auditor, admin."""

    __tablename__ = "roles"

    role_id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    id = synonym("role_id")
    name: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    users: Mapped[list["User"]] = relationship(back_populates="role_ref")

    def __repr__(self) -> str:
        return f"<Role(id={self.role_id}, name={self.name!r})>"


class User(TimestampMixin, Base):
    """Single users table for every role (role_id -> roles)."""

    __tablename__ = "users"

    user_id: Mapped[UUID] = uuid_pk("user_id")
    id = synonym("user_id")
    org_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.org_id", ondelete="CASCADE"),
        nullable=False,
    )
    role_id: Mapped[int] = mapped_column(
        SmallInteger, ForeignKey("roles.role_id", ondelete="RESTRICT"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    google_sub: Mapped[str | None] = mapped_column(String(255), unique=True)
    full_name: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped["Organization"] = relationship(back_populates="users")
    role_ref: Mapped["Role"] = relationship(back_populates="users")
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="user", foreign_keys="AuditLog.user_id", viewonly=True
    )
    anomaly_alerts: Mapped[list["AnomalyAlert"]] = relationship(
        back_populates="user", foreign_keys="AnomalyAlert.user_id", passive_deletes=True
    )
    revoked_grants: Mapped[list["ConsentGrant"]] = relationship(
        back_populates="revoked_by_user", foreign_keys="ConsentGrant.revoked_by"
    )
    decided_requests: Mapped[list["AccessRequest"]] = relationship(
        back_populates="decided_by_user", foreign_keys="AccessRequest.decided_by"
    )
    resolved_alerts: Mapped[list["AnomalyAlert"]] = relationship(
        back_populates="resolved_by_user", foreign_keys="AnomalyAlert.resolved_by"
    )

    __table_args__ = (
        CheckConstraint("email = lower(email) AND email LIKE '%_@_%'"),
        Index("idx_users_org_id", "org_id"),
        Index("idx_users_role_id", "role_id"),
    )

    def __init__(self, *, role: UserRole | str | None = None, **kwargs: Any) -> None:
        if role is not None:
            kwargs["role_id"] = ROLE_IDS[UserRole(role)]
        if isinstance(kwargs.get("email"), str):
            kwargs["email"] = kwargs["email"].lower()
        super().__init__(**kwargs)

    @property
    def role(self) -> UserRole:
        """Role name resolved from role_id (roles is a fixed lookup table)."""
        return ROLE_BY_ID[self.role_id]

    @role.setter
    def role(self, value: UserRole | str) -> None:
        self.role_id = ROLE_IDS[UserRole(value)]

    def __repr__(self) -> str:
        return f"<User(id={self.user_id}, email={self.email!r}, role_id={self.role_id})>"


class Dataset(TimestampMixin, Base):
    __tablename__ = "datasets"

    dataset_id: Mapped[UUID] = uuid_pk("dataset_id")
    id = synonym("dataset_id")
    owner_org_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.org_id", ondelete="CASCADE"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[DatasetStatus] = mapped_column(
        str_enum(DatasetStatus, 50), default=DatasetStatus.DRAFT, nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    owner_org: Mapped["Organization"] = relationship(
        back_populates="owned_datasets", foreign_keys=[owner_org_id]
    )
    fields: Mapped[list["DatasetField"]] = relationship(
        back_populates="dataset",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DatasetField.ordinal",
    )
    consent_grants: Mapped[list["ConsentGrant"]] = relationship(
        back_populates="dataset", passive_deletes=True
    )
    access_requests: Mapped[list["AccessRequest"]] = relationship(
        back_populates="dataset", passive_deletes=True
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="dataset", foreign_keys="AuditLog.dataset_id", viewonly=True
    )

    __table_args__ = (
        CheckConstraint("status IN ('draft', 'published', 'archived')"),
        Index("idx_datasets_owner_org_id", "owner_org_id"),
        Index("idx_datasets_status", "status"),
    )

    def __repr__(self) -> str:
        return f"<Dataset(id={self.dataset_id}, title={self.title!r}, status={self.status})>"


class DatasetField(TimestampMixin, Base):
    __tablename__ = "dataset_fields"

    field_id: Mapped[UUID] = uuid_pk("field_id")
    id = synonym("field_id")
    dataset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("datasets.dataset_id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(63), nullable=False)
    data_type: Mapped[DataType] = mapped_column(str_enum(DataType, 50), nullable=False)
    sensitivity: Mapped[SensitivityLevel] = mapped_column(
        str_enum(SensitivityLevel, 20), default=SensitivityLevel.LOW, nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    dataset: Mapped["Dataset"] = relationship(back_populates="fields")
    consent_grants: Mapped[list["ConsentGrant"]] = relationship(
        back_populates="field",
        primaryjoin="DatasetField.field_id == foreign(ConsentGrant.field_id)",
        passive_deletes=True,
        overlaps="consent_grants,dataset",
    )

    __table_args__ = (
        UniqueConstraint("dataset_id", "name"),
        UniqueConstraint("field_id", "dataset_id"),
        CheckConstraint("name ~ '^[a-z_][a-z0-9_]*$'"),
    )

    def __repr__(self) -> str:
        return f"<DatasetField(id={self.field_id}, name={self.name!r}, type={self.data_type})>"


class ConsentGrant(Base):
    __tablename__ = "consent_grants"

    grant_id: Mapped[UUID] = uuid_pk("grant_id")
    id = synonym("grant_id")
    grantor_org_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.org_id", ondelete="CASCADE"),
        nullable=False,
    )
    grantee_org_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.org_id", ondelete="CASCADE"),
        nullable=False,
    )
    dataset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("datasets.dataset_id", ondelete="CASCADE"), nullable=False
    )
    field_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    purpose: Mapped[str] = mapped_column(String(500), nullable=False)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL")
    )
    revocation_reason: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        server_onupdate=FetchedValue(),
        nullable=False,
    )

    grantor_org: Mapped["Organization"] = relationship(
        back_populates="granted_consents", foreign_keys=[grantor_org_id]
    )
    grantee_org: Mapped["Organization"] = relationship(
        back_populates="received_consents", foreign_keys=[grantee_org_id]
    )
    dataset: Mapped["Dataset"] = relationship(
        back_populates="consent_grants", foreign_keys=[dataset_id]
    )
    field: Mapped["DatasetField"] = relationship(
        back_populates="consent_grants",
        primaryjoin="DatasetField.field_id == foreign(ConsentGrant.field_id)",
        overlaps="consent_grants,dataset",
    )
    revoked_by_user: Mapped["User | None"] = relationship(
        back_populates="revoked_grants", foreign_keys=[revoked_by]
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["field_id", "dataset_id"],
            ["dataset_fields.field_id", "dataset_fields.dataset_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("grantee_org_id", "dataset_id", "field_id", "purpose"),
        CheckConstraint("grantor_org_id <> grantee_org_id"),
        CheckConstraint("expires_at > granted_at"),
        Index(
            "idx_consent_grants_grantee_dataset_expires",
            "grantee_org_id",
            "dataset_id",
            "expires_at",
            postgresql_where="revoked_at IS NULL",
        ),
        Index("idx_consent_grants_grantor_dataset", "grantor_org_id", "dataset_id"),
        Index("idx_consent_grants_field", "field_id"),
    )

    @hybrid_property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        expires = self.expires_at
        if expires.tzinfo is None:  # naive datetimes are treated as UTC
            expires = expires.replace(tzinfo=UTC)
        return expires > utcnow()

    @is_active.inplace.expression
    @classmethod
    def _is_active_expression(cls) -> Any:
        return and_(cls.revoked_at.is_(None), cls.expires_at > func.now())

    def __repr__(self) -> str:
        return (
            f"<ConsentGrant(id={self.grant_id}, grantee={self.grantee_org_id}, "
            f"field={self.field_id}, revoked={self.revoked_at is not None})>"
        )


class AccessRequest(TimestampMixin, Base):
    __tablename__ = "access_requests"

    request_id: Mapped[UUID] = uuid_pk("request_id")
    id = synonym("request_id")
    grantee_org_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.org_id", ondelete="CASCADE"),
        nullable=False,
    )
    requested_by: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL")
    )
    dataset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("datasets.dataset_id", ondelete="CASCADE"), nullable=False
    )
    field_ids: Mapped[list[UUID]] = mapped_column(
        ARRAY(PG_UUID(as_uuid=True)), default=list, nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(500), nullable=False)
    requested_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[RequestStatus] = mapped_column(
        str_enum(RequestStatus, 20), default=RequestStatus.PENDING, nullable=False
    )
    decided_by: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL")
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(Text)

    grantee_org: Mapped["Organization"] = relationship(
        back_populates="sent_requests", foreign_keys=[grantee_org_id]
    )
    dataset: Mapped["Dataset"] = relationship(back_populates="access_requests")
    requested_by_user: Mapped["User | None"] = relationship(foreign_keys=[requested_by])
    decided_by_user: Mapped["User | None"] = relationship(
        back_populates="decided_requests", foreign_keys=[decided_by]
    )

    __table_args__ = (
        Index("idx_access_requests_grantee_status", "grantee_org_id", "status"),
        Index("idx_access_requests_dataset_status", "dataset_id", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<AccessRequest(id={self.request_id}, grantee={self.grantee_org_id}, "
            f"status={self.status})>"
        )


class AuditLog(Base):
    """Append-only, hash-chained audit record.

    ``seq``, ``prev_hash`` and ``row_hash`` are assigned by a database trigger
    on insert; rows cannot be updated or deleted.
    """

    __tablename__ = "audit_log"

    log_id: Mapped[UUID] = uuid_pk("log_id")
    id = synonym("log_id")
    seq: Mapped[int] = mapped_column(BigInteger, server_default=FetchedValue(), unique=True)
    user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="RESTRICT")
    )
    dataset_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("datasets.dataset_id", ondelete="RESTRICT")
    )
    field_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("dataset_fields.field_id", ondelete="RESTRICT")
    )
    field_ids: Mapped[list[UUID] | None] = mapped_column(ARRAY(PG_UUID(as_uuid=True)))
    action: Mapped[AuditAction] = mapped_column(str_enum(AuditAction, 50), nullable=False)
    rows_affected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    query_text: Mapped[str | None] = mapped_column(Text)
    client_ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary, server_default=FetchedValue())
    row_hash: Mapped[bytes] = mapped_column(LargeBinary, server_default=FetchedValue())

    user: Mapped["User | None"] = relationship(
        back_populates="audit_logs", foreign_keys=[user_id], viewonly=True
    )
    dataset: Mapped["Dataset | None"] = relationship(
        back_populates="audit_logs", foreign_keys=[dataset_id], viewonly=True
    )
    field: Mapped["DatasetField | None"] = relationship(foreign_keys=[field_id], viewonly=True)

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        Index("idx_audit_log_user_ts", "user_id", literal_column("ts").desc()),
        Index("idx_audit_log_dataset_ts", "dataset_id", literal_column("ts").desc()),
        Index("idx_audit_log_ts", literal_column("ts").desc()),
        Index("idx_audit_log_field", "field_id", postgresql_where=text("field_id IS NOT NULL")),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog(id={self.log_id}, seq={self.seq}, user={self.user_id}, "
            f"action={self.action}, ts={self.ts})>"
        )


class AnomalyAlert(Base):
    __tablename__ = "anomaly_alerts"

    alert_id: Mapped[UUID] = uuid_pk("alert_id")
    id = synonym("alert_id")
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    dataset_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("datasets.dataset_id", ondelete="SET NULL")
    )
    score: Mapped[float] = mapped_column(Numeric(5, 4, asdecimal=False), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    features: Mapped[dict | None] = mapped_column(JSONB)
    detector: Mapped[AlertDetector] = mapped_column(
        str_enum(AlertDetector, 30), default=AlertDetector.ISOLATION_FOREST, nullable=False
    )
    status: Mapped[AlertStatus] = mapped_column(
        str_enum(AlertStatus, 20), default=AlertStatus.OPEN, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL")
    )

    user: Mapped["User"] = relationship(back_populates="anomaly_alerts", foreign_keys=[user_id])
    dataset: Mapped["Dataset | None"] = relationship()
    resolved_by_user: Mapped["User | None"] = relationship(
        back_populates="resolved_alerts", foreign_keys=[resolved_by]
    )

    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 1"),
        Index("idx_anomaly_alerts_user_status", "user_id", "status"),
        Index("idx_anomaly_alerts_dataset_status", "dataset_id", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<AnomalyAlert(id={self.alert_id}, user={self.user_id}, "
            f"score={self.score:.4f}, status={self.status})>"
        )


class RevokedToken(Base):
    """JWT ids invalidated by logout (rejected until they expire)."""

    __tablename__ = "revoked_tokens"

    jti: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (Index("idx_revoked_tokens_expires", "expires_at"),)


# ============================================================================
# VIEW MODELS (read-only)
# ============================================================================


class PartnerDatasetView(ViewBase):
    """Grants visible to the current organization (one row per granted field)."""

    __tablename__ = "partner_dataset_view"

    dataset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String(100))
    grant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    field_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    field_name: Mapped[str] = mapped_column(String(63))
    data_type: Mapped[str] = mapped_column(String(50))
    sensitivity: Mapped[str] = mapped_column(String(20))
    purpose: Mapped[str] = mapped_column(String(500))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AccessEventFeatures(ViewBase):
    """Per-read features computed with window functions (for the AI detector)."""

    __tablename__ = "access_event_features"

    log_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger)
    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    org_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    dataset_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    rows_affected: Mapped[int] = mapped_column(Integer)
    fields_touched: Mapped[int] = mapped_column(Integer)
    is_off_hours: Mapped[bool] = mapped_column(Boolean)
    user_event_no: Mapped[int] = mapped_column(BigInteger)
    seconds_since_prev: Mapped[float | None] = mapped_column(Numeric(asdecimal=False))
    queries_last_hour: Mapped[int] = mapped_column(BigInteger)
    rows_last_hour: Mapped[int] = mapped_column(BigInteger)
    user_avg_rows: Mapped[float] = mapped_column(Numeric(asdecimal=False))
    rows_vs_user_avg: Mapped[float | None] = mapped_column(Numeric(asdecimal=False))
    user_off_hours_share: Mapped[float] = mapped_column(Numeric(asdecimal=False))
    rows_percentile: Mapped[float] = mapped_column(Numeric(asdecimal=False))


class AccessFeaturesHourly(ViewBase):
    """Per-user hourly features with rolling baselines (window functions)."""

    __tablename__ = "access_features_hourly"

    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    hour_bucket: Mapped[datetime] = mapped_column(DateTime, primary_key=True)  # UTC
    query_count: Mapped[int] = mapped_column(BigInteger)
    distinct_datasets: Mapped[int] = mapped_column(BigInteger)
    distinct_fields: Mapped[int] = mapped_column(BigInteger)
    total_rows_read: Mapped[int] = mapped_column(BigInteger)
    select_count: Mapped[int] = mapped_column(BigInteger)
    write_count: Mapped[int] = mapped_column(BigInteger)
    off_hours_count: Mapped[int] = mapped_column(BigInteger)
    max_rows_per_query: Mapped[int] = mapped_column(BigInteger)
    off_hours_share: Mapped[float] = mapped_column(Numeric(asdecimal=False))
    rows_per_request: Mapped[float | None] = mapped_column(Numeric(asdecimal=False))
    baseline_query_count: Mapped[float | None] = mapped_column(Numeric(asdecimal=False))
    baseline_rows_read: Mapped[float | None] = mapped_column(Numeric(asdecimal=False))
    rows_vs_baseline: Mapped[float | None] = mapped_column(Numeric(asdecimal=False))
    hours_since_prev_active: Mapped[float | None] = mapped_column(Numeric(asdecimal=False))
    rows_rank_in_hour: Mapped[int] = mapped_column(BigInteger)


class GrantUsageLatency(ViewBase):
    """Grant-to-first-use latency."""

    __tablename__ = "grant_usage_latency"

    grant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    grantee_org_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    dataset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    field_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    grant_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_user_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    first_access_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hours_to_first_use: Mapped[float | None] = mapped_column(Numeric(asdecimal=False))


__all__ = [
    "Base",
    "ViewBase",
    "OrgType",
    "UserRole",
    "ROLE_IDS",
    "ROLE_BY_ID",
    "DatasetStatus",
    "SensitivityLevel",
    "DataType",
    "RequestStatus",
    "AuditAction",
    "AlertStatus",
    "AlertDetector",
    "Organization",
    "Role",
    "User",
    "Dataset",
    "DatasetField",
    "ConsentGrant",
    "AccessRequest",
    "AuditLog",
    "AnomalyAlert",
    "RevokedToken",
    "PartnerDatasetView",
    "AccessEventFeatures",
    "AccessFeaturesHourly",
    "GrantUsageLatency",
]
