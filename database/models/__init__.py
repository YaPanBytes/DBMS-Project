"""
ConsentLedger ORM Models
Member A: Database Lead
SQLAlchemy 2.0 style models matching the database schema
"""

from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional, List
from uuid import UUID, uuid4

from sqlalchemy import (
    Column, String, Text, Integer, Boolean, DateTime, ForeignKey,
    Index, CheckConstraint, UniqueConstraint, ARRAY, func, select
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, declared_attr
from sqlalchemy.ext.hybrid import hybrid_property


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


# ============================================================================
# ENUMS
# ============================================================================

class OrgType(str, PyEnum):
    NGO = "ngo"
    GOVERNMENT = "government"
    FUNDER = "funder"
    AUDITOR = "auditor"


class UserRole(str, PyEnum):
    OWNER = "owner"
    PARTNER = "partner"
    AUDITOR = "auditor"
    ADMIN = "admin"


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
    GRANT_REVOKE = "grant_revoke"
    GRANT_EXPIRE = "grant_expire"
    REQUEST_CREATE = "request_create"
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


# ============================================================================
# MIXINS
# ============================================================================

class TimestampMixin:
    """Mixin for created_at/updated_at timestamps."""
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class UUIDMixin:
    """Mixin for UUID primary key."""
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )


# ============================================================================
# MODELS
# ============================================================================

class Organization(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "organizations"
    
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[OrgType] = mapped_column(nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Relationships
    users: Mapped[List["User"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    owned_datasets: Mapped[List["Dataset"]] = relationship(back_populates="owner_org", foreign_keys="Dataset.owner_org_id")
    granted_consents: Mapped[List["ConsentGrant"]] = relationship(back_populates="grantor_org", foreign_keys="ConsentGrant.grantor_org_id")
    received_consents: Mapped[List["ConsentGrant"]] = relationship(back_populates="grantee_org", foreign_keys="ConsentGrant.grantee_org_id")
    sent_requests: Mapped[List["AccessRequest"]] = relationship(back_populates="grantee_org", foreign_keys="AccessRequest.grantee_org_id")
    
    __table_args__ = (
        Index("ix_organizations_type", "type"),
    )
    
    def __repr__(self) -> str:
        return f"<Organization(id={self.id}, name={self.name!r}, type={self.type})>"


class User(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "users"
    
    org_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("organizations.org_id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="users")
    audit_logs: Mapped[List["AuditLog"]] = relationship(back_populates="user")
    anomaly_alerts: Mapped[List["AnomalyAlert"]] = relationship(back_populates="user")
    revoked_grants: Mapped[List["ConsentGrant"]] = relationship(back_populates="revoked_by_user", foreign_keys="ConsentGrant.revoked_by")
    decided_requests: Mapped[List["AccessRequest"]] = relationship(back_populates="decided_by_user", foreign_keys="AccessRequest.decided_by")
    resolved_alerts: Mapped[List["AnomalyAlert"]] = relationship(back_populates="resolved_by_user", foreign_keys="AnomalyAlert.resolved_by")
    
    __table_args__ = (
        Index("ix_users_org_id", "org_id"),
        Index("ix_users_email", "email"),
    )
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email!r}, role={self.role})>"


class Dataset(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "datasets"
    
    owner_org_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("organizations.org_id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[DatasetStatus] = mapped_column(default=DatasetStatus.DRAFT, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    
    # Relationships
    owner_org: Mapped["Organization"] = relationship(back_populates="owned_datasets", foreign_keys=[owner_org_id])
    fields: Mapped[List["DatasetField"]] = relationship(back_populates="dataset", cascade="all, delete-orphan")
    consent_grants: Mapped[List["ConsentGrant"]] = relationship(back_populates="dataset")
    access_requests: Mapped[List["AccessRequest"]] = relationship(back_populates="dataset")
    audit_logs: Mapped[List["AuditLog"]] = relationship(back_populates="dataset")
    
    __table_args__ = (
        Index("ix_datasets_owner_org_id", "owner_org_id"),
        Index("ix_datasets_status", "status"),
    )
    
    def __repr__(self) -> str:
        return f"<Dataset(id={self.id}, title={self.title!r}, status={self.status})>"


class DatasetField(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "dataset_fields"
    
    dataset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("datasets.dataset_id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    data_type: Mapped[DataType] = mapped_column(nullable=False)
    sensitivity: Mapped[SensitivityLevel] = mapped_column(default=SensitivityLevel.LOW, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    
    # Relationships
    dataset: Mapped["Dataset"] = relationship(back_populates="fields")
    consent_grants: Mapped[List["ConsentGrant"]] = relationship(back_populates="field")
    audit_logs: Mapped[List["AuditLog"]] = relationship(back_populates="field")
    
    __table_args__ = (
        UniqueConstraint("dataset_id", "name", name="uq_dataset_fields_dataset_name"),
        Index("ix_dataset_fields_dataset_id", "dataset_id"),
    )
    
    def __repr__(self) -> str:
        return f"<DatasetField(id={self.id}, name={self.name!r}, type={self.data_type})>"


class ConsentGrant(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "consent_grants"
    
    grantor_org_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("organizations.org_id", ondelete="CASCADE"), nullable=False
    )
    grantee_org_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("organizations.org_id", ondelete="CASCADE"), nullable=False
    )
    dataset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("datasets.dataset_id", ondelete="CASCADE"), nullable=False
    )
    field_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("dataset_fields.field_id", ondelete="CASCADE"), nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(500), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True
    )
    revocation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Relationships
    grantor_org: Mapped["Organization"] = relationship(back_populates="granted_consents", foreign_keys=[grantor_org_id])
    grantee_org: Mapped["Organization"] = relationship(back_populates="received_consents", foreign_keys=[grantee_org_id])
    dataset: Mapped["Dataset"] = relationship(back_populates="consent_grants")
    field: Mapped["DatasetField"] = relationship(back_populates="consent_grants")
    revoked_by_user: Mapped[Optional["User"]] = relationship(back_populates="revoked_grants", foreign_keys=[revoked_by])
    
    __table_args__ = (
        UniqueConstraint(
            "grantee_org_id", "dataset_id", "field_id", "purpose",
            name="uq_consent_grants_grantee_dataset_field_purpose"
        ),
        CheckConstraint("expires_at > created_at", name="ck_consent_grants_expires_after_created"),
        Index("ix_consent_grants_grantee_dataset_expires", "grantee_org_id", "dataset_id", "expires_at",
              postgresql_where="revoked_at IS NULL"),
        Index("ix_consent_grants_grantor_dataset", "grantor_org_id", "dataset_id"),
        Index("ix_consent_grants_field_id", "field_id"),
    )
    
    @hybrid_property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.expires_at > datetime.utcnow()
    
    def __repr__(self) -> str:
        return f"<ConsentGrant(id={self.id}, grantee={self.grantee_org_id}, field={self.field_id}, active={self.is_active})>"


class AccessRequest(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "access_requests"
    
    grantee_org_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("organizations.org_id", ondelete="CASCADE"), nullable=False
    )
    dataset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("datasets.dataset_id", ondelete="CASCADE"), nullable=False
    )
    field_ids: Mapped[List[UUID]] = mapped_column(ARRAY(PG_UUID(as_uuid=True)), default=list, nullable=False)
    purpose: Mapped[str] = mapped_column(String(500), nullable=False)
    requested_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[RequestStatus] = mapped_column(default=RequestStatus.PENDING, nullable=False)
    decided_by: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Relationships
    grantee_org: Mapped["Organization"] = relationship(back_populates="sent_requests", foreign_keys=[grantee_org_id])
    dataset: Mapped["Dataset"] = relationship(back_populates="access_requests")
    decided_by_user: Mapped[Optional["User"]] = relationship(back_populates="decided_requests", foreign_keys=[decided_by])
    
    __table_args__ = (
        Index("ix_access_requests_grantee_status", "grantee_org_id", "status"),
        Index("ix_access_requests_dataset_status", "dataset_id", "status"),
    )
    
    def __repr__(self) -> str:
        return f"<AccessRequest(id={self.id}, grantee={self.grantee_org_id}, status={self.status})>"


class AuditLog(UUIDMixin, Base):
    __tablename__ = "audit_log"
    
    # No TimestampMixin - only has ts (immutable)
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=False
    )
    dataset_id: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("datasets.dataset_id"), nullable=True
    )
    field_id: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("dataset_fields.field_id"), nullable=True
    )
    action: Mapped[AuditAction] = mapped_column(nullable=False)
    rows_affected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    query_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    client_ip: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    prev_hash: Mapped[bytes] = mapped_column(nullable=False)
    row_hash: Mapped[bytes] = mapped_column(nullable=False)
    
    # Relationships
    user: Mapped["User"] = relationship(back_populates="audit_logs")
    dataset: Mapped[Optional["Dataset"]] = relationship(back_populates="audit_logs")
    field: Mapped[Optional["DatasetField"]] = relationship(back_populates="audit_logs")
    
    __table_args__ = (
        Index("ix_audit_log_user_ts", "user_id", "ts"),
        Index("ix_audit_log_dataset_ts", "dataset_id", "ts"),
        Index("ix_audit_log_ts", "ts"),
    )
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, user={self.user_id}, action={self.action}, ts={self.ts})>"


class AnomalyAlert(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "anomaly_alerts"
    
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=False
    )
    dataset_id: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("datasets.dataset_id"), nullable=True
    )
    score: Mapped[float] = mapped_column(nullable=False)  # 0.0 to 1.0
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    features: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    status: Mapped[AlertStatus] = mapped_column(default=AlertStatus.OPEN, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True
    )
    
    # Relationships
    user: Mapped["User"] = relationship(back_populates="anomaly_alerts")
    dataset: Mapped[Optional["Dataset"]] = relationship()
    resolved_by_user: Mapped[Optional["User"]] = relationship(back_populates="resolved_alerts", foreign_keys=[resolved_by])
    
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 1", name="ck_anomaly_alerts_score_range"),
        Index("ix_anomaly_alerts_user_status", "user_id", "status"),
        Index("ix_anomaly_alerts_dataset_status", "dataset_id", "status"),
    )
    
    def __repr__(self) -> str:
        return f"<AnomalyAlert(id={self.id}, user={self.user_id}, score={self.score:.4f}, status={self.status})>"


# ============================================================================
# VIEW MODELS (for querying)
# ============================================================================

class PartnerDatasetView(Base):
    """Read-only view for partner dataset access."""
    __tablename__ = "partner_dataset_view"
    __table_args__ = {"info": {"is_view": True}}
    
    dataset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text)
    category: Mapped[Optional[str]] = mapped_column(String(100))
    grant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    field_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    field_name: Mapped[str] = mapped_column(String(100))
    data_type: Mapped[str] = mapped_column(String(50))
    sensitivity: Mapped[str] = mapped_column(String(20))
    purpose: Mapped[str] = mapped_column(String(500))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class AccessFeaturesHourly(Base):
    """Materialized view for anomaly detection features."""
    __tablename__ = "access_features_hourly"
    __table_args__ = {"info": {"is_view": True}}
    
    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    hour_bucket: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    query_count: Mapped[int] = mapped_column(Integer)
    distinct_datasets: Mapped[int] = mapped_column(Integer)
    distinct_fields: Mapped[int] = mapped_column(Integer)
    total_rows_read: Mapped[int] = mapped_column(Integer)
    select_count: Mapped[int] = mapped_column(Integer)
    write_count: Mapped[int] = mapped_column(Integer)
    off_hours_count: Mapped[int] = mapped_column(Integer)
    max_rows_per_query: Mapped[int] = mapped_column(Integer)


class GrantUsageLatency(Base):
    """View for grant-to-first-use latency."""
    __tablename__ = "grant_usage_latency"
    __table_args__ = {"info": {"is_view": True}}
    
    grant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    grantee_org_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    dataset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True))
    grant_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_access_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    hours_to_first_use: Mapped[Optional[float]] = mapped_column()


# ============================================================================
# MODEL REGISTRY
# ============================================================================

__all__ = [
    "Base",
    "OrgType", "UserRole", "DatasetStatus", "SensitivityLevel", "DataType",
    "RequestStatus", "AuditAction", "AlertStatus",
    "Organization", "User", "Dataset", "DatasetField",
    "ConsentGrant", "AccessRequest", "AuditLog", "AnomalyAlert",
    "PartnerDatasetView", "AccessFeaturesHourly", "GrantUsageLatency",
]