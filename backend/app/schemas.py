"""Pydantic request/response models (validation happens here, before the DB)."""

from datetime import UTC, datetime
from typing import Annotated, Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

from database.models import (
    AlertDetector,
    AlertStatus,
    AuditAction,
    DatasetStatus,
    DataType,
    OrgType,
    RequestStatus,
    SensitivityLevel,
    UserRole,
)

T = TypeVar("T")

NonEmpty = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Purpose = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]
FieldName = Annotated[
    str, StringConstraints(strip_whitespace=True, pattern=r"^[a-z_][a-z0-9_]*$", max_length=63)
]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


def _future(v: datetime) -> datetime:
    if v.tzinfo is None:
        v = v.replace(tzinfo=UTC)
    if v <= datetime.now(UTC):
        raise ValueError("must be in the future")
    return v


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int


def make_page(items: list, total: int, page: int, page_size: int) -> dict[str, Any]:
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, -(-total // page_size)),
    }


# ------------------------------------------------------------------ auth/users


class LoginIn(BaseModel):
    email: EmailStr
    password: Annotated[str, StringConstraints(min_length=1, max_length=200)]


class GoogleCredentialIn(BaseModel):
    credential: Annotated[str, StringConstraints(min_length=20)]


class OrganizationOut(ORM):
    org_id: UUID
    name: str
    type: OrgType
    description: str | None = None
    contact_email: str | None = None
    created_at: datetime


class OrganizationCreate(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=255)]
    type: OrgType
    description: str | None = Field(None, max_length=2000)
    contact_email: EmailStr | None = None


class OrganizationUpdate(BaseModel):
    name: (
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=255)]
        | None
    ) = None
    description: str | None = Field(None, max_length=2000)
    contact_email: EmailStr | None = None


class RoleOut(ORM):
    role_id: int
    name: str
    description: str


class UserOut(ORM):
    user_id: UUID
    email: str
    full_name: str | None = None
    role: UserRole
    org_id: UUID
    org_name: str | None = None
    is_active: bool
    last_login: datetime | None = None
    has_password: bool = False
    google_linked: bool = False


class UserCreate(BaseModel):
    email: EmailStr
    full_name: Annotated[str, StringConstraints(strip_whitespace=True, max_length=255)] | None = (
        None
    )
    org_id: UUID
    role: UserRole
    password: Annotated[str, StringConstraints(min_length=8, max_length=200)] | None = Field(
        None, description="Optional: omit for Google-only accounts"
    )


class UserUpdate(BaseModel):
    full_name: Annotated[str, StringConstraints(strip_whitespace=True, max_length=255)] | None = (
        None
    )
    role: UserRole | None = None
    is_active: bool | None = None


class MeOut(BaseModel):
    user: UserOut
    organization: OrganizationOut
    permissions: list[str]
    auth_method: Literal["cookie", "bearer"]
    expires_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class AuthConfigOut(BaseModel):
    google_enabled: bool
    password_login_enabled: bool


# ------------------------------------------------------------------ datasets


class FieldCreate(BaseModel):
    name: FieldName
    data_type: DataType
    sensitivity: SensitivityLevel = SensitivityLevel.LOW
    description: str | None = Field(None, max_length=1000)
    is_encrypted: bool = False
    ordinal: int | None = Field(None, ge=0, le=10000)


class FieldUpdate(BaseModel):
    sensitivity: SensitivityLevel | None = None
    description: str | None = Field(None, max_length=1000)
    is_encrypted: bool | None = None
    ordinal: int | None = Field(None, ge=0, le=10000)


class FieldOut(ORM):
    field_id: UUID
    dataset_id: UUID
    name: str
    data_type: DataType
    sensitivity: SensitivityLevel
    description: str | None = None
    is_encrypted: bool
    ordinal: int


class DatasetCreate(BaseModel):
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=255)]
    description: str | None = Field(None, max_length=5000)
    category: Annotated[str, StringConstraints(strip_whitespace=True, max_length=100)] | None = None


class DatasetUpdate(BaseModel):
    title: (
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=255)]
        | None
    ) = None
    description: str | None = Field(None, max_length=5000)
    category: Annotated[str, StringConstraints(strip_whitespace=True, max_length=100)] | None = None
    status: Literal["draft", "archived"] | None = Field(
        None, description="Use POST /publish to publish; datasets are archived, never deleted"
    )


class DatasetOut(ORM):
    dataset_id: UUID
    title: str
    description: str | None = None
    category: str | None = None
    status: DatasetStatus
    version: int
    owner_org_id: UUID
    owner_org_name: str | None = None
    created_at: datetime
    updated_at: datetime
    field_count: int = 0
    is_owner: bool = False
    has_access: bool = False


class GrantSummary(BaseModel):
    grant_id: UUID
    field_id: UUID
    field_name: str
    purpose: str
    expires_at: datetime


class DatasetDetail(DatasetOut):
    fields: list[FieldOut] = []
    my_grants: list[GrantSummary] = []
    row_count: int | None = None


class ColumnSuggestion(BaseModel):
    name: str
    original_name: str
    inferred_type: DataType
    suggested_sensitivity: SensitivityLevel
    confidence: float
    detected: dict[str, float]
    reasons: list[str]
    masked_preview: list[Any]
    suggest_encryption: bool


class UploadPreview(BaseModel):
    row_count: int
    columns: list[ColumnSuggestion]
    ner_available: bool


class BulkFieldsIn(BaseModel):
    fields: Annotated[list[FieldCreate], Field(min_length=1, max_length=200)]


class IngestResult(BaseModel):
    rows_loaded: int
    total_rows: int


class DataPage(BaseModel):
    columns: list[str]
    rows: list[dict[str, Any]]
    total: int
    page: int
    page_size: int
    purpose: str | None
    visible_fields: list[str]
    masked_fields: list[str]


# ------------------------------------------------------------------ consent


class ConsentCreate(BaseModel):
    dataset_id: UUID
    grantee_org_id: UUID
    field_ids: Annotated[list[UUID], Field(min_length=1, max_length=200)]
    purpose: Purpose
    expires_at: datetime

    _future = field_validator("expires_at")(_future)


class ConsentOut(BaseModel):
    grant_id: UUID
    dataset_id: UUID
    dataset_title: str | None
    grantor_org_id: UUID
    grantor_org_name: str | None
    grantee_org_id: UUID
    grantee_org_name: str | None
    field_id: UUID
    field_name: str | None
    sensitivity: SensitivityLevel | None
    purpose: str
    granted_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None
    status: Literal["active", "expired", "revoked"]


class RevokeIn(BaseModel):
    reason: str | None = Field(None, max_length=1000)


class BulkRevokeIn(BaseModel):
    grant_ids: Annotated[list[UUID], Field(min_length=1, max_length=500)]
    reason: str | None = Field(None, max_length=1000)


class BulkRevokeOut(BaseModel):
    revoked: int


class ExtendIn(BaseModel):
    expires_at: datetime

    _future = field_validator("expires_at")(_future)


# ------------------------------------------------------------------ requests


class RequestCreate(BaseModel):
    dataset_id: UUID
    field_ids: Annotated[list[UUID], Field(min_length=1, max_length=200)]
    purpose: Purpose
    expires_at: datetime

    _future = field_validator("expires_at")(_future)


class FieldRef(BaseModel):
    field_id: UUID
    name: str | None
    sensitivity: SensitivityLevel | None


class RequestOut(BaseModel):
    request_id: UUID
    dataset_id: UUID
    dataset_title: str | None
    owner_org_id: UUID | None
    owner_org_name: str | None
    grantee_org_id: UUID
    grantee_org_name: str | None
    requested_by_email: str | None
    fields: list[FieldRef]
    purpose: str
    requested_expires_at: datetime
    status: RequestStatus
    decided_by_email: str | None
    decided_at: datetime | None
    decision_note: str | None
    created_at: datetime


class ApproveIn(BaseModel):
    field_ids: Annotated[list[UUID], Field(min_length=1, max_length=200)] | None = Field(
        None, description="Subset of the requested fields (default: all requested)"
    )
    purpose: Purpose | None = None
    expires_at: datetime | None = Field(None, description="Default: the requested expiry")
    note: str | None = Field(None, max_length=1000)

    @field_validator("expires_at")
    @classmethod
    def _exp(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _future(v)


class DenyIn(BaseModel):
    note: str | None = Field(None, max_length=1000)


# ------------------------------------------------------------------ audit & alerts


class AuditOut(BaseModel):
    log_id: UUID
    seq: int
    ts: datetime
    action: AuditAction
    user_id: UUID | None
    user_email: str | None
    dataset_id: UUID | None
    dataset_title: str | None
    field_id: UUID | None
    field_count: int
    rows_affected: int
    query_text: str | None
    client_ip: str | None
    row_hash: str
    prev_hash: str


class ChainError(BaseModel):
    log_id: UUID
    message: str


class VerifyOut(BaseModel):
    valid: bool
    total_rows: int
    verified_rows: int
    first_error: ChainError | None
    checked_at: datetime


class AlertOut(BaseModel):
    alert_id: UUID
    user_id: UUID
    user_email: str | None
    user_org_name: str | None
    dataset_id: UUID | None
    dataset_title: str | None
    score: float
    reason: str
    features: dict[str, Any] | None
    detector: AlertDetector
    status: AlertStatus
    created_at: datetime
    resolved_at: datetime | None
    active_grants: int = 0


class AlertUpdate(BaseModel):
    status: AlertStatus


class AlertRevokeResult(BaseModel):
    revoked_grants: int


class DetectorRunOut(BaseModel):
    user_hours: int
    alerts_written: int
    isolation_forest_flags: int | None = None
    rule_flags: int | None = None
    evaluation: dict[str, Any] | None = None


class DashboardOut(BaseModel):
    role: UserRole
    datasets_visible: int
    datasets_owned: int
    consents_given_active: int
    consents_received_active: int
    requests_incoming_pending: int
    requests_outgoing_pending: int
    alerts_open: int
    audit_events_24h: int
    recent_audit: list[AuditOut]
    recent_alerts: list[AlertOut]
