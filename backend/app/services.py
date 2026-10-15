"""Shared query helpers and serializers used by the routers."""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import Request
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from database.models import AuditAction, AuditLog, ConsentGrant, Organization, User

from .schemas import UserOut


def now() -> datetime:
    return datetime.now(UTC)


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def record_event(
    db: Session,
    request: Request,
    user_id: UUID,
    action: AuditAction,
    *,
    dataset_id: UUID | None = None,
    rows: int = 0,
    detail: str | None = None,
) -> None:
    """Append an application event (login, logout, pii_scan, ...) to the audit chain."""
    ip = client_ip(request)
    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            dataset_id=dataset_id,
            rows_affected=rows,
            query_text=detail,
            client_ip=ip if ip and ip != "testclient" else None,
            user_agent=(request.headers.get("user-agent") or "")[:500] or None,
        )
    )
    db.flush()


def count(db: Session, stmt: Select) -> int:
    return db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0


def grant_status(g: ConsentGrant) -> str:
    if g.revoked_at is not None:
        return "revoked"
    expires = g.expires_at if g.expires_at.tzinfo else g.expires_at.replace(tzinfo=UTC)
    return "active" if expires > now() else "expired"


def user_out(user: User, org: Organization | None = None) -> UserOut:
    return UserOut(
        user_id=user.user_id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        org_id=user.org_id,
        org_name=org.name if org else None,
        is_active=user.is_active,
        last_login=user.last_login,
        has_password=user.password_hash is not None,
        google_linked=user.google_sub is not None,
    )


PERMISSIONS = {
    "owner": [
        "datasets:create",
        "datasets:publish",
        "datasets:upload",
        "pii:scan",
        "consent:grant",
        "consent:revoke",
        "requests:decide",
        "alerts:manage",
        "audit:read_org",
        "audit:verify",
        "data:read_own",
    ],
    "partner": ["datasets:browse", "requests:create", "data:read_consented", "audit:read_org"],
    "auditor": [
        "datasets:read_all",
        "consent:read_all",
        "requests:read_all",
        "audit:read_all",
        "audit:verify",
        "alerts:review",
        "alerts:run_detector",
    ],
    "admin": ["orgs:manage", "users:manage", "alerts:run_detector", "audit:verify"],
}
