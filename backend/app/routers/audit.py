"""Audit trail (read-only, RLS-filtered) and hash-chain verification."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import func, select, text

from database.models import AuditAction, AuditLog, Dataset, User, UserRole

from ..deps import AuthUser, DbSession, Paging
from ..errors import AppError
from ..schemas import AuditOut, ChainError, Page, VerifyOut, make_page
from ..services import count, now

router = APIRouter(prefix="/audit", tags=["audit"])


def audit_out(log: AuditLog, email: str | None, title: str | None) -> AuditOut:
    return AuditOut(
        log_id=log.log_id,
        seq=log.seq,
        ts=log.ts,
        action=log.action,
        user_id=log.user_id,
        user_email=email,
        dataset_id=log.dataset_id,
        dataset_title=title,
        field_id=log.field_id,
        field_count=len(log.field_ids or []),
        rows_affected=log.rows_affected,
        query_text=log.query_text,
        client_ip=str(log.client_ip) if log.client_ip else None,
        row_hash=log.row_hash.hex(),
        prev_hash=log.prev_hash.hex(),
    )


def audit_query():
    return (
        select(AuditLog, User.email, Dataset.title)
        .join(User, User.user_id == AuditLog.user_id, isouter=True)
        .join(Dataset, Dataset.dataset_id == AuditLog.dataset_id, isouter=True)
    )


@router.get(
    "",
    response_model=Page[AuditOut],
    summary="Audit entries visible to you (auditors: all; others: your org and datasets)",
)
def list_audit(
    db: DbSession,
    current: AuthUser,
    paging: Paging,
    action: AuditAction | None = None,
    user_id: UUID | None = None,
    dataset_id: UUID | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    q: Annotated[
        str | None, Query(max_length=100, description="Search user email / dataset")
    ] = None,
) -> dict:
    stmt = audit_query()
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if dataset_id:
        stmt = stmt.where(AuditLog.dataset_id == dataset_id)
    if since:
        stmt = stmt.where(AuditLog.ts >= since)
    if until:
        stmt = stmt.where(AuditLog.ts < until)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(User.email.ilike(like) | Dataset.title.ilike(like))
    total = count(db, stmt)
    rows = db.execute(
        stmt.order_by(AuditLog.seq.desc()).offset(paging.offset).limit(paging.page_size)
    ).all()
    return make_page([audit_out(*r) for r in rows], total, paging.page, paging.page_size)


@router.get(
    "/verify",
    response_model=VerifyOut,
    summary="Verify the whole hash chain with verify_chain_summary()",
)
def verify(db: DbSession, current: AuthUser) -> VerifyOut:
    if current.role == UserRole.PARTNER:
        raise AppError(403, "Only owners, auditors and admins can verify the chain")
    # Walks every row (SECURITY DEFINER), stops at the first break, returns one row
    r = db.execute(text("SELECT * FROM verify_chain_summary()")).one()
    return VerifyOut(
        valid=r.is_valid,
        total_rows=r.total_rows,
        verified_rows=r.verified_rows,
        first_error=(
            None if r.is_valid else ChainError(log_id=r.first_bad_log_id, message=r.error_msg)
        ),
        checked_at=now(),
    )


@router.get("/stats", summary="Daily event counts per action (for charts)")
def stats(
    db: DbSession, current: AuthUser, days: Annotated[int, Query(ge=1, le=90)] = 14
) -> list[dict]:
    day = func.date_trunc("day", AuditLog.ts)
    rows = db.execute(
        select(day.label("day"), AuditLog.action, func.count().label("n"))
        .where(AuditLog.ts >= func.now() - func.make_interval(0, 0, 0, days))
        .group_by(day, AuditLog.action)
        .order_by(day)
    ).all()
    return [{"day": d.date().isoformat(), "action": a.value, "count": n} for d, a, n in rows]
