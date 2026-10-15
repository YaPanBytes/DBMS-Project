"""Dashboard summary for the signed-in user (everything is RLS-filtered)."""

from fastapi import APIRouter
from sqlalchemy import func, select

from database.models import (
    AccessRequest,
    AlertStatus,
    AnomalyAlert,
    AuditLog,
    ConsentGrant,
    Dataset,
    RequestStatus,
)

from ..deps import AuthUser, DbSession
from ..schemas import DashboardOut
from .alerts import alert_out, alert_query
from .audit import audit_out, audit_query

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardOut)
def dashboard(db: DbSession, current: AuthUser) -> DashboardOut:
    org = current.org_id
    active = (ConsentGrant.revoked_at.is_(None), ConsentGrant.expires_at > func.now())

    def n(stmt) -> int:
        return db.scalar(stmt) or 0

    return DashboardOut(
        role=current.role,
        datasets_visible=n(select(func.count()).select_from(Dataset)),
        datasets_owned=n(select(func.count()).where(Dataset.owner_org_id == org)),
        consents_given_active=n(
            select(func.count()).where(ConsentGrant.grantor_org_id == org, *active)
        ),
        consents_received_active=n(
            select(func.count()).where(ConsentGrant.grantee_org_id == org, *active)
        ),
        requests_incoming_pending=n(
            select(func.count())
            .select_from(AccessRequest)
            .join(Dataset, Dataset.dataset_id == AccessRequest.dataset_id)
            .where(Dataset.owner_org_id == org, AccessRequest.status == RequestStatus.PENDING)
        ),
        requests_outgoing_pending=n(
            select(func.count()).where(
                AccessRequest.grantee_org_id == org, AccessRequest.status == RequestStatus.PENDING
            )
        ),
        alerts_open=n(
            select(func.count()).where(
                AnomalyAlert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING])
            )
        ),
        audit_events_24h=n(
            select(func.count()).where(AuditLog.ts >= func.now() - func.make_interval(0, 0, 0, 1))
        ),
        recent_audit=[
            audit_out(*r)
            for r in db.execute(audit_query().order_by(AuditLog.seq.desc()).limit(8)).all()
        ],
        recent_alerts=[
            alert_out(r)
            for r in db.execute(
                alert_query()
                .where(AnomalyAlert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING]))
                .order_by(AnomalyAlert.score.desc())
                .limit(5)
            ).all()
        ],
    )
