"""Anomaly alerts: review, resolve, one-click revoke, and run the detector."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import and_, func, select, text

from database.models import (
    AlertDetector,
    AlertStatus,
    AnomalyAlert,
    ConsentGrant,
    Dataset,
    Organization,
    User,
)

from ..deps import AuditorOrAdmin, AuthUser, DbSession, OwnerUser, Paging
from ..errors import AppError
from ..schemas import AlertOut, AlertRevokeResult, AlertUpdate, DetectorRunOut, Page, make_page
from ..services import count, now

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _active_grants_subquery():
    return (
        select(func.count(ConsentGrant.grant_id))
        .where(
            ConsentGrant.dataset_id == AnomalyAlert.dataset_id,
            ConsentGrant.grantee_org_id == User.org_id,
            ConsentGrant.revoked_at.is_(None),
            ConsentGrant.expires_at > func.now(),
        )
        .scalar_subquery()
    )


def alert_query():
    return (
        select(
            AnomalyAlert, User.email, Organization.name, Dataset.title, _active_grants_subquery()
        )
        .join(User, User.user_id == AnomalyAlert.user_id)
        .join(Organization, Organization.org_id == User.org_id)
        .join(Dataset, Dataset.dataset_id == AnomalyAlert.dataset_id, isouter=True)
    )


def alert_out(row) -> AlertOut:
    a, email, org, title, grants = row
    return AlertOut(
        alert_id=a.alert_id,
        user_id=a.user_id,
        user_email=email,
        user_org_name=org,
        dataset_id=a.dataset_id,
        dataset_title=title,
        score=a.score,
        reason=a.reason,
        features=a.features,
        detector=a.detector,
        status=a.status,
        created_at=a.created_at,
        resolved_at=a.resolved_at,
        active_grants=grants or 0,
    )


@router.get(
    "", response_model=Page[AlertOut], summary="Alerts on your datasets (auditors: all alerts)"
)
def list_alerts(
    db: DbSession,
    current: AuthUser,
    paging: Paging,
    status: AlertStatus | None = None,
    detector: AlertDetector | None = None,
    dataset_id: UUID | None = None,
    min_score: Annotated[float | None, Query(ge=0, le=1)] = None,
) -> dict:
    stmt = alert_query()
    if status:
        stmt = stmt.where(AnomalyAlert.status == status)
    if detector:
        stmt = stmt.where(AnomalyAlert.detector == detector)
    if dataset_id:
        stmt = stmt.where(AnomalyAlert.dataset_id == dataset_id)
    if min_score is not None:
        stmt = stmt.where(AnomalyAlert.score >= min_score)
    total = count(db, stmt)
    rows = db.execute(
        stmt.order_by(AnomalyAlert.created_at.desc(), AnomalyAlert.score.desc())
        .offset(paging.offset)
        .limit(paging.page_size)
    ).all()
    return make_page([alert_out(r) for r in rows], total, paging.page, paging.page_size)


def _one(db, alert_id: UUID) -> AlertOut:
    row = db.execute(
        alert_query()
        .where(AnomalyAlert.alert_id == alert_id)
        .execution_options(populate_existing=True)
    ).first()
    if row is None:
        raise AppError(404, "Alert not found")
    return alert_out(row)


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: UUID, db: DbSession, current: AuthUser) -> AlertOut:
    return _one(db, alert_id)


@router.patch("/{alert_id}", response_model=AlertOut, summary="Change status (investigate/resolve)")
def update_alert(alert_id: UUID, body: AlertUpdate, db: DbSession, current: AuthUser) -> AlertOut:
    alert = db.get(AnomalyAlert, alert_id)
    if alert is None:
        raise AppError(404, "Alert not found")
    alert.status = body.status
    if body.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
        alert.resolved_at, alert.resolved_by = now(), current.id
    else:
        alert.resolved_at, alert.resolved_by = None, None
    db.commit()  # RLS: only the dataset's owners and auditors may update
    return _one(db, alert_id)


@router.post(
    "/{alert_id}/revoke-grants",
    response_model=AlertRevokeResult,
    summary="One click: revoke every active grant the flagged user's organization holds on the dataset",
)
def revoke_from_alert(alert_id: UUID, db: DbSession, current: OwnerUser) -> AlertRevokeResult:
    alert = db.get(AnomalyAlert, alert_id)
    if alert is None or alert.dataset_id is None:
        raise AppError(404, "Alert not found")
    user = db.get(User, alert.user_id)
    grant_ids = list(
        db.scalars(
            select(ConsentGrant.grant_id).where(
                and_(
                    ConsentGrant.dataset_id == alert.dataset_id,
                    ConsentGrant.grantee_org_id == user.org_id,
                    ConsentGrant.grantor_org_id == current.org_id,
                    ConsentGrant.revoked_at.is_(None),
                )
            )
        )
    )
    for gid in grant_ids:
        db.execute(
            text("CALL revoke_grant(:u, :g, :r)"),
            {"u": current.id, "g": gid, "r": f"Revoked after anomaly alert {alert_id}"},
        )
    alert.status, alert.resolved_at, alert.resolved_by = AlertStatus.RESOLVED, now(), current.id
    db.commit()
    return AlertRevokeResult(revoked_grants=len(grant_ids))


@router.post(
    "/run-detector",
    response_model=DetectorRunOut,
    summary="Score recent access with the Isolation Forest and write new alerts",
)
def run_detector(current: AuditorOrAdmin) -> DetectorRunOut:
    from ai.anomaly import detect_and_store

    from ..db import get_engine

    # The detector needs the whole audit history, so it runs on a service
    # connection (not the request's RLS-restricted session).
    summary = detect_and_store(get_engine(), save_model=False)
    return DetectorRunOut(**{k: summary.get(k) for k in DetectorRunOut.model_fields})
