"""Consent grants: list, grant directly, revoke instantly, extend."""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session, aliased

from database.models import ConsentGrant, Dataset, DatasetField, Organization

from ..deps import AuthUser, DbSession, OwnerUser, Paging
from ..errors import AppError
from ..schemas import ConsentCreate, ConsentOut, ExtendIn, Page, RevokeIn, make_page
from ..services import count, grant_status

router = APIRouter(prefix="/consents", tags=["consent"])

Grantor = aliased(Organization)
Grantee = aliased(Organization)


def _base():
    return (
        select(
            ConsentGrant,
            Dataset.title,
            DatasetField.name,
            DatasetField.sensitivity,
            Grantor.name,
            Grantee.name,
        )
        .join(Dataset, Dataset.dataset_id == ConsentGrant.dataset_id, isouter=True)
        .join(DatasetField, DatasetField.field_id == ConsentGrant.field_id, isouter=True)
        .join(Grantor, Grantor.org_id == ConsentGrant.grantor_org_id)
        .join(Grantee, Grantee.org_id == ConsentGrant.grantee_org_id)
    )


def _out(row) -> ConsentOut:
    g, title, fname, sens, grantor, grantee = row
    return ConsentOut(
        grant_id=g.grant_id,
        dataset_id=g.dataset_id,
        dataset_title=title,
        grantor_org_id=g.grantor_org_id,
        grantor_org_name=grantor,
        grantee_org_id=g.grantee_org_id,
        grantee_org_name=grantee,
        field_id=g.field_id,
        field_name=fname,
        sensitivity=sens,
        purpose=g.purpose,
        granted_at=g.granted_at,
        expires_at=g.expires_at,
        revoked_at=g.revoked_at,
        revocation_reason=g.revocation_reason,
        status=grant_status(g),
    )


def _one(db: Session, grant_id: UUID) -> ConsentOut:
    row = db.execute(
        _base().where(ConsentGrant.grant_id == grant_id).execution_options(populate_existing=True)
    ).first()
    if row is None:
        raise AppError(404, "Consent grant not found")
    return _out(row)


@router.get("", response_model=Page[ConsentOut], summary="Grants you gave or received")
def list_consents(
    db: DbSession,
    current: AuthUser,
    paging: Paging,
    status: Literal["active", "expired", "revoked", "all"] = "active",
    direction: Literal["all", "given", "received"] = "all",
    dataset_id: UUID | None = None,
    grantee_org_id: UUID | None = None,
    q: Annotated[
        str | None, Query(max_length=100, description="Search purpose/dataset/field")
    ] = None,
) -> dict:
    stmt = _base()
    if status == "active":
        stmt = stmt.where(ConsentGrant.revoked_at.is_(None), ConsentGrant.expires_at > func.now())
    elif status == "expired":
        stmt = stmt.where(ConsentGrant.revoked_at.is_(None), ConsentGrant.expires_at <= func.now())
    elif status == "revoked":
        stmt = stmt.where(ConsentGrant.revoked_at.is_not(None))
    if direction == "given":
        stmt = stmt.where(ConsentGrant.grantor_org_id == current.org_id)
    elif direction == "received":
        stmt = stmt.where(ConsentGrant.grantee_org_id == current.org_id)
    if dataset_id:
        stmt = stmt.where(ConsentGrant.dataset_id == dataset_id)
    if grantee_org_id:
        stmt = stmt.where(ConsentGrant.grantee_org_id == grantee_org_id)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                ConsentGrant.purpose.ilike(like),
                Dataset.title.ilike(like),
                DatasetField.name.ilike(like),
                Grantee.name.ilike(like),
            )
        )
    total = count(db, stmt)
    rows = db.execute(
        stmt.order_by(ConsentGrant.granted_at.desc(), Dataset.title, DatasetField.ordinal)
        .offset(paging.offset)
        .limit(paging.page_size)
    ).all()
    return make_page([_out(r) for r in rows], total, paging.page, paging.page_size)


@router.post(
    "",
    response_model=list[ConsentOut],
    status_code=201,
    summary="Grant a partner access to fields for a purpose (one grant per field)",
)
def create_consents(body: ConsentCreate, db: DbSession, current: OwnerUser) -> list[ConsentOut]:
    ds = db.get(Dataset, body.dataset_id)
    if ds is None or ds.owner_org_id != current.org_id:
        raise AppError(404, "Dataset not found among your organization's datasets")
    if body.grantee_org_id == current.org_id:
        raise AppError(400, "You cannot grant consent to your own organization")
    if db.get(Organization, body.grantee_org_id) is None:
        raise AppError(422, "Grantee organization not found")
    field_ids = list(dict.fromkeys(body.field_ids))
    valid = set(
        db.scalars(
            select(DatasetField.field_id).where(
                DatasetField.dataset_id == ds.dataset_id, DatasetField.field_id.in_(field_ids)
            )
        )
    )
    if missing := [str(f) for f in field_ids if f not in valid]:
        raise AppError(422, "Some fields do not belong to this dataset", details=missing)
    grants = [
        ConsentGrant(
            grantor_org_id=current.org_id,
            grantee_org_id=body.grantee_org_id,
            dataset_id=ds.dataset_id,
            field_id=f,
            purpose=body.purpose,
            expires_at=body.expires_at,
        )
        for f in field_ids
    ]
    db.add_all(grants)  # grants and their audit entries commit together
    db.commit()
    return [_one(db, g.grant_id) for g in grants]


@router.get("/{grant_id}", response_model=ConsentOut)
def get_consent(grant_id: UUID, db: DbSession, current: AuthUser) -> ConsentOut:
    return _one(db, grant_id)


@router.post(
    "/{grant_id}/revoke",
    response_model=ConsentOut,
    summary="Revoke instantly: the partner's next read is already blocked",
)
def revoke(grant_id: UUID, body: RevokeIn, db: DbSession, current: OwnerUser) -> ConsentOut:
    _one(db, grant_id)
    db.execute(
        text("CALL revoke_grant(:u, :g, :r)"), {"u": current.id, "g": grant_id, "r": body.reason}
    )
    db.commit()
    return _one(db, grant_id)


@router.patch("/{grant_id}", response_model=ConsentOut, summary="Change a grant's expiry")
def extend(grant_id: UUID, body: ExtendIn, db: DbSession, current: OwnerUser) -> ConsentOut:
    grant = db.get(ConsentGrant, grant_id)
    if grant is None or grant.grantor_org_id != current.org_id:
        raise AppError(404, "Consent grant not found")
    if grant.revoked_at is not None:
        raise AppError(400, "Revoked grants cannot be changed; create a new grant instead")
    grant.expires_at = body.expires_at
    db.commit()
    return _one(db, grant_id)
