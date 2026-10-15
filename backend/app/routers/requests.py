"""Access requests: partners ask, owners approve (optionally narrowing) or deny."""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session, aliased

from database.models import AccessRequest, Dataset, DatasetField, Organization, RequestStatus, User

from ..deps import AuthUser, DbSession, OwnerUser, Paging, PartnerOrOwner
from ..errors import AppError
from ..schemas import ApproveIn, DenyIn, FieldRef, Page, RequestCreate, RequestOut, make_page
from ..services import count

router = APIRouter(prefix="/requests", tags=["requests"])

Owner = aliased(Organization)
Grantee = aliased(Organization)
Requester = aliased(User)
Decider = aliased(User)


def _base():
    return (
        select(
            AccessRequest,
            Dataset.title,
            Dataset.owner_org_id,
            Owner.name,
            Grantee.name,
            Requester.email,
            Decider.email,
        )
        .join(Dataset, Dataset.dataset_id == AccessRequest.dataset_id, isouter=True)
        .join(Owner, Owner.org_id == Dataset.owner_org_id, isouter=True)
        .join(Grantee, Grantee.org_id == AccessRequest.grantee_org_id)
        .join(Requester, Requester.user_id == AccessRequest.requested_by, isouter=True)
        .join(Decider, Decider.user_id == AccessRequest.decided_by, isouter=True)
    )


def _outs(db: Session, rows) -> list[RequestOut]:
    ids = {f for r in rows for f in r[0].field_ids}
    fields = (
        {
            f.field_id: f
            for f in db.scalars(select(DatasetField).where(DatasetField.field_id.in_(ids)))
        }
        if ids
        else {}
    )
    out = []
    for req, title, owner_id, owner, grantee, req_email, dec_email in rows:
        out.append(
            RequestOut(
                request_id=req.request_id,
                dataset_id=req.dataset_id,
                dataset_title=title,
                owner_org_id=owner_id,
                owner_org_name=owner,
                grantee_org_id=req.grantee_org_id,
                grantee_org_name=grantee,
                requested_by_email=req_email,
                fields=[
                    FieldRef(
                        field_id=f,
                        name=getattr(fields.get(f), "name", None),
                        sensitivity=getattr(fields.get(f), "sensitivity", None),
                    )
                    for f in req.field_ids
                ],
                purpose=req.purpose,
                requested_expires_at=req.requested_expires_at,
                status=req.status,
                decided_by_email=dec_email,
                decided_at=req.decided_at,
                decision_note=req.decision_note,
                created_at=req.created_at,
            )
        )
    return out


def _one(db: Session, request_id: UUID) -> RequestOut:
    row = db.execute(
        _base()
        .where(AccessRequest.request_id == request_id)
        .execution_options(populate_existing=True)
    ).first()
    if row is None:
        raise AppError(404, "Access request not found")
    return _outs(db, [row])[0]


@router.get("", response_model=Page[RequestOut])
def list_requests(
    db: DbSession,
    current: AuthUser,
    paging: Paging,
    status: RequestStatus | None = None,
    direction: Annotated[
        Literal["all", "incoming", "outgoing"],
        Query(description="incoming = requests for your datasets, outgoing = requests you made"),
    ] = "all",
    dataset_id: UUID | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
) -> dict:
    stmt = _base()
    if status:
        stmt = stmt.where(AccessRequest.status == status)
    if direction == "incoming":
        stmt = stmt.where(Dataset.owner_org_id == current.org_id)
    elif direction == "outgoing":
        stmt = stmt.where(AccessRequest.grantee_org_id == current.org_id)
    if dataset_id:
        stmt = stmt.where(AccessRequest.dataset_id == dataset_id)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                AccessRequest.purpose.ilike(like),
                Dataset.title.ilike(like),
                Grantee.name.ilike(like),
            )
        )
    total = count(db, stmt)
    rows = db.execute(
        stmt.order_by(AccessRequest.created_at.desc()).offset(paging.offset).limit(paging.page_size)
    ).all()
    return make_page(_outs(db, rows), total, paging.page, paging.page_size)


@router.post(
    "",
    response_model=RequestOut,
    status_code=201,
    summary="Request access to fields of a published dataset (stored procedure)",
)
def create_request(body: RequestCreate, db: DbSession, current: PartnerOrOwner) -> RequestOut:
    db.execute(
        text("CALL request_access(:u, :d, CAST(:f AS uuid[]), :p, :e)"),
        {
            "u": current.id,
            "d": body.dataset_id,
            "f": [str(f) for f in dict.fromkeys(body.field_ids)],
            "p": body.purpose,
            "e": body.expires_at,
        },
    )
    request_id = db.scalar(
        select(AccessRequest.request_id)
        .where(AccessRequest.requested_by == current.id)
        .order_by(AccessRequest.created_at.desc())
        .limit(1)
    )
    db.commit()
    return _one(db, request_id)


@router.get("/{request_id}", response_model=RequestOut)
def get_request(request_id: UUID, db: DbSession, current: AuthUser) -> RequestOut:
    return _one(db, request_id)


@router.post(
    "/{request_id}/approve",
    response_model=RequestOut,
    summary="Approve, optionally narrowing fields, purpose wording or expiry",
)
def approve(request_id: UUID, body: ApproveIn, db: DbSession, current: OwnerUser) -> RequestOut:
    req = db.get(AccessRequest, request_id)
    if req is None:
        raise AppError(404, "Access request not found")
    db.execute(
        text("CALL approve_access_request(:u, :r, CAST(:f AS uuid[]), :p, :e, :n)"),
        {
            "u": current.id,
            "r": request_id,
            "f": [str(f) for f in (body.field_ids or req.field_ids)],
            "p": body.purpose or req.purpose,
            "e": body.expires_at or req.requested_expires_at,
            "n": body.note,
        },
    )
    db.commit()
    return _one(db, request_id)


@router.post("/{request_id}/deny", response_model=RequestOut)
def deny(request_id: UUID, body: DenyIn, db: DbSession, current: OwnerUser) -> RequestOut:
    _one(db, request_id)
    db.execute(
        text("CALL deny_access_request(:u, :r, :n)"),
        {"u": current.id, "r": request_id, "n": body.note},
    )
    db.commit()
    return _one(db, request_id)
