"""Datasets: catalogue, fields, upload + PII scan, publish, data load and the
consent-checked, audited read path."""

import json
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, File, Query, Request, UploadFile
from sqlalchemy import and_, exists, func, or_, select, text
from sqlalchemy.orm import Session

from ai.pii import scan_rows
from database.models import (
    AuditAction,
    ConsentGrant,
    Dataset,
    DatasetField,
    DatasetStatus,
    DataType,
    Organization,
    SensitivityLevel,
    UserRole,
)

from ..csv_utils import parse_csv
from ..deps import AuthUser, CurrentUser, DbSession, OwnerUser, Paging
from ..errors import AppError
from ..schemas import (
    BulkFieldsIn,
    ColumnSuggestion,
    DataPage,
    DatasetCreate,
    DatasetDetail,
    DatasetOut,
    DatasetUpdate,
    FieldCreate,
    FieldOut,
    FieldUpdate,
    GrantSummary,
    IngestResult,
    Page,
    UploadPreview,
    make_page,
)
from ..services import count, record_event

router = APIRouter(prefix="/datasets", tags=["datasets"])


def _active_grant_clause(org_id: UUID):
    return and_(
        ConsentGrant.grantee_org_id == org_id,
        ConsentGrant.revoked_at.is_(None),
        ConsentGrant.expires_at > func.now(),
    )


def _get_dataset(db: Session, dataset_id: UUID) -> Dataset:
    ds = db.get(Dataset, dataset_id)  # RLS: invisible datasets look like missing ones
    if ds is None:
        raise AppError(404, "Dataset not found")
    return ds


def _owned_dataset(db: Session, dataset_id: UUID, current: CurrentUser) -> Dataset:
    ds = _get_dataset(db, dataset_id)
    if ds.owner_org_id != current.org_id:
        raise AppError(403, "Only the owning organization can change this dataset")
    return ds


def _dataset_out(
    ds: Dataset, org_name: str | None, field_count: int, has_access: bool, current: CurrentUser
) -> DatasetOut:
    return DatasetOut(
        dataset_id=ds.dataset_id,
        title=ds.title,
        description=ds.description,
        category=ds.category,
        status=ds.status,
        version=ds.version,
        owner_org_id=ds.owner_org_id,
        owner_org_name=org_name,
        created_at=ds.created_at,
        updated_at=ds.updated_at,
        field_count=field_count,
        is_owner=ds.owner_org_id == current.org_id,
        has_access=has_access,
    )


@router.get("", response_model=Page[DatasetOut], summary="List datasets visible to you")
def list_datasets(
    db: DbSession,
    current: AuthUser,
    paging: Paging,
    q: Annotated[str | None, Query(max_length=100, description="Search title/description")] = None,
    status: DatasetStatus | None = None,
    category: Annotated[str | None, Query(max_length=100)] = None,
    scope: Annotated[
        Literal["all", "mine", "shared"],
        Query(description="mine = owned by your organization, shared = you hold an active grant"),
    ] = "all",
    sort: Literal["title", "-updated_at", "updated_at"] = "-updated_at",
) -> dict:
    field_count = (
        select(func.count(DatasetField.field_id))
        .where(DatasetField.dataset_id == Dataset.dataset_id)
        .scalar_subquery()
    )
    has_access = exists().where(
        ConsentGrant.dataset_id == Dataset.dataset_id, _active_grant_clause(current.org_id)
    )
    stmt = select(Dataset, Organization.name, field_count, has_access).join(
        Organization, Organization.org_id == Dataset.owner_org_id
    )
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                Dataset.title.ilike(like),
                Dataset.description.ilike(like),
                Dataset.category.ilike(like),
            )
        )
    if status:
        stmt = stmt.where(Dataset.status == status)
    if category:
        stmt = stmt.where(Dataset.category == category)
    if scope == "mine":
        stmt = stmt.where(Dataset.owner_org_id == current.org_id)
    elif scope == "shared":
        stmt = stmt.where(has_access)
    order = {
        "title": Dataset.title,
        "updated_at": Dataset.updated_at,
        "-updated_at": Dataset.updated_at.desc(),
    }[sort]
    total = count(db, stmt)
    rows = db.execute(stmt.order_by(order).offset(paging.offset).limit(paging.page_size)).all()
    items = [_dataset_out(ds, name, n or 0, bool(acc), current) for ds, name, n, acc in rows]
    return make_page(items, total, paging.page, paging.page_size)


@router.get("/categories", response_model=list[str])
def list_categories(db: DbSession, current: AuthUser) -> list[str]:
    return [
        c for c in db.scalars(select(Dataset.category).distinct().order_by(Dataset.category)) if c
    ]


@router.post("", response_model=DatasetOut, status_code=201, summary="Register a dataset")
def create_dataset(body: DatasetCreate, db: DbSession, current: OwnerUser) -> DatasetOut:
    ds = Dataset(owner_org_id=current.org_id, **body.model_dump())
    db.add(ds)
    db.commit()
    return _dataset_out(ds, current.organization.name, 0, False, current)


@router.get("/{dataset_id}", response_model=DatasetDetail)
def get_dataset(dataset_id: UUID, db: DbSession, current: AuthUser) -> DatasetDetail:
    ds = _get_dataset(db, dataset_id)
    org = db.get(Organization, ds.owner_org_id)
    fields = list(
        db.scalars(
            select(DatasetField)
            .where(DatasetField.dataset_id == dataset_id)
            .order_by(DatasetField.ordinal, DatasetField.name)
        )
    )
    grants = db.execute(
        select(ConsentGrant, DatasetField.name)
        .join(DatasetField, DatasetField.field_id == ConsentGrant.field_id)
        .where(ConsentGrant.dataset_id == dataset_id, _active_grant_clause(current.org_id))
        .order_by(ConsentGrant.purpose, DatasetField.ordinal)
    ).all()
    is_owner = ds.owner_org_id == current.org_id
    row_count = None
    if is_owner or grants:
        row_count = db.scalar(text("SELECT dataset_row_count(:d)"), {"d": dataset_id})
    out = _dataset_out(ds, org.name if org else None, len(fields), bool(grants), current)
    return DatasetDetail(
        **out.model_dump(),
        fields=[FieldOut.model_validate(f) for f in fields],
        my_grants=[
            GrantSummary(
                grant_id=g.grant_id,
                field_id=g.field_id,
                field_name=name,
                purpose=g.purpose,
                expires_at=g.expires_at,
            )
            for g, name in grants
        ],
        row_count=row_count,
    )


@router.patch("/{dataset_id}", response_model=DatasetOut)
def update_dataset(
    dataset_id: UUID, body: DatasetUpdate, db: DbSession, current: OwnerUser
) -> DatasetOut:
    ds = _owned_dataset(db, dataset_id, current)
    data = body.model_dump(exclude_unset=True)
    if data.get("status") == "draft" and ds.status == DatasetStatus.PUBLISHED:
        raise AppError(400, "A published dataset can be archived but not moved back to draft")
    for k, v in data.items():
        setattr(ds, k, DatasetStatus(v) if k == "status" else v)
    if data:
        ds.version += 1
    db.commit()
    db.refresh(ds)
    n = db.scalar(select(func.count()).where(DatasetField.dataset_id == ds.dataset_id)) or 0
    return _dataset_out(ds, current.organization.name, n, False, current)


# ------------------------------------------------------------------ fields


def _next_ordinal(db: Session, dataset_id: UUID) -> int:
    return (
        db.scalar(
            select(func.max(DatasetField.ordinal)).where(DatasetField.dataset_id == dataset_id)
        )
        or -1
    ) + 1


def _check_editable(ds: Dataset) -> None:
    if ds.status == DatasetStatus.ARCHIVED:
        raise AppError(400, "Archived datasets cannot be changed")


@router.post("/{dataset_id}/fields", response_model=FieldOut, status_code=201)
def add_field(
    dataset_id: UUID, body: FieldCreate, db: DbSession, current: OwnerUser
) -> DatasetField:
    ds = _owned_dataset(db, dataset_id, current)
    _check_editable(ds)
    data = body.model_dump()
    if data["ordinal"] is None:
        data["ordinal"] = _next_ordinal(db, dataset_id)
    field = DatasetField(dataset_id=dataset_id, **data)
    db.add(field)
    db.commit()
    return field


@router.post(
    "/{dataset_id}/fields/bulk",
    response_model=list[FieldOut],
    status_code=201,
    summary="Create several fields at once (e.g. after reviewing PII suggestions)",
)
def add_fields(
    dataset_id: UUID, body: BulkFieldsIn, db: DbSession, current: OwnerUser
) -> list[DatasetField]:
    ds = _owned_dataset(db, dataset_id, current)
    _check_editable(ds)
    names = [f.name for f in body.fields]
    if len(set(names)) != len(names):
        raise AppError(422, "Field names must be unique")
    start = _next_ordinal(db, dataset_id)
    created = []
    for i, f in enumerate(body.fields):
        data = f.model_dump()
        data["ordinal"] = data["ordinal"] if data["ordinal"] is not None else start + i
        field = DatasetField(dataset_id=dataset_id, **data)
        db.add(field)
        created.append(field)
    db.commit()
    return created


@router.patch("/{dataset_id}/fields/{field_id}", response_model=FieldOut)
def update_field(
    dataset_id: UUID, field_id: UUID, body: FieldUpdate, db: DbSession, current: OwnerUser
) -> DatasetField:
    ds = _owned_dataset(db, dataset_id, current)
    _check_editable(ds)
    field = db.get(DatasetField, field_id)
    if field is None or field.dataset_id != dataset_id:
        raise AppError(404, "Field not found")
    data = body.model_dump(exclude_unset=True)
    if (
        "is_encrypted" in data
        and data["is_encrypted"] != field.is_encrypted
        and ds.status == DatasetStatus.PUBLISHED
    ):
        raise AppError(400, "Encryption cannot be changed after the dataset is published")
    for k, v in data.items():
        setattr(field, k, v)
    db.commit()
    db.refresh(field)
    return field


@router.delete("/{dataset_id}/fields/{field_id}", status_code=204)
def delete_field(dataset_id: UUID, field_id: UUID, db: DbSession, current: OwnerUser) -> None:
    ds = _owned_dataset(db, dataset_id, current)
    if ds.status != DatasetStatus.DRAFT:
        raise AppError(400, "Fields can only be removed while the dataset is a draft")
    field = db.get(DatasetField, field_id)
    if field is None or field.dataset_id != dataset_id:
        raise AppError(404, "Field not found")
    db.delete(field)
    db.commit()


# ------------------------------------------------------------------ upload / publish / data


@router.post(
    "/{dataset_id}/upload/preview",
    response_model=UploadPreview,
    summary="Scan a CSV for PII and suggest field types and sensitivity",
)
async def upload_preview(
    dataset_id: UUID,
    request: Request,
    db: DbSession,
    current: OwnerUser,
    file: Annotated[UploadFile, File(description="UTF-8 CSV file")],
) -> UploadPreview:
    _owned_dataset(db, dataset_id, current)
    headers, names, rows = parse_csv(await file.read())
    report = scan_rows(rows)
    by_name = {f.name: f for f in report.fields}
    columns = []
    for original, name in zip(headers, names, strict=True):
        f = by_name.get(name)
        sens = f.suggested_sensitivity if f else "low"
        dtype = f.inferred_type if f else "text"
        columns.append(
            ColumnSuggestion(
                name=name,
                original_name=original,
                inferred_type=DataType(dtype),
                suggested_sensitivity=SensitivityLevel(sens),
                confidence=f.confidence if f else 0.3,
                detected=f.detected if f else {},
                reasons=f.reasons if f else [],
                masked_preview=f.masked_preview if f else [],
                suggest_encryption=sens == "pii" and dtype == "text",
            )
        )
    record_event(
        db,
        request,
        current.id,
        AuditAction.PII_SCAN,
        dataset_id=dataset_id,
        rows=report.rows_scanned,
        detail=f"pii scan of {file.filename or 'upload'}",
    )
    db.commit()
    return UploadPreview(row_count=len(rows), columns=columns, ner_available=report.ner_available)


@router.post(
    "/{dataset_id}/publish",
    response_model=DatasetOut,
    summary="Publish: create the protected data table and masked view",
)
def publish(dataset_id: UUID, db: DbSession, current: OwnerUser) -> DatasetOut:
    _owned_dataset(db, dataset_id, current)
    db.execute(text("SELECT publish_dataset(:d)"), {"d": dataset_id})
    db.commit()
    ds = db.get(Dataset, dataset_id)
    db.refresh(ds)
    n = db.scalar(select(func.count()).where(DatasetField.dataset_id == dataset_id)) or 0
    return _dataset_out(ds, current.organization.name, n, False, current)


@router.post(
    "/{dataset_id}/rows",
    response_model=IngestResult,
    summary="Load rows from a CSV into a published dataset (columns matched by name)",
)
async def upload_rows(
    dataset_id: UUID,
    db: DbSession,
    current: OwnerUser,
    file: Annotated[UploadFile, File(description="UTF-8 CSV file")],
) -> IngestResult:
    ds = _owned_dataset(db, dataset_id, current)
    if ds.status != DatasetStatus.PUBLISHED:
        raise AppError(400, "Publish the dataset before loading data")
    _, names, rows = parse_csv(await file.read())
    known = set(db.scalars(select(DatasetField.name).where(DatasetField.dataset_id == dataset_id)))
    if not known & set(names):
        raise AppError(422, "None of the CSV columns match the dataset's fields")
    loaded = db.scalar(
        text("SELECT ingest_dataset_rows(:d, CAST(:rows AS jsonb))"),
        {"d": dataset_id, "rows": json.dumps(rows)},
    )
    total = db.scalar(text("SELECT dataset_row_count(:d)"), {"d": dataset_id})
    db.commit()
    return IngestResult(rows_loaded=loaded or 0, total_rows=total or 0)


@router.get(
    "/{dataset_id}/data",
    response_model=DataPage,
    summary="Read rows (owners: everything; partners: consented fields for a purpose)",
)
def read_data(
    dataset_id: UUID,
    db: DbSession,
    current: AuthUser,
    paging: Paging,
    purpose: Annotated[
        str | None, Query(max_length=500, description="Required for partners")
    ] = None,
) -> DataPage:
    ds = _get_dataset(db, dataset_id)
    is_owner = ds.owner_org_id == current.org_id
    if not is_owner and current.role == UserRole.AUDITOR:
        raise AppError(403, "Auditors review the audit trail, not dataset contents")
    fields = list(
        db.scalars(
            select(DatasetField)
            .where(DatasetField.dataset_id == dataset_id)
            .order_by(DatasetField.ordinal, DatasetField.name)
        )
    )
    rows = list(
        db.scalars(
            text("SELECT access_dataset(:d, :p, :lim, :off)"),
            {
                "d": dataset_id,
                "p": None if is_owner else purpose,
                "lim": paging.page_size,
                "off": paging.offset,
            },
        )
    )
    total = db.scalar(text("SELECT dataset_row_count(:d)"), {"d": dataset_id}) or 0
    db.commit()  # persist the audit entry written by access_dataset

    if is_owner:
        visible = [f.name for f in fields]
    else:
        granted = set(
            db.scalars(
                select(ConsentGrant.field_id).where(
                    ConsentGrant.dataset_id == dataset_id,
                    ConsentGrant.purpose == purpose,
                    _active_grant_clause(current.org_id),
                )
            )
        )
        visible = [f.name for f in fields if f.field_id in granted]
    columns = ["row_id"] + [f.name for f in fields]
    return DataPage(
        columns=columns,
        rows=rows,
        total=total,
        page=paging.page,
        page_size=paging.page_size,
        purpose=purpose if not is_owner else None,
        visible_fields=visible,
        masked_fields=[f.name for f in fields if f.name not in visible],
    )


@router.get(
    "/{dataset_id}/purposes",
    response_model=list[str],
    summary="Purposes for which your organization holds active grants on this dataset",
)
def my_purposes(dataset_id: UUID, db: DbSession, current: AuthUser) -> list[str]:
    _get_dataset(db, dataset_id)
    return list(
        db.scalars(
            select(ConsentGrant.purpose)
            .distinct()
            .where(ConsentGrant.dataset_id == dataset_id, _active_grant_clause(current.org_id))
            .order_by(ConsentGrant.purpose)
        )
    )
