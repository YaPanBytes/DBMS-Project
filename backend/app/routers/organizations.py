"""Organizations, users and roles. Admins manage accounts; everyone can look up
organizations (to choose a grantee) and the members of their own organization."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import or_, select

from database.models import Organization, OrgType, Role, User, UserRole

from ..deps import AdminUser, AuthUser, DbSession, Paging
from ..errors import AppError
from ..schemas import (
    OrganizationCreate,
    OrganizationOut,
    OrganizationUpdate,
    Page,
    RoleOut,
    UserCreate,
    UserOut,
    UserUpdate,
    make_page,
)
from ..security import hash_password
from ..services import count, user_out

router = APIRouter(tags=["organizations"])


@router.get("/organizations", response_model=Page[OrganizationOut])
def list_organizations(
    db: DbSession,
    current: AuthUser,
    paging: Paging,
    q: Annotated[str | None, Query(max_length=100, description="Search name/description")] = None,
    type: OrgType | None = None,  # noqa: A002
) -> dict:
    stmt = select(Organization)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Organization.name.ilike(like), Organization.description.ilike(like)))
    if type:
        stmt = stmt.where(Organization.type == type)
    total = count(db, stmt)
    rows = db.scalars(
        stmt.order_by(Organization.name).offset(paging.offset).limit(paging.page_size)
    )
    return make_page(
        [OrganizationOut.model_validate(o) for o in rows], total, paging.page, paging.page_size
    )


@router.get("/organizations/{org_id}", response_model=OrganizationOut)
def get_organization(org_id: UUID, db: DbSession, current: AuthUser) -> Organization:
    org = db.get(Organization, org_id)
    if org is None:
        raise AppError(404, "Organization not found")
    return org


@router.post("/organizations", response_model=OrganizationOut, status_code=201)
def create_organization(body: OrganizationCreate, db: DbSession, admin: AdminUser) -> Organization:
    org = Organization(**body.model_dump())
    db.add(org)
    db.commit()
    return org


@router.patch("/organizations/{org_id}", response_model=OrganizationOut)
def update_organization(
    org_id: UUID, body: OrganizationUpdate, db: DbSession, admin: AdminUser
) -> Organization:
    org = db.get(Organization, org_id)
    if org is None:
        raise AppError(404, "Organization not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(org, k, v)
    db.commit()
    db.refresh(org)
    return org


@router.get("/roles", response_model=list[RoleOut])
def list_roles(db: DbSession, current: AuthUser) -> list[Role]:
    return list(db.scalars(select(Role).order_by(Role.role_id)))


@router.get("/users", response_model=Page[UserOut])
def list_users(
    db: DbSession,
    current: AuthUser,
    paging: Paging,
    q: Annotated[str | None, Query(max_length=100)] = None,
    role: UserRole | None = None,
    org_id: UUID | None = None,
    is_active: bool | None = None,
) -> dict:
    stmt = select(User, Organization).join(Organization, Organization.org_id == User.org_id)
    if current.role != UserRole.ADMIN:  # non-admins only see their own organization
        stmt = stmt.where(User.org_id == current.org_id)
    elif org_id:
        stmt = stmt.where(User.org_id == org_id)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(User.email.ilike(like), User.full_name.ilike(like)))
    if role:
        stmt = stmt.where(
            User.role_id == select(Role.role_id).where(Role.name == role.value).scalar_subquery()
        )
    if is_active is not None:
        stmt = stmt.where(User.is_active == is_active)
    total = count(db, stmt)
    rows = db.execute(
        stmt.order_by(Organization.name, User.email).offset(paging.offset).limit(paging.page_size)
    ).all()
    return make_page([user_out(u, o) for u, o in rows], total, paging.page, paging.page_size)


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, db: DbSession, admin: AdminUser) -> UserOut:
    org = db.get(Organization, body.org_id)
    if org is None:
        raise AppError(422, "Organization not found")
    user = User(
        email=body.email,
        full_name=body.full_name,
        org_id=body.org_id,
        role=body.role,
        password_hash=hash_password(body.password) if body.password else None,
    )
    db.add(user)
    db.commit()
    return user_out(user, org)


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: UUID, body: UserUpdate, db: DbSession, admin: AdminUser) -> UserOut:
    user = db.get(User, user_id)
    if user is None:
        raise AppError(404, "User not found")
    if user.user_id == admin.id and (
        body.is_active is False or (body.role and body.role != UserRole.ADMIN)
    ):
        raise AppError(400, "You cannot deactivate or demote your own account")
    data = body.model_dump(exclude_unset=True)
    if "role" in data:
        user.role = data.pop("role")
    for k, v in data.items():
        setattr(user, k, v)
    db.commit()
    db.refresh(user)
    return user_out(user, db.get(Organization, user.org_id))
