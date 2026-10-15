"""Request dependencies: database session, current user, role-based access."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends, Query, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from database.models import Organization, RevokedToken, User, UserRole

from .db import get_db, set_request_user
from .errors import AppError
from .security import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, csrf_matches, decode_access_token

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Lets the Swagger UI "Authorize" button obtain a bearer token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]


@dataclass
class CurrentUser:
    user: User
    organization: Organization
    claims: dict
    via_cookie: bool

    @property
    def id(self) -> UUID:
        return self.user.user_id

    @property
    def org_id(self) -> UUID:
        return self.user.org_id

    @property
    def role(self) -> UserRole:
        return self.user.role

    @property
    def jti(self) -> UUID:
        return UUID(self.claims["jti"])

    @property
    def expires_at(self) -> datetime:
        return datetime.fromtimestamp(self.claims["exp"], tz=UTC)


def _unauthorized(message: str = "Please sign in") -> AppError:
    return AppError(401, message, code="unauthorized")


def get_current_user(
    request: Request,
    db: DbSession,
    bearer: Annotated[str | None, Depends(oauth2_scheme)] = None,
) -> CurrentUser:
    token, via_cookie = bearer, False
    if not token:
        token = request.cookies.get(SESSION_COOKIE)
        via_cookie = token is not None
    if not token:
        raise _unauthorized()

    try:
        claims = decode_access_token(token)
        user_id, org_id = UUID(claims["sub"]), UUID(claims["org"])
    except (jwt.PyJWTError, ValueError, KeyError) as e:
        raise _unauthorized("Your session is invalid or has expired") from e

    # CSRF: cookie-authenticated state changes must echo the CSRF cookie
    if (
        via_cookie
        and request.method not in SAFE_METHODS
        and not csrf_matches(request.cookies.get(CSRF_COOKIE), request.headers.get(CSRF_HEADER))
    ):
        raise AppError(403, "Missing or invalid CSRF token", code="csrf_failed")

    # From here on every query runs with this user's RLS context
    set_request_user(db, user_id, org_id)

    if db.get(RevokedToken, UUID(claims["jti"])) is not None:
        raise _unauthorized("You have been signed out")
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.org_id != org_id:
        raise _unauthorized("Your account is not active")
    org = db.get(Organization, user.org_id)
    return CurrentUser(user=user, organization=org, claims=claims, via_cookie=via_cookie)


AuthUser = Annotated[CurrentUser, Depends(get_current_user)]


def require_roles(*roles: UserRole) -> Callable[[CurrentUser], CurrentUser]:
    """Dependency factory: allow only users whose role (from the users/roles
    tables) is one of ``roles``."""
    allowed = set(roles)

    def checker(current: AuthUser) -> CurrentUser:
        if current.role not in allowed:
            names = ", ".join(sorted(r.value for r in allowed))
            raise AppError(
                403, f"This action requires one of these roles: {names}", code="forbidden"
            )
        return current

    return checker


OwnerUser = Annotated[CurrentUser, Depends(require_roles(UserRole.OWNER))]
PartnerOrOwner = Annotated[CurrentUser, Depends(require_roles(UserRole.PARTNER, UserRole.OWNER))]
AdminUser = Annotated[CurrentUser, Depends(require_roles(UserRole.ADMIN))]
AuditorOrAdmin = Annotated[CurrentUser, Depends(require_roles(UserRole.AUDITOR, UserRole.ADMIN))]
OwnerOrAuditor = Annotated[CurrentUser, Depends(require_roles(UserRole.OWNER, UserRole.AUDITOR))]


@dataclass
class PageParams:
    page: int
    page_size: int

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def page_params(
    page: Annotated[int, Query(ge=1, description="Page number, starting at 1")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
) -> PageParams:
    return PageParams(page=page, page_size=page_size)


Paging = Annotated[PageParams, Depends(page_params)]


def load_user(db: Session, user_id: UUID) -> User | None:
    return db.scalar(select(User).where(User.user_id == user_id))
