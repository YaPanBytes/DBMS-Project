"""Authentication: Google OAuth 2.0, local password login, JWT session, logout, /me."""

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from database.models import AuditAction, Organization, RevokedToken, User

from .. import google_oauth, ratelimit
from ..config import get_settings
from ..db import set_request_user
from ..deps import AuthUser, DbSession
from ..errors import AppError
from ..schemas import AuthConfigOut, GoogleCredentialIn, LoginIn, MeOut, OrganizationOut, TokenOut
from ..security import (
    OAUTH_STATE_COOKIE,
    clear_session_cookies,
    create_access_token,
    set_session_cookies,
    verify_password,
)
from ..services import PERMISSIONS, now, record_event, user_out

router = APIRouter(prefix="/auth", tags=["auth"])


def _me(user: User, org: Organization, method: str, expires) -> MeOut:
    return MeOut(
        user=user_out(user, org),
        organization=OrganizationOut.model_validate(org),
        permissions=PERMISSIONS.get(user.role.value, []),
        auth_method=method,
        expires_at=expires,
    )


def _complete_login(db: Session, request: Request, user: User, method: str) -> tuple[str, object]:
    """Record the login in the audit chain and issue a token."""
    set_request_user(db, user.user_id, user.org_id)
    user.last_login = now()
    record_event(db, request, user.user_id, AuditAction.LOGIN, detail=f"login via {method}")
    token, _, expires = create_access_token(user.user_id, user.org_id, user.role.value)
    db.commit()
    return token, expires


def _find_active_user(db: Session, email: str) -> User | None:
    user = db.scalar(select(User).where(User.email == email.lower()))
    return user if user and user.is_active else None


@router.get("/config", response_model=AuthConfigOut, summary="Which sign-in methods are enabled")
def auth_config() -> AuthConfigOut:
    s = get_settings()
    return AuthConfigOut(
        google_enabled=s.google_enabled, password_login_enabled=s.allow_password_login
    )


@router.post("/login", response_model=MeOut, summary="Email + password login (sets session cookie)")
def login(body: LoginIn, request: Request, response: Response, db: DbSession) -> MeOut:
    if not get_settings().allow_password_login:
        raise AppError(403, "Password login is disabled; sign in with Google")
    ratelimit.check_login_allowed(request, body.email)
    user = _find_active_user(db, body.email)
    if not verify_password(body.password, user.password_hash if user else None):
        ratelimit.record_login_failure(request, body.email)
        raise AppError(401, "Incorrect email or password", code="invalid_credentials")
    ratelimit.record_login_success(request, body.email)
    token, expires = _complete_login(db, request, user, "password")
    set_session_cookies(response, token, expires)
    return _me(user, db.get(Organization, user.org_id), "cookie", expires)


@router.post(
    "/token",
    response_model=TokenOut,
    summary="OAuth2 password grant: bearer token for API clients and Swagger",
)
def token(
    form: Annotated[OAuth2PasswordRequestForm, Depends()], request: Request, db: DbSession
) -> TokenOut:
    if not get_settings().allow_password_login:
        raise AppError(403, "Password login is disabled")
    ratelimit.check_login_allowed(request, form.username)
    user = _find_active_user(db, form.username)
    if not verify_password(form.password, user.password_hash if user else None):
        ratelimit.record_login_failure(request, form.username)
        raise AppError(401, "Incorrect email or password", code="invalid_credentials")
    ratelimit.record_login_success(request, form.username)
    access_token, expires = _complete_login(db, request, user, "token")
    return TokenOut(access_token=access_token, expires_at=expires)


def _google_user(db: Session, claims: dict) -> User:
    user = db.scalar(select(User).where(User.google_sub == claims["sub"]))
    if user is None:
        user = _find_active_user(db, claims["email"])
        if user is None:
            raise AppError(
                403,
                "This Google account is not registered. Ask an administrator "
                "to create an account for your email.",
                code="not_registered",
            )
        if user.google_sub and user.google_sub != claims["sub"]:
            raise AppError(403, "This email is linked to a different Google account")
        user.google_sub = claims["sub"]
    if not user.is_active:
        raise AppError(403, "Your account is not active")
    if not user.full_name and claims.get("name"):
        user.full_name = claims["name"]
    return user


@router.get("/google/login", summary="Start Google OAuth 2.0 sign-in (redirect)")
def google_login() -> RedirectResponse:
    s = get_settings()
    if not s.google_enabled:
        raise AppError(404, "Google sign-in is not configured")
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    resp = RedirectResponse(google_oauth.authorization_url(state, nonce), status_code=302)
    resp.set_cookie(
        OAUTH_STATE_COOKIE,
        f"{state}.{nonce}",
        max_age=600,
        httponly=True,
        secure=s.cookie_secure,
        samesite="lax",
        path="/",
    )
    return resp


@router.get("/google/callback", summary="Google OAuth 2.0 redirect target")
def google_callback(
    request: Request,
    db: DbSession,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    s = get_settings()
    fail = f"{s.frontend_url}/login?error="
    stored = request.cookies.get(OAUTH_STATE_COOKIE, "")
    expected_state, _, nonce = stored.partition(".")
    if error or not code or not state or not secrets.compare_digest(state, expected_state or "-"):
        return RedirectResponse(fail + "google_cancelled", status_code=302)
    try:
        claims = google_oauth.verify_id_token(google_oauth.exchange_code(code), nonce=nonce)
        user = _google_user(db, claims)
    except google_oauth.GoogleAuthError:
        return RedirectResponse(fail + "google_failed", status_code=302)
    except AppError as e:
        return RedirectResponse(fail + e.code, status_code=302)
    token, expires = _complete_login(db, request, user, "google")
    resp = RedirectResponse(f"{s.frontend_url}/", status_code=302)
    set_session_cookies(resp, token, expires)
    resp.delete_cookie(OAUTH_STATE_COOKIE, path="/")
    return resp


@router.post(
    "/google",
    response_model=MeOut,
    summary="Sign in with a Google ID token (Google Identity Services button)",
)
def google_credential(
    body: GoogleCredentialIn, request: Request, response: Response, db: DbSession
) -> MeOut:
    if not get_settings().google_enabled:
        raise AppError(404, "Google sign-in is not configured")
    try:
        claims = google_oauth.verify_id_token(body.credential)
    except google_oauth.GoogleAuthError as e:
        raise AppError(401, str(e), code="google_failed") from e
    user = _google_user(db, claims)
    token, expires = _complete_login(db, request, user, "google")
    set_session_cookies(response, token, expires)
    return _me(user, db.get(Organization, user.org_id), "cookie", expires)


@router.post("/logout", status_code=204, summary="Sign out: revoke this token and clear cookies")
def logout(current: AuthUser, request: Request, db: DbSession) -> Response:
    db.add(RevokedToken(jti=current.jti, user_id=current.id, expires_at=current.expires_at))
    record_event(db, request, current.id, AuditAction.LOGOUT)
    db.commit()
    response = Response(status_code=204)
    clear_session_cookies(response)
    return response


@router.get("/me", response_model=MeOut, summary="The signed-in user")
def me(current: AuthUser) -> MeOut:
    return _me(
        current.user,
        current.organization,
        "cookie" if current.via_cookie else "bearer",
        current.expires_at,
    )
