"""Tokens, cookies, CSRF and password hashing.

Token handling:
* The JWT is delivered in an **httpOnly** cookie (``cl_session``), so page
  JavaScript can never read it; ``Secure`` in production, ``SameSite=Lax``.
* Cookie-authenticated requests that change state must echo the
  ``cl_csrf`` cookie in an ``X-CSRF-Token`` header (double-submit pattern).
* API clients (and the Swagger "Authorize" button) can instead send
  ``Authorization: Bearer <token>`` obtained from ``POST /api/auth/token``.
* Every token has a ``jti``; logout records it in ``revoked_tokens`` so the
  token stops working immediately.
"""

import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import bcrypt
import jwt
from fastapi import Response

from .config import get_settings

SESSION_COOKIE = "cl_session"
CSRF_COOKIE = "cl_csrf"
CSRF_HEADER = "X-CSRF-Token"
OAUTH_STATE_COOKIE = "cl_oauth_state"

# A real bcrypt hash compared when the user does not exist, so login timing
# does not reveal which emails are registered.
_DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt()).decode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str | None) -> bool:
    candidate = (password_hash or _DUMMY_HASH).encode("ascii")
    try:
        ok = bcrypt.checkpw(password.encode("utf-8"), candidate)
    except ValueError:
        return False
    return ok and password_hash is not None


def create_access_token(user_id: UUID, org_id: UUID, role: str) -> tuple[str, UUID, datetime]:
    s = get_settings()
    now = datetime.now(UTC)
    jti = uuid4()
    expires = now + timedelta(minutes=s.jwt_expire_minutes)
    payload = {
        "sub": str(user_id),
        "org": str(org_id),
        "role": role,
        "jti": str(jti),
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "typ": "access",
    }
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm), jti, expires


def decode_access_token(token: str) -> dict[str, Any]:
    s = get_settings()
    claims = jwt.decode(
        token,
        s.jwt_secret,
        algorithms=[s.jwt_algorithm],
        options={"require": ["sub", "org", "jti", "exp", "iat"]},
    )
    if claims.get("typ") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return claims


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_matches(cookie_value: str | None, header_value: str | None) -> bool:
    return bool(cookie_value and header_value and hmac.compare_digest(cookie_value, header_value))


def set_session_cookies(response: Response, token: str, expires: datetime) -> str:
    s = get_settings()
    max_age = int((expires - datetime.now(UTC)).total_seconds())
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max_age,
        httponly=True,
        secure=s.cookie_secure,
        samesite=s.cookie_samesite,
        path="/",
    )
    csrf = new_csrf_token()
    # readable by the frontend so it can echo it in X-CSRF-Token
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=max_age,
        httponly=False,
        secure=s.cookie_secure,
        samesite=s.cookie_samesite,
        path="/",
    )
    return csrf


def clear_session_cookies(response: Response) -> None:
    s = get_settings()
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/", secure=s.cookie_secure, samesite=s.cookie_samesite)
