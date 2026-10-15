"""Google OAuth 2.0 / OpenID Connect helpers.

Two ways to sign in with Google are supported:
* Authorization-code flow (server side, uses GOOGLE_CLIENT_SECRET):
  /api/auth/google/login -> Google -> /api/auth/google/callback
* Google Identity Services button: the browser posts the ID token
  ("credential") to /api/auth/google.
Either way the ID token's signature, audience, issuer and expiry are verified
with Google's public keys before the user is matched by email.
"""

from typing import Any
from urllib.parse import urlencode

import httpx

from .config import get_settings

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"


class GoogleAuthError(Exception):
    pass


def authorization_url(state: str, nonce: str) -> str:
    s = get_settings()
    params = {
        "client_id": s.google_client_id,
        "redirect_uri": s.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "prompt": "select_account",
        "access_type": "online",
    }
    return f"{AUTH_ENDPOINT}?{urlencode(params)}"


def exchange_code(code: str) -> str:
    """Exchange an authorization code for an ID token."""
    s = get_settings()
    try:
        resp = httpx.post(
            TOKEN_ENDPOINT,
            timeout=10,
            data={
                "code": code,
                "client_id": s.google_client_id,
                "client_secret": s.google_client_secret,
                "redirect_uri": s.google_redirect_uri,
                "grant_type": "authorization_code",
            },
        )
    except httpx.HTTPError as e:
        raise GoogleAuthError("Could not reach Google") from e
    if resp.status_code != 200 or "id_token" not in resp.json():
        raise GoogleAuthError("Google rejected the sign-in")
    return resp.json()["id_token"]


def verify_id_token(token: str, nonce: str | None = None) -> dict[str, Any]:
    """Verify a Google ID token and return its claims."""
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token

    s = get_settings()
    try:
        claims = id_token.verify_oauth2_token(token, google_requests.Request(), s.google_client_id)
    except ValueError as e:
        raise GoogleAuthError("Invalid Google token") from e
    if claims.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        raise GoogleAuthError("Invalid token issuer")
    if not claims.get("email_verified"):
        raise GoogleAuthError("Google account email is not verified")
    if nonce is not None and claims.get("nonce") != nonce:
        raise GoogleAuthError("Sign-in request mismatch")
    return claims
