"""ConsentLedger API (FastAPI).

Run:  uvicorn backend.app.main:app --reload      (from the project root)
Docs: http://localhost:8000/docs  (OpenAPI JSON at /openapi.json)
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from .config import get_settings
from .db import get_engine
from .errors import AppError, install_exception_handlers
from .routers import alerts, audit, auth, consent, dashboard, datasets, organizations, requests

API_PREFIX = "/api"

TAGS = [
    {
        "name": "auth",
        "description": "Google OAuth 2.0 and password login, JWT sessions, logout, /me",
    },
    {
        "name": "organizations",
        "description": "Organizations, users and roles (admins manage accounts)",
    },
    {
        "name": "datasets",
        "description": "Dataset registry, fields, PII scan, publish, load and read data",
    },
    {"name": "consent", "description": "Per-field, purpose-bound, expiring consent grants"},
    {"name": "requests", "description": "Partner access requests and owner decisions"},
    {"name": "audit", "description": "Hash-chained audit trail and verification"},
    {"name": "alerts", "description": "Anomaly alerts from the AI detector"},
    {"name": "dashboard", "description": "Summary counts for the signed-in user"},
]


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_settings().check_production_secrets()
    yield
    get_engine().dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=logging.INFO)
    app = FastAPI(
        title="ConsentLedger API",
        version="1.0.0",
        description=(
            "Data-sharing hub with per-field, purpose-bound consent enforced by PostgreSQL "
            "row-level security, a hash-chained audit log and AI anomaly detection.\n\n"
            "**Auth**: sign in via `POST /api/auth/login` (session cookie) or use the "
            "*Authorize* button (bearer token from `POST /api/auth/token`). Demo accounts use "
            "password `demo123`, e.g. `owner@hope.org`, `funder@globalfund.org`, "
            "`auditor@transparency.org`, `admin@consentledger.org`.\n\n"
            '**Errors** are always `{"error": {"code", "message", "details"?}}`.'
        ),
        openapi_tags=TAGS,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        swagger_ui_parameters={"persistAuthorization": True},
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
    )
    install_exception_handlers(app)
    for r in (auth, organizations, datasets, consent, requests, audit, alerts, dashboard):
        app.include_router(r.router, prefix=API_PREFIX)

    # Plain landing response for the bare host (e.g. a hosting platform's URL
    # check). Kept out of the OpenAPI spec; the API itself lives under /api.

    @app.get(f"{API_PREFIX}/health", tags=["dashboard"], summary="Liveness and database check")
    def health() -> dict:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
            rev = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        return {"status": "ok", "database": "ok", "migration": rev}

    dist = Path(settings.frontend_dist) if settings.frontend_dist else None
    if dist is not None and (dist / "index.html").is_file():
        _serve_frontend(app, dist)
    else:
        # API only. GET and HEAD: hosting platforms probe the root with HEAD.
        @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
        def root() -> dict:
            return {"service": "consentledger-api", "status": "ok", "docs": "/docs"}

    return app


def _serve_frontend(app: FastAPI, dist: Path) -> None:
    """Serve the built single-page app: hashed assets from /assets, real files
    (favicon, ...) as they are, and index.html for every other path so the
    app's own routes (/datasets/..., /audit) work on reload. Registered after
    the API routes, so /api, /docs, /redoc and /openapi.json win."""
    root = dist.resolve()
    index = root / "index.html"
    if (root / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=root / "assets"), name="assets")

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    def spa(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):
            raise AppError(404, "Not Found")  # unknown API paths stay JSON 404s
        candidate = (root / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        # Always revalidate the page so a new deploy is picked up at once
        return FileResponse(index, headers={"Cache-Control": "no-cache"})


app = create_app()
