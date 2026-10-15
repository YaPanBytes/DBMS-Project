"""Database session for API requests.

Every transaction a request opens runs as the non-owner role
``consentledger_app`` with the signed-in user's id and organization in
transaction-local settings, so PostgreSQL row-level security decides what the
request can see. The context is re-applied at the start of *every*
transaction (``after_begin``), so it survives commits within one request.
"""

from collections.abc import Generator
from dataclasses import dataclass
from functools import lru_cache
from uuid import UUID

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings


@dataclass
class RequestContext:
    user_id: UUID | None = None
    org_id: UUID | None = None


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(settings.database_url, pool_pre_ping=True, pool_size=5, max_overflow=10)


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, autoflush=False)


def apply_context(conn: Connection, ctx: RequestContext) -> None:
    settings = get_settings()
    conn.execute(
        text(
            "SELECT set_config('consentledger.current_user_id', :uid, true), "
            "set_config('consentledger.current_org_id', :oid, true), "
            "set_config('consentledger.encryption_key', :key, true)"
        ),
        {
            "uid": str(ctx.user_id) if ctx.user_id else "",
            "oid": str(ctx.org_id) if ctx.org_id else "",
            "key": settings.encryption_key if ctx.user_id else "",
        },
    )
    role = settings.db_app_role
    if role:
        if not role.replace("_", "").isalnum():
            raise ValueError(f"Invalid DB_APP_ROLE: {role!r}")
        conn.execute(text(f"SET LOCAL ROLE {role}"))


@event.listens_for(Session, "after_begin")
def _set_rls_context(session: Session, transaction, connection: Connection) -> None:  # noqa: ARG001
    ctx = session.info.get("rls")
    if ctx is not None:
        apply_context(connection, ctx)


def set_request_user(session: Session, user_id: UUID | None, org_id: UUID | None) -> None:
    """Change the RLS identity for this session (applies to the current transaction too)."""
    ctx = RequestContext(user_id=user_id, org_id=org_id)
    session.info["rls"] = ctx
    if session.in_transaction():
        apply_context(session.connection(), ctx)


def get_db() -> Generator[Session, None, None]:
    session = get_sessionmaker()()
    session.info["rls"] = RequestContext()  # anonymous until authenticated
    try:
        yield session
    finally:
        session.rollback()  # anything not explicitly committed is discarded
        session.close()
