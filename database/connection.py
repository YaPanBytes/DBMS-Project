"""
ConsentLedger Database Connection & Session Management
"""

import os
from collections.abc import Generator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

try:  # Load .env if python-dotenv is installed
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass


DEFAULT_DATABASE_URL = (
    "postgresql+psycopg://consentledger:consentledger@localhost:5432/consentledger"
)

# Database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

# Engine configuration
engine = create_engine(
    DATABASE_URL,
    poolclass=NullPool if os.getenv("DB_NULL_POOL", "false").lower() == "true" else None,
    pool_pre_ping=True,
    echo=os.getenv("SQL_ECHO", "false").lower() == "true",
)

# Session factory
SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    expire_on_commit=False,
    autoflush=False,
)


def get_engine() -> Engine:
    """Return the shared SQLAlchemy engine."""
    return engine


def get_db() -> Generator[Session, None, None]:
    """Plain session dependency (no RLS context; see backend for the API one)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Context manager for standalone scripts."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> int:
    """Initialize the database by applying the Alembic migrations.

    The schema (RLS policies, triggers, audit chain, procedures) lives in
    database/migrations; ``Base.metadata.create_all`` would create bare tables
    without any of that, so it is not used.
    """
    from database.migrate import migrate

    return migrate(engine)


def drop_db() -> None:
    """Drop every object in the public schema (use with caution!)."""
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))


def check_connection() -> bool:
    """Verify database connectivity."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


# ============================================================================
# RLS CONTEXT
# ============================================================================


def set_rls_context(
    session: Session,
    user_id: str | UUID,
    org_id: str | UUID,
    *,
    app_role: str | None = None,
    encryption_key: str | None = None,
) -> None:
    """Set the per-request RLS context for the current transaction.

    ``SET LOCAL`` cannot take bind parameters, so ``set_config(..., true)``
    (the transaction-local equivalent) is used. With ``app_role`` the
    transaction also switches to that non-owner role, so RLS applies even when
    the connection itself logs in as the table owner.
    """
    session.execute(
        text(
            "SELECT set_config('consentledger.current_user_id', :uid, true), "
            "set_config('consentledger.current_org_id', :oid, true), "
            "set_config('consentledger.encryption_key', :key, true)"
        ),
        {"uid": str(user_id), "oid": str(org_id), "key": encryption_key or ""},
    )
    if app_role:
        if not app_role.replace("_", "").isalnum():
            raise ValueError(f"Invalid role name: {app_role!r}")
        session.execute(text(f"SET LOCAL ROLE {app_role}"))


def clear_rls_context(session: Session) -> None:
    """Clear RLS context variables."""
    session.execute(text("RESET consentledger.current_user_id"))
    session.execute(text("RESET consentledger.current_org_id"))
    session.execute(text("RESET consentledger.encryption_key"))


# ============================================================================
# HEALTH CHECK
# ============================================================================


def health_check() -> dict:
    """Comprehensive health check."""
    result = {
        "database": "unknown",
        "migrations": "unknown",
        "audit_chain": "unknown",
    }

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            result["database"] = "healthy"

            has_alembic = conn.execute(
                text("SELECT to_regclass('alembic_version') IS NOT NULL")
            ).scalar()
            if has_alembic:
                rev = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
                result["migrations"] = f"at revision {rev}"
            else:
                result["migrations"] = "not_configured"

            has_fn = conn.execute(text("SELECT to_regproc('verify_chain') IS NOT NULL")).scalar()
            if has_fn:
                valid = conn.execute(text("SELECT is_audit_chain_valid()")).scalar()
                result["audit_chain"] = "valid" if valid else "invalid"
            else:
                result["audit_chain"] = "not_installed"

    except Exception as e:
        result["database"] = f"unhealthy: {e}"

    return result
