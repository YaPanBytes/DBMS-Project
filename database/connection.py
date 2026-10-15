"""
ConsentLedger Database Connection & Session Management
Member A: Database Lead
"""

from contextlib import contextmanager
from typing import Generator, Optional
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool
import os


# Database URL from environment
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://consentledger:consentledger@localhost:5432/consentledger"
)

# Engine configuration
engine = create_engine(
    DATABASE_URL,
    poolclass=NullPool,  # Use NullPool for development; switch to QueuePool for production
    echo=os.getenv("SQL_ECHO", "false").lower() == "true",
    future=True,
)

# Session factory
SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for database session."""
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


def init_db() -> None:
    """Initialize database: create tables if they don't exist."""
    from database.models import Base
    Base.metadata.create_all(bind=engine)


def drop_db() -> None:
    """Drop all tables (use with caution!)."""
    from database.models import Base
    Base.metadata.drop_all(bind=engine)


def check_connection() -> bool:
    """Verify database connectivity."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


# ============================================================================
# EVENT LISTENERS
# ============================================================================

@event.listens_for(engine, "connect")
def set_session_variables(dbapi_connection, connection_record):
    """Set PostgreSQL session variables for RLS."""
    # This runs on each new connection
    # The application should set these per-request via SET LOCAL
    pass


def set_rls_context(session: Session, user_id: str, org_id: str) -> None:
    """Set RLS context variables for the current session."""
    session.execute(text("SET LOCAL consentledger.current_user_id = :uid"), {"uid": user_id})
    session.execute(text("SET LOCAL consentledger.current_org_id = :oid"), {"oid": org_id})


def clear_rls_context(session: Session) -> None:
    """Clear RLS context variables."""
    session.execute(text("RESET consentledger.current_user_id"))
    session.execute(text("RESET consentledger.current_org_id"))


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
            # Basic connectivity
            conn.execute(text("SELECT 1"))
            result["database"] = "healthy"
            
            # Check migrations table exists
            mig_result = conn.execute(text("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_name = 'alembic_version'
                )
            """))
            result["migrations"] = "configured" if mig_result.scalar() else "not_configured"
            
            # Check audit chain
            chain_result = conn.execute(text("SELECT is_audit_chain_valid()"))
            result["audit_chain"] = "valid" if chain_result.scalar() else "invalid"
            
    except Exception as e:
        result["database"] = f"unhealthy: {str(e)}"
    
    return result