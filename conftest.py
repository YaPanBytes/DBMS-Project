"""Test session setup.

All tests run against a throwaway database (default: ``<your db>_test``) that
is created at the start of the run and dropped at the end, so the development
database is never touched. Set TEST_DATABASE_URL to choose it explicitly, and
KEEP_TEST_DB=1 to keep it for inspection. The connecting role needs CREATEDB
(the docker-compose user is a superuser).
"""

import os
import tempfile

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

_TEST_URL = None


def _admin_url(url):
    return url.set(database="postgres")


def pytest_configure(config):
    global _TEST_URL
    base = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://consentledger:consentledger@localhost:5432/consentledger",
    )
    url = make_url(os.getenv("TEST_DATABASE_URL") or base)
    if not os.getenv("TEST_DATABASE_URL"):
        url = url.set(database=f"{url.database}_test")
    _TEST_URL = url
    try:
        admin = create_engine(_admin_url(url), isolation_level="AUTOCOMMIT")
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)'))
            conn.execute(text(f'CREATE DATABASE "{url.database}"'))
        admin.dispose()
    except Exception as e:  # pragma: no cover
        config.issue_config_time_warning(pytest.PytestWarning(f"Could not create test DB: {e}"), 2)
    # Everything imported from here on (database.connection, backend settings)
    # binds to the test database.
    os.environ["DATABASE_URL"] = url.render_as_string(hide_password=False)
    os.environ.setdefault(
        "ANOMALY_LABELS_PATH", os.path.join(tempfile.gettempdir(), "cl_labels.csv")
    )
    os.environ.setdefault("JWT_SECRET", "test-secret-" + "x" * 40)


def pytest_unconfigure(config):
    if _TEST_URL is None or os.getenv("KEEP_TEST_DB"):
        return
    try:
        from database.connection import engine

        engine.dispose()
        try:
            from backend.app.db import get_engine

            get_engine().dispose()
        except Exception:
            pass
        admin = create_engine(_admin_url(_TEST_URL), isolation_level="AUTOCOMMIT")
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{_TEST_URL.database}" WITH (FORCE)'))
        admin.dispose()
    except Exception:
        pass


@pytest.fixture(scope="session")
def migrated_engine():
    """Engine on the test database with all Alembic migrations applied."""
    from database.connection import engine
    from database.migrate import migrate

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:  # pragma: no cover
        pytest.skip(f"PostgreSQL not reachable: {e}")
    assert migrate(engine) == 0, "migrations failed"
    return engine


@pytest.fixture(scope="session")
def seeded(migrated_engine):
    """The full demo world (seed script), created once per test run."""
    from database.seeds.seed_data import seed_all

    result = seed_all()
    assert result["status"] in ("success", "skipped")
    return result
