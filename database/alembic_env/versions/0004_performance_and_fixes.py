"""Performance and correctness fixes from the code review

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence

from database.alembic_env.sqlfile import run_sql_file

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL_FILE = "004_performance_and_fixes.sql"


def upgrade() -> None:
    run_sql_file(SQL_FILE)


def downgrade() -> None:
    run_sql_file(SQL_FILE, down=True)
