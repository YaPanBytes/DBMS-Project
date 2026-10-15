"""Initial schema: tables, keys, constraints, indexes, updated_at triggers

Revision ID: 0001
Revises:
"""

from collections.abc import Sequence

from database.alembic_env.sqlfile import run_sql_file

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL_FILE = "001_initial_schema.sql"


def upgrade() -> None:
    run_sql_file(SQL_FILE)


def downgrade() -> None:
    run_sql_file(SQL_FILE, down=True)
