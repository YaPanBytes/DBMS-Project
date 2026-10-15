"""RLS policies, audit hash chain, masked views, procedures, feature views

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

from database.alembic_env.sqlfile import run_sql_file

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL_FILE = "002_rls_views_audit.sql"


def upgrade() -> None:
    run_sql_file(SQL_FILE)


def downgrade() -> None:
    run_sql_file(SQL_FILE, down=True)
