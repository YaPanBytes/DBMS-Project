"""Revoked JWT ids for logout

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

from database.alembic_env.sqlfile import run_sql_file

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL_FILE = "003_auth_tokens.sql"


def upgrade() -> None:
    run_sql_file(SQL_FILE)


def downgrade() -> None:
    run_sql_file(SQL_FILE, down=True)
