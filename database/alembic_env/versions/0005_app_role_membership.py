"""Let the database login switch to the application role

Revision ID: 0005
Revises: 0004
"""

from collections.abc import Sequence

from database.alembic_env.sqlfile import run_sql_file

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQL_FILE = "005_app_role_membership.sql"


def upgrade() -> None:
    run_sql_file(SQL_FILE)


def downgrade() -> None:
    run_sql_file(SQL_FILE, down=True)
