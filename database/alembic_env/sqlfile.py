"""Helper for Alembic revisions that apply a SQL file from database/migrations."""

from pathlib import Path

from alembic import op

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def run_sql_file(name: str, *, down: bool = False) -> None:
    path = MIGRATIONS_DIR / ("down" if down else "") / name
    sql = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    # Send the whole file at once: splitting on ";" would break function bodies,
    # and SQLAlchemy's text() would treat ":name" as bind parameters. Without
    # parameters psycopg uses the simple query protocol (multiple statements OK).
    dbapi_conn = op.get_bind().connection.dbapi_connection
    with dbapi_conn.cursor() as cur:
        cur.execute(sql)
