"""
ConsentLedger migration commands (thin wrapper around Alembic).

    python -m database.migrate            # upgrade to the latest revision
    python -m database.migrate status     # current revision and history
    python -m database.migrate downgrade <revision|-1|base>

Equivalent to running ``alembic upgrade head`` etc. from the project root.
"""

import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_DIR = Path(__file__).resolve().parent / "alembic_env"


def alembic_config(engine: Engine | None = None) -> Config:
    ini = PROJECT_ROOT / "alembic.ini"
    cfg = Config(str(ini)) if ini.exists() else Config()
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    cfg.attributes["configure_logger"] = False
    if engine is not None:
        cfg.attributes["url"] = engine.url.render_as_string(hide_password=False)
    return cfg


def get_engine() -> Engine:
    from database.connection import get_engine as _get_engine

    return _get_engine()


def _check_connection(engine: Engine) -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except OperationalError as e:
        print(f"Cannot connect to database: {e}")
        return False


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def head_revision() -> str | None:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def migrate(engine: Engine | None = None) -> int:
    """Upgrade the database to the latest Alembic revision."""
    engine = engine or get_engine()
    if not _check_connection(engine):
        return 1
    before = current_revision(engine)
    try:
        command.upgrade(alembic_config(engine), "head")
    except Exception as e:
        print(f"✗ Migration failed: {e}")
        return 1
    after = current_revision(engine)
    if before == after:
        print(f"No pending migrations (at {after}).")
    else:
        print(f"✓ Migrated {before or 'empty database'} -> {after}")
    return 0


def status(engine: Engine | None = None) -> int:
    engine = engine or get_engine()
    if not _check_connection(engine):
        return 1
    current = current_revision(engine)
    script = ScriptDirectory.from_config(alembic_config())
    print("Migration Status:")
    print("-" * 60)
    applied = bool(current)
    for rev in reversed(list(script.walk_revisions())):
        mark = "✓" if applied else "○"
        print(f"  {mark} {rev.revision}: {rev.doc}")
        if rev.revision == current:
            applied = False
    print("-" * 60)
    print(f"Current: {current or 'none'}   Head: {script.get_current_head()}")
    return 0


def downgrade(target: str, engine: Engine | None = None) -> int:
    engine = engine or get_engine()
    if not _check_connection(engine):
        return 1
    command.downgrade(alembic_config(engine), target)
    print(f"✓ Downgraded to {current_revision(engine) or 'base'}")
    return 0


def main(argv: list[str]) -> int:
    command_name = argv[1] if len(argv) > 1 else "migrate"
    if command_name in ("migrate", "upgrade"):
        return migrate()
    if command_name == "status":
        return status()
    if command_name == "downgrade" and len(argv) > 2:
        return downgrade(argv[2])
    print("Usage: python -m database.migrate [migrate|status|downgrade <revision>]")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
