"""Alembic environment for ConsentLedger.

The schema is written in SQL (database/migrations/*.sql) because it relies on
PostgreSQL features SQLAlchemy cannot express (RLS policies, plpgsql
functions, triggers, procedures). Each Alembic revision applies one of those
files; ``target_metadata`` is the ORM metadata so ``alembic revision
--autogenerate`` can still compare the models against the database.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from database.connection import DATABASE_URL
from database.models import Base

config = context.config
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _url() -> str:
    return config.attributes.get("url") or config.get_main_option("sqlalchemy.url") or DATABASE_URL


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
        return

    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
