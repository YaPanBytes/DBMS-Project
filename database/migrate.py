"""
ConsentLedger Migration Runner
Member A: Database Lead
Runs SQL migrations in order with transaction safety.
"""

import os
import sys
from pathlib import Path
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import OperationalError


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://consentledger:consentledger@localhost:5432/consentledger"
)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def get_engine():
    return create_engine(DATABASE_URL, future=True)


def ensure_migrations_table(engine):
    """Create migrations tracking table if it doesn't exist."""
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version VARCHAR(50) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                checksum VARCHAR(64) NOT NULL
            )
        """))
        conn.commit()


def get_applied_migrations(engine) -> set:
    """Get set of already applied migration versions."""
    with engine.connect() as conn:
        result = conn.execute(text("SELECT version FROM schema_migrations"))
        return {row[0] for row in result}


def compute_checksum(content: str) -> str:
    """Compute SHA256 checksum of migration content."""
    import hashlib
    return hashlib.sha256(content.encode()).hexdigest()


def get_migration_files() -> list:
    """Get sorted list of migration files."""
    files = []
    for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
        # Extract version from filename (e.g., 001_initial_schema.sql -> 001)
        version = f.stem.split("_")[0]
        files.append((version, f.stem, f))
    return files


def run_migration(engine, version: str, name: str, filepath: Path) -> bool:
    """Run a single migration file."""
    content = filepath.read_text()
    checksum = compute_checksum(content)
    
    print(f"  Applying {version}: {name}...")
    
    try:
        with engine.connect() as conn:
            # Run in transaction
            trans = conn.begin()
            try:
                # Split by semicolon and execute each statement
                statements = [s.strip() for s in content.split(";") if s.strip()]
                for stmt in statements:
                    if stmt:
                        conn.execute(text(stmt))
                
                # Record migration
                conn.execute(text("""
                    INSERT INTO schema_migrations (version, name, checksum)
                    VALUES (:version, :name, :checksum)
                """), {"version": version, "name": name, "checksum": checksum})
                
                trans.commit()
                print(f"  ✓ {version} applied successfully")
                return True
            except Exception as e:
                trans.rollback()
                print(f"  ✗ {version} failed: {e}")
                return False
    except Exception as e:
        print(f"  ✗ {version} connection error: {e}")
        return False


def migrate() -> int:
    """Run all pending migrations."""
    engine = get_engine()
    
    # Test connection
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as e:
        print(f"Cannot connect to database: {e}")
        return 1
    
    ensure_migrations_table(engine)
    applied = get_applied_migrations(engine)
    migrations = get_migration_files()
    
    print(f"Found {len(migrations)} migration(s)")
    print(f"Already applied: {len(applied)}")
    
    pending = [(v, n, f) for v, n, f in migrations if v not in applied]
    
    if not pending:
        print("No pending migrations.")
        return 0
    
    print(f"Applying {len(pending)} pending migration(s)...")
    
    success = 0
    for version, name, filepath in pending:
        if run_migration(engine, version, name, filepath):
            success += 1
        else:
            print(f"\nMigration {version} failed. Stopping.")
            return 1
    
    print(f"\n✓ All {success} migration(s) applied successfully")
    return 0


def status() -> int:
    """Show migration status."""
    engine = get_engine()
    
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as e:
        print(f"Cannot connect to database: {e}")
        return 1
    
    ensure_migrations_table(engine)
    applied = get_applied_migrations(engine)
    migrations = get_migration_files()
    
    print("Migration Status:")
    print("-" * 60)
    
    for version, name, filepath in migrations:
        status_mark = "✓" if version in applied else "○"
        print(f"  {status_mark} {version}: {name}")
    
    print("-" * 60)
    print(f"Total: {len(migrations)}, Applied: {len(applied)}, Pending: {len(migrations) - len(applied)}")
    return 0


def rollback(version: str) -> int:
    """Rollback a specific migration (if supported)."""
    print(f"Rollback not implemented for {version}. Manual intervention required.")
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m database.migrate [migrate|status|rollback <version>]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "migrate":
        sys.exit(migrate())
    elif command == "status":
        sys.exit(status())
    elif command == "rollback" and len(sys.argv) > 2:
        sys.exit(rollback(sys.argv[2]))
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)