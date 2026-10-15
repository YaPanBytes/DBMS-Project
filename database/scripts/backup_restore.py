"""
ConsentLedger Backup & Restore
PostgreSQL backup and restore utilities with compression and verification.
"""

import gzip
import json
import os
import shutil
import subprocess
import sys
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

# Allow running as a plain script as well as with `python -m`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from database.connection import DATABASE_URL  # noqa: E402

META_SUFFIX = ".meta.json"


class BackupManager:
    """Manage database backups and restores."""

    def __init__(self, backup_dir: str = "./backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Parse DATABASE_URL for pg_dump/pg_restore
        # postgresql+psycopg://user:pass@host:port/dbname
        parsed = urllib.parse.urlparse(DATABASE_URL)
        self.db_host = parsed.hostname or "localhost"
        self.db_port = parsed.port or 5432
        self.db_user = urllib.parse.unquote(parsed.username or "postgres")
        self.db_password = urllib.parse.unquote(parsed.password or "")
        self.db_name = parsed.path.lstrip("/") or "postgres"

        self.pg_dump = shutil.which("pg_dump")
        self.pg_restore = shutil.which("pg_restore")
        self.psql = shutil.which("psql")

        if not self.pg_dump:
            raise RuntimeError("pg_dump not found in PATH. Install PostgreSQL client tools.")

    def _env(self) -> dict:
        """Environment with PGPASSWORD."""
        env = os.environ.copy()
        if self.db_password:
            env["PGPASSWORD"] = self.db_password
        return env

    def _require(self, tool: str | None, name: str) -> str:
        if not tool:
            raise RuntimeError(f"{name} not found in PATH. Install PostgreSQL client tools.")
        return tool

    @staticmethod
    def metadata_path(backup_path: Path) -> Path:
        return backup_path.with_name(backup_path.name + META_SUFFIX)

    def _run(self, cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        """Run command with proper environment."""
        return subprocess.run(cmd, env=self._env(), capture_output=True, text=True, **kwargs)

    def create_backup(
        self,
        name: str | None = None,
        format: str = "custom",
        compress: bool = True,
        schema_only: bool = False,
        data_only: bool = False,
        exclude_tables: list[str] | None = None,
    ) -> Path:
        """Create a database backup."""
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        backup_name = name or f"consentledger_{timestamp}"

        if format == "custom":
            ext = ".dump"
        elif format == "plain":
            ext = ".sql"
        else:
            ext = f".{format}"

        # pg_dump writes the plain file; it is gzipped afterwards
        backup_path = self.backup_dir / f"{backup_name}{ext}"

        cmd = [
            self.pg_dump,
            "-h",
            self.db_host,
            "-p",
            str(self.db_port),
            "-U",
            self.db_user,
            "-d",
            self.db_name,
            "-F",
            format,
            "-f",
            str(backup_path),
            "--no-owner",
            "--no-privileges",
        ]

        if schema_only:
            cmd.append("--schema-only")
        if data_only:
            cmd.append("--data-only")

        if exclude_tables:
            for table in exclude_tables:
                cmd.extend(["--exclude-table", table])

        print(f"Creating backup: {backup_path}")
        result = self._run(cmd)

        if result.returncode != 0:
            raise RuntimeError(f"pg_dump failed: {result.stderr}")

        # Compress if needed (custom format is already compressed)
        if compress and format == "plain":
            print("Compressing...")
            with open(backup_path, "rb") as f_in, gzip.open(f"{backup_path}.gz", "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            backup_path.unlink()
            backup_path = Path(f"{backup_path}.gz")

        # Create metadata
        metadata = {
            "name": backup_name,
            "timestamp": timestamp,
            "format": format,
            # custom format is always compressed by pg_dump
            "compressed": format == "custom" or (compress and format == "plain"),
            "schema_only": schema_only,
            "data_only": data_only,
            "size_bytes": backup_path.stat().st_size,
            "database": self.db_name,
            "host": self.db_host,
            "port": self.db_port,
        }
        metadata_path = self.metadata_path(backup_path)
        metadata_path.write_text(json.dumps(metadata, indent=2))

        print(f"Backup created: {backup_path} ({metadata['size_bytes']:,} bytes)")
        return backup_path

    def list_backups(self) -> list[dict]:
        """List all available backups."""
        backups = []
        for meta_file in sorted(self.backup_dir.glob(f"*{META_SUFFIX}")):
            try:
                metadata = json.loads(meta_file.read_text())
                backup_file = meta_file.with_name(meta_file.name[: -len(META_SUFFIX)])
                if backup_file.exists():
                    metadata["file"] = str(backup_file)
                    metadata["exists"] = True
                else:
                    metadata["exists"] = False
                backups.append(metadata)
            except (OSError, ValueError) as e:
                print(f"Skipping unreadable metadata {meta_file}: {e}")
        return backups

    def restore_backup(
        self,
        backup_path: Path,
        clean: bool = False,
        schema_only: bool = False,
        data_only: bool = False,
        single_transaction: bool = True,
    ) -> bool:
        """Restore database from backup."""
        backup_path = Path(backup_path)

        if not backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        # Check metadata
        meta_path = self.metadata_path(backup_path)
        if meta_path.exists():
            metadata = json.loads(meta_path.read_text())
            print(f"Restoring backup: {metadata['name']} from {metadata['timestamp']}")

        # Decompress if needed
        is_gzipped = backup_path.suffix == ".gz"
        actual_path = backup_path

        if is_gzipped:
            actual_path = backup_path.with_suffix("")  # Remove .gz
            print("Decompressing...")
            with gzip.open(backup_path, "rb") as f_in, open(actual_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        try:
            if actual_path.suffix in (".dump", ".tar"):
                # Archive formats - use pg_restore
                cmd = [
                    self._require(self.pg_restore, "pg_restore"),
                    "-h",
                    self.db_host,
                    "-p",
                    str(self.db_port),
                    "-U",
                    self.db_user,
                    "-d",
                    self.db_name,
                    "--no-owner",
                    "--no-privileges",
                ]
                if clean:
                    cmd.extend(["--clean", "--if-exists"])
                if schema_only:
                    cmd.append("--schema-only")
                if data_only:
                    # Otherwise the audit triggers would fire for every restored
                    # row and append new entries to the audit chain.
                    cmd.extend(["--data-only", "--disable-triggers"])
                if single_transaction:
                    cmd.append("--single-transaction")
                cmd.append(str(actual_path))
            else:
                # Plain SQL - use psql
                cmd = [
                    self._require(self.psql, "psql"),
                    "-h",
                    self.db_host,
                    "-p",
                    str(self.db_port),
                    "-U",
                    self.db_user,
                    "-d",
                    self.db_name,
                    "-v",
                    "ON_ERROR_STOP=1",
                ]
                if single_transaction:
                    cmd.append("--single-transaction")
                cmd.extend(["-f", str(actual_path)])

            print(f"Restoring from {actual_path}...")
            result = self._run(cmd)

            if result.returncode != 0:
                raise RuntimeError(f"Restore failed: {result.stderr}")

            print("Restore completed successfully")
            return True

        finally:
            # Clean up decompressed file
            if is_gzipped and actual_path.exists():
                actual_path.unlink()

    def verify_backup(self, backup_path: Path) -> dict:
        """Verify backup integrity: archive formats are read with `pg_restore --list`,
        plain SQL files are checked for a pg_dump header."""
        backup_path = Path(backup_path)
        result = {"valid": False, "metadata": None, "size_bytes": 0, "error": None}

        try:
            if not backup_path.exists():
                result["error"] = "Backup file not found"
                return result

            result["size_bytes"] = backup_path.stat().st_size

            meta_path = self.metadata_path(backup_path)
            if meta_path.exists():
                result["metadata"] = json.loads(meta_path.read_text())

            if backup_path.suffix in (".dump", ".tar"):
                listing = self._run(
                    [self._require(self.pg_restore, "pg_restore"), "--list", str(backup_path)]
                )
                if listing.returncode == 0:
                    result["valid"] = True
                else:
                    result["error"] = f"Not a readable pg_dump archive: {listing.stderr.strip()}"
            else:
                opener = gzip.open if backup_path.suffix == ".gz" else open
                with opener(backup_path, "rb") as f:
                    header = f.read(4096)
                if not header:
                    result["error"] = "Backup file appears empty"
                elif b"PostgreSQL database dump" in header:
                    result["valid"] = True
                else:
                    result["error"] = "File does not look like a pg_dump SQL backup"

        except Exception as e:
            result["error"] = str(e)

        return result


def backup_main():
    """CLI entry point for backup."""
    import argparse

    parser = argparse.ArgumentParser(description="ConsentLedger database backup")
    parser.add_argument("--name", help="Backup name (default: timestamp)")
    parser.add_argument("--format", choices=["custom", "plain", "tar"], default="custom")
    parser.add_argument("--no-compress", action="store_true", help="Disable compression")
    parser.add_argument("--schema-only", action="store_true")
    parser.add_argument("--data-only", action="store_true")
    parser.add_argument("--exclude", action="append", help="Tables to exclude")
    parser.add_argument("--list", action="store_true", help="List existing backups")
    parser.add_argument("--backup-dir", default="./backups")

    args = parser.parse_args()

    manager = BackupManager(args.backup_dir)

    if args.list:
        backups = manager.list_backups()
        if not backups:
            print("No backups found")
            return
        print(f"{'Name':<30} {'Date':<20} {'Format':<10} {'Size':>12} {'Status'}")
        print("-" * 90)
        for b in backups:
            status = "✓" if b["exists"] else "✗ MISSING"
            size = f"{b['size_bytes']:,}" if b["exists"] else "N/A"
            print(f"{b['name']:<30} {b['timestamp']:<20} {b['format']:<10} {size:>12} {status}")
        return

    try:
        path = manager.create_backup(
            name=args.name,
            format=args.format,
            compress=not args.no_compress,
            schema_only=args.schema_only,
            data_only=args.data_only,
            exclude_tables=args.exclude,
        )
        print(f"\n✓ Backup saved to: {path}")
    except Exception as e:
        print(f"✗ Backup failed: {e}")
        sys.exit(1)


def restore_main():
    """CLI entry point for restore."""
    import argparse

    parser = argparse.ArgumentParser(description="ConsentLedger database restore")
    parser.add_argument("backup", help="Backup file path")
    parser.add_argument("--clean", action="store_true", help="Drop objects before restore")
    parser.add_argument("--schema-only", action="store_true")
    parser.add_argument("--data-only", action="store_true")
    parser.add_argument("--no-single-transaction", action="store_true")
    parser.add_argument("--backup-dir", default="./backups")

    args = parser.parse_args()

    manager = BackupManager(args.backup_dir)
    backup_path = Path(args.backup)

    if not backup_path.is_absolute():
        backup_path = manager.backup_dir / backup_path

    try:
        # Verify first
        verification = manager.verify_backup(backup_path)
        if not verification["valid"]:
            print(f"✗ Backup verification failed: {verification['error']}")
            sys.exit(1)

        print(f"Backup verified: {verification['size_bytes']:,} bytes")

        # Confirm
        confirm = input("This will overwrite the database. Continue? (yes/no): ")
        if confirm.lower() != "yes":
            print("Aborted")
            return

        success = manager.restore_backup(
            backup_path,
            clean=args.clean,
            schema_only=args.schema_only,
            data_only=args.data_only,
            single_transaction=not args.no_single_transaction,
        )

        if success:
            print("✓ Restore completed")
        else:
            print("✗ Restore failed")
            sys.exit(1)

    except Exception as e:
        print(f"✗ Restore failed: {e}")
        sys.exit(1)


def verify_main():
    """CLI entry point for verify."""
    import argparse

    parser = argparse.ArgumentParser(description="Verify backup integrity")
    parser.add_argument("backup", help="Backup file path")
    parser.add_argument("--backup-dir", default="./backups")

    args = parser.parse_args()

    manager = BackupManager(args.backup_dir)
    backup_path = Path(args.backup)

    if not backup_path.is_absolute():
        backup_path = manager.backup_dir / backup_path

    result = manager.verify_backup(backup_path)

    if result["valid"]:
        print("✓ Backup is valid")
        if result["metadata"]:
            print(f"  Name: {result['metadata']['name']}")
            print(f"  Date: {result['metadata']['timestamp']}")
            print(f"  Format: {result['metadata']['format']}")
        print(f"  Size: {result['size_bytes']:,} bytes")
    else:
        print(f"✗ Backup is invalid: {result['error']}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("backup", "restore", "verify"):
        command = sys.argv.pop(1)
        if command == "backup":
            backup_main()
        elif command == "restore":
            restore_main()
        elif command == "verify":
            verify_main()
    else:
        print("Usage: python -m database.scripts.backup_restore [backup|restore|verify] [options]")
        sys.exit(1)
