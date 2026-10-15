"""
ConsentLedger Audit Chain Verification
Verifies the integrity of the hash-chained audit log.
"""

import hashlib
import json
import os
import sys

from sqlalchemy import text

# Allow running as a plain script as well as with `python -m`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from database.connection import get_engine  # noqa: E402

GENESIS_HASH = b"\x00" * 32


def compute_row_hash(
    prev_hash: bytes,
    user_id: str | None,
    dataset_id: str | None,
    field_id: str | None,
    field_ids: str | None,
    action: str,
    rows_affected: str,
    query_text: str | None,
    client_ip: str | None,
    user_agent: str | None,
    ts_text: str,
) -> bytes:
    """Python re-implementation of the SQL function compute_audit_hash().

    The hash input is the JSON array (as rendered by PostgreSQL's
    json_build_array) of the text form of each column, with prev_hash in hex and
    the timestamp as UTC 'YYYY-MM-DDTHH:MM:SS.ffffffZ'.
    """
    payload = json.dumps(
        [
            prev_hash.hex(),
            user_id,
            dataset_id,
            field_id,
            field_ids,
            action,
            rows_affected,
            query_text,
            client_ip,
            user_agent,
            ts_text,
        ],
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).digest()


def verify_audit_chain() -> dict:
    """Verify the complete audit chain using the database function."""
    engine = get_engine()

    result = {
        "valid": False,
        "total_rows": 0,
        "verified_rows": 0,
        "first_error": None,
        "errors": [],
    }

    try:
        with engine.connect() as conn:
            result["total_rows"] = conn.execute(text("SELECT count(*) FROM audit_log")).scalar()
            rows = conn.execute(text("SELECT * FROM verify_chain()")).fetchall()

            for log_id, expected_hash, actual_hash, is_valid, error_msg in rows:
                if is_valid:
                    result["verified_rows"] += 1
                    continue
                error = {
                    "log_id": str(log_id),
                    "expected_hash": expected_hash.hex() if expected_hash else None,
                    "actual_hash": actual_hash.hex() if actual_hash else None,
                    "error": error_msg,
                }
                result["errors"].append(error)
                if result["first_error"] is None:
                    result["first_error"] = {"log_id": str(log_id), "error": error_msg}

            result["valid"] = (
                not result["errors"] and result["verified_rows"] == result["total_rows"]
            )

    except Exception as e:
        result["errors"].append({"log_id": None, "error": f"Verification failed: {e}"})

    return result


def verify_audit_chain_detailed() -> dict:
    """Independent verification: recompute every hash in Python.

    Unlike verify_audit_chain() this does not stop at the first problem, so it
    reports every broken link and every mismatching row.
    """
    engine = get_engine()

    result = {
        "valid": False,
        "total_rows": 0,
        "verified_rows": 0,
        "mismatches": [],
        "chain_breaks": [],
    }

    try:
        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT log_id, prev_hash, row_hash,
                       user_id::text, dataset_id::text, field_id::text, field_ids::text, action,
                       rows_affected::text, query_text, client_ip::text, user_agent,
                       audit_ts_text(ts)
                FROM audit_log
                ORDER BY seq ASC
            """)).fetchall()

        result["total_rows"] = len(rows)
        expected_prev = GENESIS_HASH

        for i, row in enumerate(rows):
            log_id, prev_hash, row_hash, *content = row
            prev_hash, row_hash = bytes(prev_hash), bytes(row_hash)

            linked = prev_hash == expected_prev
            if not linked:
                result["chain_breaks"].append(
                    {
                        "index": i,
                        "log_id": str(log_id),
                        "expected_prev_hash": expected_prev.hex(),
                        "actual_prev_hash": prev_hash.hex(),
                    }
                )

            computed = compute_row_hash(prev_hash, *content)
            if computed != row_hash:
                result["mismatches"].append(
                    {
                        "index": i,
                        "log_id": str(log_id),
                        "expected_hash": computed.hex(),
                        "actual_hash": row_hash.hex(),
                    }
                )
            elif linked:
                result["verified_rows"] += 1

            expected_prev = row_hash

        result["valid"] = not result["mismatches"] and not result["chain_breaks"]

    except Exception as e:
        result["mismatches"].append({"log_id": None, "error": f"Verification failed: {e}"})

    return result


def tamper_test() -> dict:
    """Demonstrate tamper detection by modifying a row inside a rolled-back transaction.

    audit_log rejects UPDATE through a trigger, so the test first disables that
    trigger (as a privileged attacker could) and then checks that the hash chain
    still exposes the change. Nothing is committed.
    """
    engine = get_engine()

    result = {"tamper_detected": False, "update_blocked": False, "details": ""}

    try:
        with engine.connect() as conn:
            trans = conn.begin()
            try:
                row = conn.execute(
                    text("SELECT log_id FROM audit_log ORDER BY seq LIMIT 1")
                ).fetchone()
                if not row:
                    result["details"] = "No audit logs to test"
                    return result
                log_id = row[0]

                # 1. A normal UPDATE must be rejected
                savepoint = conn.begin_nested()
                try:
                    conn.execute(
                        text(
                            "UPDATE audit_log SET rows_affected = rows_affected + 1 "
                            "WHERE log_id = :id"
                        ),
                        {"id": log_id},
                    )
                except Exception:
                    result["update_blocked"] = True
                savepoint.rollback()

                # 2. Bypass the trigger and tamper; the chain must catch it
                conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER trg_audit_log_immutable"))
                conn.execute(
                    text(
                        "UPDATE audit_log SET rows_affected = rows_affected + 1 "
                        "WHERE log_id = :id"
                    ),
                    {"id": log_id},
                )
                valid = conn.execute(text("SELECT is_audit_chain_valid()")).scalar()

                result["tamper_detected"] = not valid
                result["details"] = (
                    f"Tamper detected on log {log_id}"
                    if not valid
                    else "Tamper NOT detected - chain validation is broken"
                )
            finally:
                trans.rollback()  # always undo the tampering

    except Exception as e:
        result["details"] = f"Test error: {e}"

    return result


def print_verification_report(result: dict) -> None:
    """Print a formatted verification report."""
    errors = (
        result.get("errors", []) + result.get("mismatches", []) + result.get("chain_breaks", [])
    )
    print("=" * 60)
    print("AUDIT CHAIN VERIFICATION REPORT")
    print("=" * 60)
    print(f"Status: {'✓ VALID' if result['valid'] else '✗ INVALID'}")
    print(f"Total Rows: {result['total_rows']}")
    print(f"Verified: {result['verified_rows']}")
    print(f"Errors: {len(errors)}")

    if result.get("first_error"):
        print("\nFirst Error:")
        print(f"  Log ID: {result['first_error']['log_id']}")
        print(f"  Error: {result['first_error']['error']}")

    if result.get("errors"):
        print(f"\nAll Errors ({len(result['errors'])}):")
        for e in result["errors"][:10]:
            print(f"  - Log {e.get('log_id')}: {e['error']}")

    if result.get("mismatches"):
        print(f"\nHash Mismatches ({len(result['mismatches'])}):")
        for m in result["mismatches"][:10]:
            if "error" in m:
                print(f"  - {m['error']}")
            else:
                print(
                    f"  - Log {m['log_id']}: expected {m['expected_hash'][:16]}..., "
                    f"got {m['actual_hash'][:16]}..."
                )

    if result.get("chain_breaks"):
        print(f"\nChain Breaks ({len(result['chain_breaks'])}):")
        for c in result["chain_breaks"][:10]:
            print(
                f"  - Index {c['index']}: expected prev {c['expected_prev_hash'][:16]}..., "
                f"got {c['actual_prev_hash'][:16]}..."
            )

    print("=" * 60)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Verify audit chain integrity")
    parser.add_argument("--detailed", action="store_true", help="Recompute every hash in Python")
    parser.add_argument("--tamper-test", action="store_true", help="Run tamper detection test")
    args = parser.parse_args()

    if args.tamper_test:
        print("Running tamper detection test...")
        result = tamper_test()
        print(f"Direct UPDATE blocked: {result['update_blocked']}")
        print(f"Tamper detected: {result['tamper_detected']}")
        print(f"Details: {result['details']}")
        return 0 if result["tamper_detected"] and result["update_blocked"] else 1

    if args.detailed:
        print("Running detailed verification...")
        result = verify_audit_chain_detailed()
    else:
        print("Running standard verification...")
        result = verify_audit_chain()
    print_verification_report(result)
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
