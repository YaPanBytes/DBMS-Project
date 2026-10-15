"""
ConsentLedger Audit Chain Verification
Member A: Database Lead
Verifies the integrity of the hash-chained audit log.
"""

import os
import sys
from sqlalchemy import text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import get_engine


def verify_audit_chain() -> dict:
    """Verify the complete audit chain integrity."""
    engine = get_engine()
    
    result = {
        "valid": False,
        "total_rows": 0,
        "verified_rows": 0,
        "first_error": None,
        "errors": []
    }
    
    try:
        with engine.connect() as conn:
            # Call the database function
            rows = conn.execute(text("SELECT * FROM verify_audit_chain()")).fetchall()
            
            result["total_rows"] = len(rows)
            
            for row in rows:
                log_id, expected_hash, actual_hash, is_valid, error_msg = row
                if is_valid:
                    result["verified_rows"] += 1
                else:
                    result["errors"].append({
                        "log_id": str(log_id),
                        "expected_hash": expected_hash.hex() if expected_hash else None,
                        "actual_hash": actual_hash.hex() if actual_hash else None,
                        "error": error_msg
                    })
                    if result["first_error"] is None:
                        result["first_error"] = {
                            "log_id": str(log_id),
                            "error": error_msg
                        }
            
            result["valid"] = len(result["errors"]) == 0
            
    except Exception as e:
        result["errors"].append({"error": f"Verification failed: {str(e)}"})
    
    return result


def verify_audit_chain_detailed() -> dict:
    """Detailed verification with manual hash computation."""
    engine = get_engine()
    
    result = {
        "valid": False,
        "total_rows": 0,
        "verified_rows": 0,
        "mismatches": [],
        "chain_breaks": [],
        "orphaned_rows": 0
    }
    
    try:
        with engine.connect() as conn:
            # Get all audit logs in order
            rows = conn.execute(text("""
                SELECT log_id, user_id, dataset_id, action, ts, prev_hash, row_hash
                FROM audit_log
                ORDER BY ts ASC, log_id ASC
            """)).fetchall()
            
            result["total_rows"] = len(rows)
            
            expected_prev = b'\x00' * 32
            
            for i, row in enumerate(rows):
                log_id, user_id, dataset_id, action, ts, prev_hash, row_hash = row
                
                # Check chain linkage
                if prev_hash != expected_prev:
                    result["chain_breaks"].append({
                        "index": i,
                        "log_id": str(log_id),
                        "expected_prev_hash": expected_prev.hex(),
                        "actual_prev_hash": prev_hash.hex()
                    })
                
                # Recompute row hash
                import hashlib
                computed = hashlib.sha256(
                    prev_hash +
                    str(user_id).encode() +
                    (str(dataset_id).encode() if dataset_id else b'') +
                    action.encode() +
                    ts.isoformat().encode()
                ).digest()
                
                if computed != row_hash:
                    result["mismatches"].append({
                        "index": i,
                        "log_id": str(log_id),
                        "expected_hash": computed.hex(),
                        "actual_hash": row_hash.hex()
                    })
                else:
                    result["verified_rows"] += 1
                
                expected_prev = row_hash
            
            result["valid"] = len(result["mismatches"]) == 0 and len(result["chain_breaks"]) == 0
            
    except Exception as e:
        result["mismatches"].append({"error": f"Verification failed: {str(e)}"})
    
    return result


def tamper_test() -> dict:
    """Test tamper detection by temporarily modifying a row."""
    engine = get_engine()
    
    result = {
        "tamper_detected": False,
        "details": ""
    }
    
    try:
        with engine.connect() as conn:
            trans = conn.begin()
            try:
                # Get a row to tamper with
                row = conn.execute(text("""
                    SELECT log_id, row_hash FROM audit_log ORDER BY ts LIMIT 1
                """)).fetchone()
                
                if not row:
                    result["details"] = "No audit logs to test"
                    trans.rollback()
                    return result
                
                log_id, original_hash = row
                
                # Tamper: change the hash
                tampered_hash = b'\xff' * 32
                conn.execute(text("UPDATE audit_log SET row_hash = :h WHERE log_id = :id"),
                           {"h": tampered_hash, "id": log_id})
                
                # Verify should now fail
                verify_result = conn.execute(text("SELECT is_audit_chain_valid()")).scalar()
                
                if not verify_result:
                    result["tamper_detected"] = True
                    result["details"] = f"Tamper detected on log {log_id}"
                else:
                    result["details"] = "Tamper NOT detected - chain validation failed"
                
                trans.rollback()  # Always rollback the tamper
                
            except Exception as e:
                trans.rollback()
                result["details"] = f"Test error: {str(e)}"
                
    except Exception as e:
        result["details"] = f"Connection error: {str(e)}"
    
    return result


def print_verification_report(result: dict) -> None:
    """Print a formatted verification report."""
    print("=" * 60)
    print("AUDIT CHAIN VERIFICATION REPORT")
    print("=" * 60)
    print(f"Status: {'✓ VALID' if result['valid'] else '✗ INVALID'}")
    print(f"Total Rows: {result['total_rows']}")
    print(f"Verified: {result['verified_rows']}")
    print(f"Errors: {len(result.get('errors', [])) + len(result.get('mismatches', [])) + len(result.get('chain_breaks', []))}")
    
    if result.get("first_error"):
        print(f"\nFirst Error:")
        print(f"  Log ID: {result['first_error']['log_id']}")
        print(f"  Error: {result['first_error']['error']}")
    
    if result.get("errors"):
        print(f"\nAll Errors ({len(result['errors'])}):")
        for e in result["errors"][:10]:
            print(f"  - Log {e['log_id']}: {e['error']}")
    
    if result.get("mismatches"):
        print(f"\nHash Mismatches ({len(result['mismatches'])}):")
        for m in result["mismatches"][:10]:
            print(f"  - Log {m['log_id']}: expected {m['expected_hash'][:16]}..., got {m['actual_hash'][:16]}...")
    
    if result.get("chain_breaks"):
        print(f"\nChain Breaks ({len(result['chain_breaks'])}):")
        for c in result["chain_breaks"][:10]:
            print(f"  - Index {c['index']}: expected prev {c['expected_prev_hash'][:16]}..., got {c['actual_prev_hash'][:16]}...")
    
    print("=" * 60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Verify audit chain integrity")
    parser.add_argument("--detailed", action="store_true", help="Run detailed verification")
    parser.add_argument("--tamper-test", action="store_true", help="Run tamper detection test")
    args = parser.parse_args()
    
    if args.tamper_test:
        print("Running tamper detection test...")
        result = tamper_test()
        print(f"Tamper detected: {result['tamper_detected']}")
        print(f"Details: {result['details']}")
    elif args.detailed:
        print("Running detailed verification...")
        result = verify_audit_chain_detailed()
        print_verification_report(result)
    else:
        print("Running standard verification...")
        result = verify_audit_chain()
        print_verification_report(result)
    
    sys.exit(0 if result["valid"] else 1)