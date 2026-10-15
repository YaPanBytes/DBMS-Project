"""Generate docs/DATA_DICTIONARY.md from the live schema plus column descriptions.

python scripts/data_dictionary.py      (needs a migrated database at DATABASE_URL)
"""

import sys
from pathlib import Path

from sqlalchemy import text

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from database.connection import engine  # noqa: E402

TABLES = {
    "organizations": (
        "Organizations taking part: NGOs, government agencies, funders, auditors.",
        {
            "org_id": "Surrogate key.",
            "name": "Display name.",
            "type": "Kind of organization.",
            "description": "Free-text description.",
            "contact_email": "General contact address.",
            "created_at": "When the row was created.",
            "updated_at": "Last change (maintained by trigger).",
        },
    ),
    "roles": (
        "RBAC lookup table. Every user has exactly one role.",
        {
            "role_id": "Fixed key (1 owner, 2 partner, 3 auditor, 4 admin).",
            "name": "Role name used by the API and RLS policies.",
            "description": "What the role may do.",
            "created_at": "When the row was created.",
        },
    ),
    "users": (
        "People acting for an organization. One table for every role.",
        {
            "user_id": "Surrogate key.",
            "org_id": "Organization the user acts for.",
            "role_id": "The user's role (roles lookup).",
            "email": "Sign-in email, stored lower-case; matched against Google accounts.",
            "password_hash": "bcrypt hash for local login; NULL for Google-only accounts.",
            "google_sub": "Google account id, linked on first Google sign-in.",
            "full_name": "Display name.",
            "is_active": "Deactivated users cannot sign in (users are never deleted once audited).",
            "last_login": "Time of the last successful sign-in.",
            "created_at": "When the row was created.",
            "updated_at": "Last change (maintained by trigger).",
        },
    ),
    "datasets": (
        "Datasets registered by data owners.",
        {
            "dataset_id": "Surrogate key; also names the data table data_<id>.",
            "owner_org_id": "Organization that owns the data.",
            "title": "Display title.",
            "description": "What the records are.",
            "category": "Free-form category (health, education, ...).",
            "status": "draft (not shared), published (in the catalogue), archived (read-only).",
            "version": "Incremented on metadata changes.",
            "created_at": "When the row was created.",
            "updated_at": "Last change (maintained by trigger).",
        },
    ),
    "dataset_fields": (
        "Columns of a dataset, the unit of consent.",
        {
            "field_id": "Surrogate key.",
            "dataset_id": "Dataset the field belongs to.",
            "name": "Column name in the data table (safe identifier).",
            "data_type": "Logical type; maps to a PostgreSQL type in the data table.",
            "sensitivity": "low / medium / high / pii; controls the mask shown when not consented.",
            "description": "What the field holds.",
            "is_encrypted": "Stored as pgcrypto ciphertext (BYTEA) in the data table.",
            "ordinal": "Display order.",
            "created_at": "When the row was created.",
            "updated_at": "Last change (maintained by trigger).",
        },
    ),
    "consent_grants": (
        "Per-field, purpose-bound, expiring, revocable consent. Resolves the "
        "many-to-many between organizations and datasets.",
        {
            "grant_id": "Surrogate key.",
            "grantor_org_id": "Organization giving consent (the dataset owner).",
            "grantee_org_id": "Organization receiving access.",
            "dataset_id": "Dataset concerned.",
            "field_id": "Field concerned (must belong to dataset_id: composite FK).",
            "purpose": "The purpose the grantee must state when reading.",
            "granted_at": "When consent was given.",
            "expires_at": "When consent ends (must be later than granted_at).",
            "revoked_at": "When consent was revoked; NULL while active.",
            "revoked_by": "User who revoked it.",
            "revocation_reason": "Why it was revoked ('Expired' for the scheduled job).",
            "updated_at": "Last change (maintained by trigger).",
        },
    ),
    "access_requests": (
        "Partners asking an owner for fields, for a purpose, until a date.",
        {
            "request_id": "Surrogate key.",
            "grantee_org_id": "Requesting organization.",
            "requested_by": "User who made the request.",
            "dataset_id": "Dataset requested.",
            "field_ids": "Requested fields (validated by request_access()).",
            "purpose": "Stated purpose.",
            "requested_expires_at": "Requested end of access.",
            "status": "pending / approved / denied / expired.",
            "decided_by": "Owner who decided.",
            "decided_at": "When it was decided.",
            "decision_note": "Note from the owner.",
            "created_at": "When the request was made.",
            "updated_at": "Last change (maintained by trigger).",
        },
    ),
    "audit_log": (
        "Append-only, hash-chained record of every read and change.",
        {
            "log_id": "Surrogate key.",
            "seq": "Position in the chain (assigned under a lock by trigger).",
            "user_id": "Acting user; NULL for system actions.",
            "dataset_id": "Dataset concerned.",
            "field_id": "Single field concerned (grants).",
            "field_ids": "Fields returned in clear text by a read.",
            "action": "What happened (select, insert, grant_create, grant_revoke, login, ...).",
            "rows_affected": "Rows read or written.",
            "query_text": "Description of the access (never row values).",
            "client_ip": "Client address, when known.",
            "user_agent": "Client user agent, when known.",
            "ts": "When it happened.",
            "prev_hash": "row_hash of the previous entry (32 zero bytes for the first).",
            "row_hash": "SHA-256 over prev_hash and every content column.",
        },
    ),
    "anomaly_alerts": (
        "Unusual access flagged by the AI detector.",
        {
            "alert_id": "Surrogate key.",
            "user_id": "User whose access was flagged.",
            "dataset_id": "Dataset most read in the flagged hour.",
            "score": "Anomaly score in [0, 1].",
            "reason": "Human-readable explanation.",
            "features": "Feature values for the flagged hour (JSON).",
            "detector": "isolation_forest, rule (baseline) or manual.",
            "status": "open / investigating / resolved / false_positive.",
            "created_at": "When the alert was raised.",
            "resolved_at": "When it was resolved.",
            "resolved_by": "User who resolved it.",
        },
    ),
    "revoked_tokens": (
        "JWT ids invalidated by logout (rejected until they expire).",
        {
            "jti": "Token id from the JWT.",
            "user_id": "Token owner.",
            "expires_at": "Token expiry (rows can be purged after this).",
            "revoked_at": "When the user signed out.",
        },
    ),
}

COLUMNS_SQL = """
SELECT c.column_name, c.data_type, c.udt_name, c.character_maximum_length, c.is_nullable,
       c.column_default, c.numeric_precision, c.numeric_scale
FROM information_schema.columns c
WHERE c.table_schema = 'public' AND c.table_name = :t
ORDER BY c.ordinal_position
"""
KEYS_SQL = """
SELECT a.attname,
       string_agg(CASE con.contype WHEN 'p' THEN 'PK' WHEN 'u' THEN 'UNIQUE'
                  WHEN 'f' THEN 'FK -> ' || confrel.relname END, ', ' ORDER BY con.contype)
FROM pg_constraint con
JOIN pg_class rel ON rel.oid = con.conrelid
JOIN LATERAL unnest(con.conkey) k(attnum) ON true
JOIN pg_attribute a ON a.attrelid = rel.oid AND a.attnum = k.attnum
LEFT JOIN pg_class confrel ON confrel.oid = con.confrelid
WHERE rel.relname = :t AND con.contype IN ('p', 'u', 'f')
GROUP BY a.attname
"""
CHECKS_SQL = """
SELECT pg_get_constraintdef(con.oid)
FROM pg_constraint con JOIN pg_class rel ON rel.oid = con.conrelid
WHERE rel.relname = :t AND con.contype = 'c' ORDER BY con.conname
"""


def type_name(row) -> str:
    _, data_type, udt, length, _, _, precision, scale = row
    if data_type == "character varying":
        return f"varchar({length})"
    if data_type == "ARRAY":
        return udt.lstrip("_") + "[]"
    if data_type == "numeric" and precision:
        return f"numeric({precision},{scale})"
    if data_type == "timestamp with time zone":
        return "timestamptz"
    return {"USER-DEFINED": udt}.get(data_type, data_type)


def tidy(check: str) -> str:
    for cast in ("::character varying[]", "::character varying", "::text[]", "::text"):
        check = check.replace(cast, "")
    return check.replace("|", "\\|")


def main() -> None:
    out = [
        "# Data Dictionary",
        "",
        "Generated from the live schema by `scripts/data_dictionary.py`; descriptions are "
        "maintained in that script. See `ER_DIAGRAM.md` for relationships and the 3NF "
        "justification.",
        "",
    ]
    with engine.connect() as conn:
        for table, (about, descriptions) in TABLES.items():
            cols = conn.execute(text(COLUMNS_SQL), {"t": table}).all()
            if not cols:
                continue
            keys = dict(conn.execute(text(KEYS_SQL), {"t": table}).all())
            checks = conn.execute(text(CHECKS_SQL), {"t": table}).scalars().all()
            out += [
                f"## {table}",
                "",
                about,
                "",
                "| Column | Type | Null | Default | Keys | Description |",
                "|---|---|---|---|---|---|",
            ]
            for row in cols:
                name, nullable, default = row[0], row[4], row[5]
                default = (default or "").replace("::character varying", "").replace("|", "\\|")
                out.append(
                    f"| `{name}` | {type_name(row)} | {'yes' if nullable == 'YES' else 'no'} | "
                    f"{f'`{default}`' if default else ''} | {keys.get(name, '')} | "
                    f"{descriptions.get(name, '')} |"
                )
            if checks:
                out += ["", "Check constraints:", ""]
                out += [f"- `{tidy(c)}`" for c in checks]
            out.append("")
    path = ROOT / "docs" / "DATA_DICTIONARY.md"
    path.write_text("\n".join(out))
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
