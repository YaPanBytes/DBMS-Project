"""
ConsentLedger Seed Data

Creates a demo world large enough for joins and aggregates to be meaningful:
organizations, users (one users table, roles via the roles lookup), datasets
with field schemas, real (synthetic) data rows loaded into each published
dataset (PII columns encrypted with pgcrypto), consent grants, pending access
requests, and ~30 days of access logs from ai.log_generator with injected
bulk-export and off-hours patterns. Finally the anomaly detector is run so the
dashboard has alerts to show.

    python -m database.seeds.seed_data            # seed (skips if data exists)
    python -m database.seeds.seed_data --clear    # wipe and re-seed
"""

import json
import os
import random
import sys
from datetime import UTC, date, datetime, timedelta

import bcrypt
from faker import Faker
from sqlalchemy import func, select, text

# Allow running as a plain script as well as with `python -m`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from database.connection import SessionLocal, init_db, set_rls_context  # noqa: E402
from database.models import (  # noqa: E402
    AccessRequest,
    ConsentGrant,
    Dataset,
    DatasetField,
    DatasetStatus,
    DataType,
    Organization,
    OrgType,
    RequestStatus,
    SensitivityLevel,
    User,
    UserRole,
)

fake = Faker("en_IN")
Faker.seed(42)
rng = random.Random(42)

DEMO_PASSWORD = "demo123"
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "dev-only-encryption-key-change-me")
LABELS_PATH = os.getenv("ANOMALY_LABELS_PATH", "ai/data/labels.csv")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


DEMO_PASSWORD_HASH = hash_password(DEMO_PASSWORD)


def utcnow() -> datetime:
    return datetime.now(UTC)


def set_acting_user(session, user: User) -> None:
    """Attribute audit-trigger entries in this transaction to `user`."""
    set_rls_context(session, user.user_id, user.org_id, encryption_key=ENCRYPTION_KEY)


# ============================================================================
# FIXTURE DEFINITIONS
# ============================================================================

ORGANIZATIONS = [
    ("Hope Foundation", OrgType.NGO, "NGO working on poverty relief"),
    ("Health Ministry", OrgType.GOVERNMENT, "Government health agency"),
    ("Global Fund", OrgType.FUNDER, "International funding organization"),
    ("Transparency Watch", OrgType.AUDITOR, "Independent audit organization"),
    ("EduCare Initiative", OrgType.NGO, "Education-focused NGO"),
    ("Disaster Relief Agency", OrgType.GOVERNMENT, "Emergency response agency"),
]

# (email, org, role, full name)
DEMO_USERS = [
    ("owner@hope.org", "Hope Foundation", UserRole.OWNER, "Maria Santos"),
    ("analyst@hope.org", "Hope Foundation", UserRole.PARTNER, "Arjun Mehta"),
    ("owner@health.gov", "Health Ministry", UserRole.OWNER, "Dr. Kavya Rao"),
    ("partner@health.gov", "Health Ministry", UserRole.PARTNER, "Dr. James Wilson"),
    ("funder@globalfund.org", "Global Fund", UserRole.PARTNER, "Sarah Chen"),
    ("analyst@globalfund.org", "Global Fund", UserRole.PARTNER, "Tom Okafor"),
    ("auditor@transparency.org", "Transparency Watch", UserRole.AUDITOR, "Robert Kim"),
    ("admin@consentledger.org", "Transparency Watch", UserRole.ADMIN, "Platform Admin"),
    ("owner@educare.org", "EduCare Initiative", UserRole.OWNER, "Priya Patel"),
    ("partner@educare.org", "EduCare Initiative", UserRole.PARTNER, "Leela Iyer"),
    ("owner@disaster.gov", "Disaster Relief Agency", UserRole.OWNER, "Imran Sheikh"),
    ("partner@disaster.gov", "Disaster Relief Agency", UserRole.PARTNER, "Carlos Rodriguez"),
]

P, H, M, L = (
    SensitivityLevel.PII,
    SensitivityLevel.HIGH,
    SensitivityLevel.MEDIUM,
    SensitivityLevel.LOW,
)
T, INT, N, B, D = DataType.TEXT, DataType.INTEGER, DataType.NUMERIC, DataType.BOOLEAN, DataType.DATE

# title -> (owner org, description, category, rows, [(field, type, sensitivity, encrypted, desc)])
DATASETS = {
    "Poverty Relief Beneficiaries 2024": (
        "Hope Foundation",
        "Beneficiary records for poverty relief program",
        "social_welfare",
        120,
        [
            ("beneficiary_id", T, P, False, "Unique beneficiary identifier"),
            ("full_name", T, P, True, "Full legal name"),
            ("date_of_birth", D, P, True, "Date of birth"),
            ("national_id", T, P, True, "Government ID number (Aadhaar)"),
            ("phone", T, P, True, "Contact phone number"),
            ("email", T, P, True, "Email address"),
            ("address", T, H, False, "Residential address"),
            ("district", T, L, False, "District of residence"),
            ("household_size", INT, M, False, "Number of household members"),
            ("income_level", N, H, False, "Monthly household income (INR)"),
            ("program_enrollment_date", D, L, False, "Date enrolled in program"),
            ("benefit_amount", N, H, False, "Monthly benefit amount (INR)"),
            ("status", T, L, False, "active / inactive / graduated"),
        ],
    ),
    "Nutrition Program Outcomes": (
        "Hope Foundation",
        "Monthly nutrition status tracking",
        "health",
        90,
        [
            ("child_id", T, P, False, "Child identifier"),
            ("height_cm", N, M, False, "Height in centimeters"),
            ("weight_kg", N, M, False, "Weight in kilograms"),
            ("muac_mm", INT, M, False, "Mid-upper arm circumference"),
            ("z_score_wfh", N, M, False, "Weight-for-height z-score"),
            ("assessment_date", D, L, False, "Date of assessment"),
            ("facility_id", T, L, False, "Health facility code"),
        ],
    ),
    "Vaccination Coverage Survey": (
        "Health Ministry",
        "District-level vaccination rates",
        "health",
        60,
        [
            ("district_code", T, L, False, "Administrative district code"),
            ("vaccine_type", T, L, False, "Vaccine name"),
            ("target_population", INT, L, False, "Eligible population"),
            ("doses_administered", INT, L, False, "Number of doses given"),
            ("coverage_percent", N, L, False, "Coverage percentage"),
            ("survey_date", D, L, False, "Survey date"),
        ],
    ),
    "Maternal Health Indicators": (
        "Health Ministry",
        "Prenatal and postnatal care metrics",
        "health",
        60,
        [
            ("facility_code", T, L, False, "Health facility identifier"),
            ("anc_visits", INT, M, False, "Antenatal care visits"),
            ("delivery_type", T, M, False, "normal / c-section"),
            ("birth_weight_kg", N, M, False, "Newborn weight"),
            ("maternal_mortality", B, H, False, "Maternal death flag"),
            ("reporting_month", D, L, False, "Report month"),
        ],
    ),
    "School Enrollment Tracker": (
        "EduCare Initiative",
        "Student enrollment and attendance",
        "education",
        80,
        [
            ("student_id", T, P, False, "Student identifier"),
            ("student_name", T, P, True, "Student name"),
            ("school_code", T, L, False, "School identifier"),
            ("grade_level", INT, L, False, "Current grade"),
            ("attendance_rate", N, M, False, "Attendance percentage"),
            ("enrollment_date", D, L, False, "Enrollment date"),
            ("dropout_risk", B, H, False, "Flagged as dropout risk"),
        ],
    ),
    "Emergency Shelter Registry": (
        "Disaster Relief Agency",
        "Displaced family shelter assignments",
        "emergency",
        70,
        [
            ("family_id", T, P, False, "Family identifier"),
            ("head_of_household", T, P, True, "Name of head of household"),
            ("contact_phone", T, P, True, "Contact phone"),
            ("shelter_site", T, L, False, "Shelter location code"),
            ("family_size", INT, M, False, "Number of family members"),
            ("arrival_date", D, L, False, "Date arrived at shelter"),
            ("vulnerability_score", INT, H, False, "Vulnerability assessment (0-10)"),
            ("aid_received", B, L, False, "Aid distribution flag"),
        ],
    ),
}

DISTRICTS = ["Pune", "Nagpur", "Nashik", "Thane", "Solapur", "Kolhapur", "Aurangabad", "Satara"]


def fake_value(name: str, dtype: DataType, i: int):  # noqa: PLR0911, PLR0912
    """Plausible synthetic value for a field, by name first, then by type."""
    day = date.today() - timedelta(days=rng.randint(0, 700))
    if name in ("full_name", "student_name", "head_of_household"):
        return fake.name()
    if name == "date_of_birth":
        return fake.date_of_birth(minimum_age=18, maximum_age=80).isoformat()
    if name == "national_id":
        return f"{rng.randint(2000, 9999)} {rng.randint(1000, 9999)} {rng.randint(1000, 9999)}"
    if name.endswith("_id") or name in ("facility_code", "school_code", "district_code"):
        prefix = "".join(w[0] for w in name.split("_")).upper()
        return f"{prefix}-{10000 + i}"
    if name in ("phone", "contact_phone"):
        return f"+91 {rng.randint(70000, 99999)} {rng.randint(10000, 99999)}"
    if name == "email":
        return fake.email()
    if name == "address":
        return fake.address().replace("\n", ", ")
    if name == "district":
        return rng.choice(DISTRICTS)
    if name == "status":
        return rng.choice(["active", "active", "active", "inactive", "graduated"])
    if name == "vaccine_type":
        return rng.choice(["BCG", "OPV", "DPT", "Measles", "Hepatitis B"])
    if name == "delivery_type":
        return rng.choice(["normal", "normal", "c-section"])
    if name == "shelter_site":
        return f"SITE-{rng.randint(1, 12):02d}"
    if name in ("income_level", "benefit_amount"):
        return round(rng.uniform(2000, 15000 if name == "income_level" else 3000), 2)
    if name in ("coverage_percent", "attendance_rate"):
        return round(rng.uniform(55, 99), 1)
    if name == "z_score_wfh":
        return round(rng.gauss(-0.8, 1.1), 2)
    if name == "height_cm":
        return round(rng.uniform(65, 120), 1)
    if name in ("weight_kg", "birth_weight_kg"):
        return round(rng.uniform(2.2, 4.2) if name == "birth_weight_kg" else rng.uniform(7, 25), 2)
    if dtype == DataType.INTEGER:
        return rng.randint(1, 12 if "size" in name or "visits" in name or "grade" in name else 5000)
    if dtype == DataType.NUMERIC:
        return round(rng.uniform(0, 1000), 2)
    if dtype == DataType.BOOLEAN:
        return rng.random() < 0.15
    if dtype == DataType.DATE:
        return day.isoformat()
    return fake.word()


# ============================================================================
# SEEDING STEPS
# ============================================================================


def seed_organizations(session) -> dict[str, Organization]:
    orgs = {}
    for name, org_type, desc in ORGANIZATIONS:
        org = Organization(
            name=name,
            type=org_type,
            description=desc,
            contact_email=f"contact@{name.lower().replace(' ', '')}.org",
        )
        session.add(org)
        orgs[name] = org
    session.flush()
    return orgs


def seed_users(session, orgs: dict[str, Organization]) -> dict[str, User]:
    users = {}
    for email, org_name, role, full_name in DEMO_USERS:
        user = User(
            org_id=orgs[org_name].id,
            email=email,
            password_hash=DEMO_PASSWORD_HASH,
            role=role,
            full_name=full_name,
        )
        session.add(user)
        users[email] = user
    # one more staff member per organization
    for org in orgs.values():
        if org.type == OrgType.AUDITOR:
            continue
        email = f"staff@{org.name.lower().replace(' ', '')}.org"
        user = User(
            org_id=org.id,
            email=email,
            password_hash=DEMO_PASSWORD_HASH,
            role=UserRole.PARTNER,
            full_name=fake.name(),
        )
        session.add(user)
        users[email] = user
    session.flush()
    return users


def seed_datasets(
    session, orgs, users
) -> tuple[dict[str, Dataset], dict[str, dict[str, DatasetField]]]:
    datasets, fields = {}, {}
    owners = {u.org_id: u for u in users.values() if u.role == UserRole.OWNER}
    for title, (org_name, desc, category, n_rows, schema) in DATASETS.items():
        owner = owners[orgs[org_name].id]
        set_acting_user(session, owner)
        ds = Dataset(
            owner_org_id=orgs[org_name].id,
            title=title,
            description=desc,
            category=category,
            status=DatasetStatus.PUBLISHED,
        )
        session.add(ds)
        session.flush()
        fields[title] = {}
        for ordinal, (name, dtype, sens, enc, fdesc) in enumerate(schema):
            f = DatasetField(
                dataset_id=ds.id,
                name=name,
                data_type=dtype,
                sensitivity=sens,
                is_encrypted=enc,
                description=fdesc,
                ordinal=ordinal,
            )
            session.add(f)
            fields[title][name] = f
        session.flush()

        # Physical table + masked view, then load rows through the audited,
        # encrypting ingest function (as the owner)
        session.execute(text("SELECT create_dataset_data_table(:d)"), {"d": ds.id})
        rows = [
            {name: fake_value(name, dtype, i) for name, dtype, *_ in schema} for i in range(n_rows)
        ]
        session.execute(
            text("SELECT ingest_dataset_rows(:d, CAST(:rows AS jsonb))"),
            {"d": ds.id, "rows": json.dumps(rows)},
        )
        datasets[title] = ds
    # a draft dataset (not yet shared)
    draft_owner = owners[orgs["EduCare Initiative"].id]
    set_acting_user(session, draft_owner)
    draft = Dataset(
        owner_org_id=draft_owner.org_id,
        title="Teacher Training Survey (draft)",
        description="Pilot survey, not yet published",
        category="education",
    )
    session.add(draft)
    session.flush()
    session.add(
        DatasetField(
            dataset_id=draft.id, name="teacher_name", data_type=T, sensitivity=P, ordinal=0
        )
    )
    session.add(
        DatasetField(
            dataset_id=draft.id, name="training_hours", data_type=INT, sensitivity=L, ordinal=1
        )
    )
    session.flush()
    datasets[draft.title] = draft
    return datasets, fields


GRANTS = [
    # grantor dataset, grantee org, fields, purpose, days
    (
        "Poverty Relief Beneficiaries 2024",
        "Global Fund",
        [
            "beneficiary_id",
            "district",
            "household_size",
            "income_level",
            "benefit_amount",
            "status",
        ],
        "impact_evaluation",
        180,
    ),
    (
        "Nutrition Program Outcomes",
        "Health Ministry",
        ["child_id", "height_cm", "weight_kg", "z_score_wfh", "assessment_date"],
        "malnutrition_surveillance",
        120,
    ),
    (
        "Vaccination Coverage Survey",
        "Global Fund",
        [
            "district_code",
            "vaccine_type",
            "target_population",
            "doses_administered",
            "coverage_percent",
            "survey_date",
        ],
        "program_monitoring",
        365,
    ),
    (
        "Maternal Health Indicators",
        "Hope Foundation",
        ["facility_code", "anc_visits", "birth_weight_kg", "reporting_month"],
        "community_health_outreach",
        90,
    ),
    (
        "School Enrollment Tracker",
        "Global Fund",
        ["school_code", "grade_level", "attendance_rate", "dropout_risk"],
        "education_grant_reporting",
        200,
    ),
]

REQUESTS = [
    (
        "Emergency Shelter Registry",
        "Health Ministry",
        "partner@health.gov",
        ["family_id", "family_size", "vulnerability_score", "shelter_site"],
        "disease_outbreak_response",
        60,
    ),
    (
        "Poverty Relief Beneficiaries 2024",
        "Disaster Relief Agency",
        "partner@disaster.gov",
        ["beneficiary_id", "district", "household_size", "phone"],
        "emergency_cash_transfer",
        30,
    ),
    (
        "Nutrition Program Outcomes",
        "Global Fund",
        "funder@globalfund.org",
        ["height_cm", "weight_kg", "z_score_wfh"],
        "impact_evaluation",
        90,
    ),
]


def seed_grants_and_requests(session, orgs, users, datasets, fields) -> tuple[list, list]:
    grants, requests = [], []
    owners = {u.org_id: u for u in users.values() if u.role == UserRole.OWNER}
    now = utcnow()
    for title, grantee, field_names, purpose, days in GRANTS:
        ds = datasets[title]
        set_acting_user(session, owners[ds.owner_org_id])
        for name in field_names:
            g = ConsentGrant(
                grantor_org_id=ds.owner_org_id,
                grantee_org_id=orgs[grantee].id,
                dataset_id=ds.id,
                field_id=fields[title][name].id,
                purpose=purpose,
                granted_at=now - timedelta(days=35),
                expires_at=now + timedelta(days=days),
            )
            session.add(g)
            grants.append(g)
        session.flush()

    for title, grantee, email, field_names, purpose, days in REQUESTS:
        ds = datasets[title]
        set_acting_user(session, users[email])
        r = AccessRequest(
            grantee_org_id=orgs[grantee].id,
            requested_by=users[email].id,
            dataset_id=ds.id,
            field_ids=[fields[title][n].id for n in field_names],
            purpose=purpose,
            requested_expires_at=now + timedelta(days=days),
            status=RequestStatus.PENDING,
        )
        session.add(r)
        requests.append(r)
        session.flush()
    return grants, requests


def seed_access_logs(session) -> int:
    """~30 days of reads with injected anomalies (labels saved for evaluation)."""
    from ai.log_generator import actors_from_grants, generate_access_log, save_labels, write_events

    actors = actors_from_grants(session)
    events = generate_access_log(actors, days=30, n_bulk_exports=2, n_off_hours=3, seed=7)
    labels = write_events(session, events)
    try:
        save_labels(labels, LABELS_PATH)
    except OSError as e:  # read-only checkout etc.
        print(f"  (could not save labels: {e})")
    return len(labels)


def run_detector() -> int:
    try:
        from ai.anomaly import detect_and_store
    except ImportError as e:  # scikit-learn not installed
        print(f"  Skipping anomaly detection ({e})")
        return 0
    return detect_and_store()["alerts_written"]


def seed_all() -> dict:
    """Run complete seeding process."""
    print("Applying migrations...")
    if init_db() != 0:
        raise RuntimeError("Migrations failed; not seeding")

    db = SessionLocal()
    try:
        existing = db.scalar(select(func.count()).select_from(Organization))
        if existing:
            print(f"Database already has {existing} organizations. Skipping seed.")
            return {"status": "skipped", "reason": "already_seeded"}

        print("Seeding organizations and users...")
        orgs = seed_organizations(db)
        users = seed_users(db, orgs)
        print(f"  {len(orgs)} organizations, {len(users)} users")

        print("Seeding datasets, fields and data rows...")
        datasets, fields = seed_datasets(db, orgs, users)
        n_fields = sum(len(v) for v in fields.values()) + 2
        print(f"  {len(datasets)} datasets, {n_fields} fields")

        print("Seeding consent grants and access requests...")
        grants, requests = seed_grants_and_requests(db, orgs, users, datasets, fields)
        print(f"  {len(grants)} grants, {len(requests)} pending requests")

        print("Generating access logs...")
        db.execute(text("RESET consentledger.current_user_id"))
        n_logs = seed_access_logs(db)
        print(f"  {n_logs} access events")

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"\n✗ Seeding failed: {e}")
        raise
    finally:
        db.close()

    print("Running anomaly detector...")
    n_alerts = run_detector()
    print(f"  {n_alerts} alerts")
    print("\n✓ Seeding completed successfully!")
    print(
        f"  Demo logins (password '{DEMO_PASSWORD}'): owner@hope.org, funder@globalfund.org, "
        "auditor@transparency.org, admin@consentledger.org"
    )
    return {
        "status": "success",
        "organizations": len(orgs),
        "users": len(users),
        "datasets": len(datasets),
        "fields": n_fields,
        "grants": len(grants),
        "requests": len(requests),
        "access_events": n_logs,
        "alerts": n_alerts,
    }


def clear_all() -> None:
    """Clear all data (use with caution!).

    Uses TRUNCATE because audit_log rejects DELETE. TRUNCATE also resets the
    audit chain, which is only appropriate for a demo/dev database.
    """
    db = SessionLocal()
    try:
        db.execute(text("""
            DO $$
            DECLARE r RECORD;
            BEGIN
                FOR r IN SELECT tablename FROM pg_tables
                         WHERE schemaname = 'public' AND tablename ~ '^data_[0-9a-f_]{36}$'
                LOOP
                    EXECUTE format('DROP TABLE %I CASCADE', r.tablename);
                END LOOP;
            END $$
        """))
        db.execute(text("""
            TRUNCATE revoked_tokens, anomaly_alerts, audit_log, access_requests, consent_grants,
                     dataset_fields, datasets, users, organizations
            RESTART IDENTITY CASCADE
        """))
        db.execute(text("SELECT setval('audit_log_chain_seq', 1, false)"))
        db.commit()
        print("All data cleared.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ConsentLedger seed data")
    parser.add_argument("--clear", action="store_true", help="Clear all data before seeding")
    args = parser.parse_args()

    if args.clear:
        print("Clearing existing data...")
        clear_all()

    result = seed_all()
    print(f"\nResult: {result}")
