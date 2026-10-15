"""
ConsentLedger Seed Data
Member A: Database Lead
Generates synthetic organizations, datasets, fields, users, grants, and audit logs for demo.
"""

import os
import sys
from datetime import datetime, timedelta
from uuid import uuid4
from faker import Faker

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import SessionLocal, init_db
from database.models import (
    Base, Organization, User, Dataset, DatasetField,
    ConsentGrant, AccessRequest, AuditLog, AnomalyAlert,
    OrgType, UserRole, DatasetStatus, SensitivityLevel,
    DataType, RequestStatus, AuditAction, AlertStatus
)
from passlib.context import CryptContext

fake = Faker()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def seed_organizations(session, count: int = 6) -> list:
    """Create synthetic organizations."""
    org_types = [OrgType.NGO, OrgType.GOVERNMENT, OrgType.FUNDER, OrgType.AUDITOR]
    orgs = []
    
    # Fixed orgs for consistent demo
    fixed_orgs = [
        ("Hope Foundation", OrgType.NGO, "NGO working on poverty relief"),
        ("Health Ministry", OrgType.GOVERNMENT, "Government health agency"),
        ("Global Fund", OrgType.FUNDER, "International funding organization"),
        ("Transparency Watch", OrgType.AUDITOR, "Independent audit organization"),
        ("EduCare Initiative", OrgType.NGO, "Education-focused NGO"),
        ("Disaster Relief Agency", OrgType.GOVERNMENT, "Emergency response agency"),
    ]
    
    for name, org_type, desc in fixed_orgs:
        org = Organization(
            name=name,
            type=org_type,
            description=desc,
            contact_email=f"contact@{name.lower().replace(' ', '')}.org"
        )
        session.add(org)
        orgs.append(org)
    
    # Additional random orgs
    for _ in range(count - len(fixed_orgs)):
        org_type = fake.random_element(org_types)
        org = Organization(
            name=fake.company(),
            type=org_type,
            description=fake.catch_phrase(),
            contact_email=fake.company_email()
        )
        session.add(org)
        orgs.append(org)
    
    session.flush()
    return orgs


def seed_users(session, orgs: list) -> list:
    """Create users for each organization."""
    users = []
    
    # Fixed demo users
    demo_users = [
        ("owner@hope.org", "Hope Foundation", UserRole.OWNER, "Maria Santos"),
        ("partner@health.gov", "Health Ministry", UserRole.PARTNER, "Dr. James Wilson"),
        ("funder@globalfund.org", "Global Fund", UserRole.PARTNER, "Sarah Chen"),
        ("auditor@transparency.org", "Transparency Watch", UserRole.AUDITOR, "Robert Kim"),
        ("owner@educare.org", "EduCare Initiative", UserRole.OWNER, "Priya Patel"),
        ("partner@disaster.gov", "Disaster Relief Agency", UserRole.PARTNER, "Carlos Rodriguez"),
    ]
    
    org_by_name = {o.name: o for o in orgs}
    
    for email, org_name, role, full_name in demo_users:
        org = org_by_name.get(org_name)
        if not org:
            continue
        user = User(
            org_id=org.id,
            email=email,
            password_hash=hash_password("demo123"),
            role=role,
            full_name=full_name,
            is_active=True
        )
        session.add(user)
        users.append(user)
    
    # Additional users per org
    for org in orgs:
        existing_emails = {u.email for u in users if u.org_id == org.id}
        for i in range(2):  # 2 extra users per org
            email = f"user{i+1}@{org.name.lower().replace(' ', '')}.org"
            if email in existing_emails:
                continue
            user = User(
                org_id=org.id,
                email=email,
                password_hash=hash_password("demo123"),
                role=fake.random_element([UserRole.OWNER, UserRole.PARTNER]),
                full_name=fake.name(),
                is_active=True
            )
            session.add(user)
            users.append(user)
    
    session.flush()
    return users


def seed_datasets(session, orgs: list) -> list:
    """Create synthetic datasets."""
    datasets = []
    
    # Fixed demo datasets
    demo_datasets = [
        ("Hope Foundation", "Poverty Relief Beneficiaries 2024", 
         "Beneficiary records for poverty relief program", "social_welfare"),
        ("Hope Foundation", "Nutrition Program Outcomes",
         "Monthly nutrition status tracking", "health"),
        ("Health Ministry", "Vaccination Coverage Survey",
         "District-level vaccination rates", "health"),
        ("Health Ministry", "Maternal Health Indicators",
         "Prenatal and postnatal care metrics", "health"),
        ("EduCare Initiative", "School Enrollment Tracker",
         "Student enrollment and attendance", "education"),
        ("Disaster Relief Agency", "Emergency Shelter Registry",
         "Displaced family shelter assignments", "emergency"),
    ]
    
    for org_name, title, desc, category in demo_datasets:
        org = next((o for o in orgs if o.name == org_name), None)
        if not org:
            continue
        ds = Dataset(
            owner_org_id=org.id,
            title=title,
            description=desc,
            category=category,
            status=DatasetStatus.PUBLISHED
        )
        session.add(ds)
        datasets.append(ds)
    
    session.flush()
    return datasets


def seed_fields(session, datasets: list) -> list:
    """Create fields for each dataset."""
    fields = []
    
    # Define field schemas per dataset
    field_schemas = {
        "Poverty Relief Beneficiaries 2024": [
            ("beneficiary_id", DataType.TEXT, SensitivityLevel.PII, True, "Unique beneficiary identifier"),
            ("full_name", DataType.TEXT, SensitivityLevel.PII, True, "Full legal name"),
            ("date_of_birth", DataType.DATE, SensitivityLevel.PII, True, "Date of birth"),
            ("national_id", DataType.TEXT, SensitivityLevel.PII, True, "Government ID number"),
            ("phone", DataType.TEXT, SensitivityLevel.PII, True, "Contact phone number"),
            ("email", DataType.TEXT, SensitivityLevel.PII, True, "Email address"),
            ("address", DataType.TEXT, SensitivityLevel.HIGH, False, "Residential address"),
            ("household_size", DataType.INTEGER, SensitivityLevel.MEDIUM, False, "Number of household members"),
            ("income_level", DataType.NUMERIC, SensitivityLevel.HIGH, False, "Monthly household income"),
            ("program_enrollment_date", DataType.DATE, SensitivityLevel.LOW, False, "Date enrolled in program"),
            ("benefit_amount", DataType.NUMERIC, SensitivityLevel.HIGH, False, "Monthly benefit amount"),
            ("status", DataType.TEXT, SensitivityLevel.LOW, False, "Active/inactive/graduated"),
        ],
        "Nutrition Program Outcomes": [
            ("child_id", DataType.TEXT, SensitivityLevel.PII, True, "Child identifier"),
            ("height_cm", DataType.NUMERIC, SensitivityLevel.MEDIUM, False, "Height in centimeters"),
            ("weight_kg", DataType.NUMERIC, SensitivityLevel.MEDIUM, False, "Weight in kilograms"),
            ("muac_mm", DataType.INTEGER, SensitivityLevel.MEDIUM, False, "Mid-upper arm circumference"),
            ("z_score_wfh", DataType.NUMERIC, SensitivityLevel.MEDIUM, False, "Weight-for-height z-score"),
            ("assessment_date", DataType.DATE, SensitivityLevel.LOW, False, "Date of assessment"),
            ("facility_id", DataType.TEXT, SensitivityLevel.LOW, False, "Health facility code"),
        ],
        "Vaccination Coverage Survey": [
            ("district_code", DataType.TEXT, SensitivityLevel.LOW, False, "Administrative district code"),
            ("vaccine_type", DataType.TEXT, SensitivityLevel.LOW, False, "Vaccine name"),
            ("target_population", DataType.INTEGER, SensitivityLevel.LOW, False, "Eligible population"),
            ("doses_administered", DataType.INTEGER, SensitivityLevel.LOW, False, "Number of doses given"),
            ("coverage_percent", DataType.NUMERIC, SensitivityLevel.LOW, False, "Coverage percentage"),
            ("survey_date", DataType.DATE, SensitivityLevel.LOW, False, "Survey date"),
        ],
        "Maternal Health Indicators": [
            ("facility_code", DataType.TEXT, SensitivityLevel.LOW, False, "Health facility identifier"),
            ("anc_visits", DataType.INTEGER, SensitivityLevel.MEDIUM, False, "Antenatal care visits"),
            ("delivery_type", DataType.TEXT, SensitivityLevel.MEDIUM, False, "Normal/C-section"),
            ("birth_weight_kg", DataType.NUMERIC, SensitivityLevel.MEDIUM, False, "Newborn weight"),
            ("maternal_mortality", DataType.BOOLEAN, SensitivityLevel.HIGH, False, "Maternal death flag"),
            ("reporting_month", DataType.DATE, SensitivityLevel.LOW, False, "Report month"),
        ],
        "School Enrollment Tracker": [
            ("student_id", DataType.TEXT, SensitivityLevel.PII, True, "Student identifier"),
            ("school_code", DataType.TEXT, SensitivityLevel.LOW, False, "School identifier"),
            ("grade_level", DataType.INTEGER, SensitivityLevel.LOW, False, "Current grade"),
            ("attendance_rate", DataType.NUMERIC, SensitivityLevel.MEDIUM, False, "Attendance percentage"),
            ("enrollment_date", DataType.DATE, SensitivityLevel.LOW, False, "Enrollment date"),
            ("dropout_risk", DataType.BOOLEAN, SensitivityLevel.HIGH, False, "Flagged as dropout risk"),
        ],
        "Emergency Shelter Registry": [
            ("family_id", DataType.TEXT, SensitivityLevel.PII, True, "Family identifier"),
            ("shelter_site", DataType.TEXT, SensitivityLevel.LOW, False, "Shelter location code"),
            ("family_size", DataType.INTEGER, SensitivityLevel.MEDIUM, False, "Number of family members"),
            ("arrival_date", DataType.DATE, SensitivityLevel.LOW, False, "Date arrived at shelter"),
            ("vulnerability_score", DataType.INTEGER, SensitivityLevel.HIGH, False, "Vulnerability assessment"),
            ("aid_received", DataType.BOOLEAN, SensitivityLevel.LOW, False, "Aid distribution flag"),
        ],
    }
    
    for ds in datasets:
        schema = field_schemas.get(ds.title, [])
        for ordinal, (name, dtype, sens, encrypted, desc) in enumerate(schema):
            field = DatasetField(
                dataset_id=ds.id,
                name=name,
                data_type=dtype,
                sensitivity=sens,
                description=desc,
                is_encrypted=encrypted,
                ordinal=ordinal
            )
            session.add(field)
            fields.append(field)
    
    session.flush()
    return fields


def seed_grants_and_requests(session, orgs: list, datasets: list, fields: list, users: list) -> tuple:
    """Create consent grants and access requests."""
    grants = []
    requests = []
    
    org_by_name = {o.name: o for o in orgs}
    fields_by_dataset = {}
    for f in fields:
        fields_by_dataset.setdefault(f.dataset_id, []).append(f)
    
    # Demo: Global Fund requests access to Hope Foundation's poverty data
    hope = org_by_name["Hope Foundation"]
    global_fund = org_by_name["Global Fund"]
    health_ministry = org_by_name["Health Ministry"]
    transparency = org_by_name["Transparency Watch"]
    
    poverty_ds = next(d for d in datasets if d.title == "Poverty Relief Beneficiaries 2024")
    nutrition_ds = next(d for d in datasets if d.title == "Nutrition Program Outcomes")
    vaccination_ds = next(d for d in datasets if d.title == "Vaccination Coverage Survey")
    
    poverty_fields = fields_by_dataset[poverty_ds.id]
    nutrition_fields = fields_by_dataset[nutrition_ds.id]
    vaccination_fields = fields_by_dataset[vaccination_ds.id]
    
    # Grant: Global Fund gets access to selected poverty fields
    gf_user = next(u for u in users if u.email == "funder@globalfund.org")
    hope_owner = next(u for u in users if u.email == "owner@hope.org")
    
    grant_fields = [
        (f.field_id, "impact_evaluation", timedelta(days=180))
        for f in poverty_fields
        if f.name in ["beneficiary_id", "household_size", "income_level", "benefit_amount", "status"]
    ]
    
    for field_id, purpose, expires_delta in grant_fields:
        grant = ConsentGrant(
            grantor_org_id=hope.id,
            grantee_org_id=global_fund.id,
            dataset_id=poverty_ds.id,
            field_id=field_id,
            purpose=purpose,
            expires_at=datetime.utcnow() + expires_delta,
            revoked_at=None
        )
        session.add(grant)
        grants.append(grant)
    
    # Grant: Health Ministry gets vaccination data
    hm_user = next(u for u in users if u.email == "partner@health.gov")
    
    for field_id in [f.field_id for f in vaccination_fields]:
        grant = ConsentGrant(
            grantor_org_id=health_ministry.id,
            grantee_org_id=global_fund.id,
            dataset_id=vaccination_ds.id,
            field_id=field_id,
            purpose="program_monitoring",
            expires_at=datetime.utcnow() + timedelta(days=365),
            revoked_at=None
        )
        session.add(grant)
        grants.append(grant)
    
    # Access request: Health Ministry requests nutrition data
    hm_nutrition_fields = [f.field_id for f in nutrition_fields 
                           if f.name in ["child_id", "height_cm", "weight_kg", "z_score_wfh", "assessment_date"]]
    
    req = AccessRequest(
        grantee_org_id=health_ministry.id,
        dataset_id=nutrition_ds.id,
        field_ids=hm_nutrition_fields,
        purpose="malnutrition_surveillance",
        requested_expires_at=datetime.utcnow() + timedelta(days=90),
        status=RequestStatus.PENDING
    )
    session.add(req)
    requests.append(req)
    
    # Access request: Disaster Relief Agency requests shelter data
    disaster = org_by_name["Disaster Relief Agency"]
    shelter_ds = next(d for d in datasets if d.title == "Emergency Shelter Registry")
    shelter_fields = fields_by_dataset[shelter_ds.id]
    
    req2 = AccessRequest(
        grantee_org_id=disaster.id,
        dataset_id=shelter_ds.id,
        field_ids=[f.field_id for f in shelter_fields],
        purpose="emergency_response_coordination",
        requested_expires_at=datetime.utcnow() + timedelta(days=30),
        status=RequestStatus.PENDING
    )
    session.add(req2)
    requests.append(req2)
    
    session.flush()
    return grants, requests


def seed_audit_logs(session, users: list, datasets: list, grants: list, count: int = 500) -> list:
    """Generate synthetic audit log entries with hash chain."""
    from sqlalchemy import func
    from sqlalchemy.dialects.postgresql import BYTEA
    import hashlib
    
    logs = []
    prev_hash = b'\x00' * 32  # Initial hash (32 bytes)
    
    # Get some users and datasets for variety
    active_users = [u for u in users if u.is_active]
    published_datasets = [d for d in datasets if d.status == DatasetStatus.PUBLISHED]
    
    actions = [AuditAction.SELECT, AuditAction.INSERT, AuditAction.UPDATE, 
               AuditAction.GRANT_CREATE, AuditAction.REQUEST_CREATE, AuditAction.LOGIN]
    
    base_time = datetime.utcnow() - timedelta(days=30)
    
    for i in range(count):
        user = fake.random_element(active_users)
        dataset = fake.random_element(published_datasets) if fake.boolean(0.7) else None
        action = fake.random_element(actions)
        
        ts = base_time + timedelta(minutes=i * 10 + fake.random_int(0, 5))
        rows_affected = fake.random_int(1, 1000) if action == AuditAction.SELECT else fake.random_int(0, 10)
        
        # Compute hash chain
        hash_input = prev_hash + str(user.id).encode() + \
                     (str(dataset.id).encode() if dataset else b'') + \
                     action.value.encode() + ts.isoformat().encode()
        row_hash = hashlib.sha256(hash_input).digest()
        
        log = AuditLog(
            user_id=user.id,
            dataset_id=dataset.id if dataset else None,
            action=action,
            rows_affected=rows_affected,
            query_text=f"SELECT * FROM data_{dataset.id} LIMIT {rows_affected}" if action == AuditAction.SELECT and dataset else None,
            client_ip=fake.ipv4(),
            user_agent=fake.user_agent(),
            ts=ts,
            prev_hash=prev_hash,
            row_hash=row_hash
        )
        session.add(log)
        logs.append(log)
        prev_hash = row_hash
    
    # Add some anomaly-triggering patterns
    # Bulk export pattern
    bulk_user = next((u for u in active_users if u.role == UserRole.PARTNER), active_users[0])
    bulk_dataset = published_datasets[0]
    bulk_time = datetime.utcnow() - timedelta(hours=2)
    
    for j in range(5):
        hash_input = prev_hash + str(bulk_user.id).encode() + \
                     str(bulk_dataset.id).encode() + \
                     AuditAction.SELECT.value.encode() + bulk_time.isoformat().encode()
        row_hash = hashlib.sha256(hash_input).digest()
        
        log = AuditLog(
            user_id=bulk_user.id,
            dataset_id=bulk_dataset.id,
            action=AuditAction.SELECT,
            rows_affected=5000 + j * 1000,
            query_text=f"SELECT * FROM data_{bulk_dataset.id}",
            client_ip="10.0.0.1",
            user_agent="python-requests/2.31",
            ts=bulk_time + timedelta(minutes=j * 5),
            prev_hash=prev_hash,
            row_hash=row_hash
        )
        session.add(log)
        logs.append(log)
        prev_hash = row_hash
    
    # Off-hours access
    off_hours_user = active_users[1] if len(active_users) > 1 else active_users[0]
    off_hours_time = datetime.utcnow().replace(hour=2, minute=30, second=0, microsecond=0)
    
    for j in range(3):
        hash_input = prev_hash + str(off_hours_user.id).encode() + \
                     str(published_datasets[1].id).encode() + \
                     AuditAction.SELECT.value.encode() + off_hours_time.isoformat().encode()
        row_hash = hashlib.sha256(hash_input).digest()
        
        log = AuditLog(
            user_id=off_hours_user.id,
            dataset_id=published_datasets[1].id,
            action=AuditAction.SELECT,
            rows_affected=100,
            query_text=f"SELECT * FROM data_{published_datasets[1].id} WHERE status='active'",
            client_ip=fake.ipv4(),
            user_agent=fake.user_agent(),
            ts=off_hours_time + timedelta(minutes=j * 10),
            prev_hash=prev_hash,
            row_hash=row_hash
        )
        session.add(log)
        logs.append(log)
        prev_hash = row_hash
    
    session.flush()
    return logs


def seed_anomaly_alerts(session, users: list, datasets: list, audit_logs: list) -> list:
    """Create synthetic anomaly alerts."""
    alerts = []
    
    # Alert for bulk export
    bulk_logs = [l for l in audit_logs if l.rows_affected > 1000]
    if bulk_logs:
        alert = AnomalyAlert(
            user_id=bulk_logs[0].user_id,
            dataset_id=bulk_logs[0].dataset_id,
            score=0.92,
            reason="Bulk data export detected: 5 queries reading >5000 rows each within 20 minutes",
            features={"query_count": 5, "avg_rows": 7000, "time_window_minutes": 20, "pattern": "bulk_export"},
            status=AlertStatus.OPEN
        )
        session.add(alert)
        alerts.append(alert)
    
    # Alert for off-hours access
    off_hours_logs = [l for l in audit_logs if l.ts.hour < 6 or l.ts.hour > 22]
    if off_hours_logs:
        alert = AnomalyAlert(
            user_id=off_hours_logs[0].user_id,
            dataset_id=off_hours_logs[0].dataset_id,
            score=0.78,
            reason="Off-hours access pattern: 3 queries between 2:30-3:00 AM",
            features={"off_hours_count": 3, "hour_range": "2-3", "pattern": "off_hours"},
            status=AlertStatus.OPEN
        )
        session.add(alert)
        alerts.append(alert)
    
    # Alert for grant-to-first-use anomaly
    alert = AnomalyAlert(
        user_id=users[0].id,
        dataset_id=datasets[0].id,
        score=0.65,
        reason="Grant used immediately after creation (2 minutes), unusual for this partner",
        features={"hours_to_first_use": 0.03, "pattern": "immediate_use"},
        status=AlertStatus.INVESTIGATING
    )
    session.add(alert)
    alerts.append(alert)
    
    session.flush()
    return alerts


def seed_all() -> dict:
    """Run complete seeding process."""
    print("Initializing database...")
    init_db()
    
    print("Starting seed process...")
    db = SessionLocal()
    
    try:
        # Check if already seeded
        existing_orgs = db.query(Organization).count()
        if existing_orgs > 0:
            print(f"Database already has {existing_orgs} organizations. Skipping seed.")
            return {"status": "skipped", "reason": "already_seeded"}
        
        print("Seeding organizations...")
        orgs = seed_organizations(db)
        print(f"  Created {len(orgs)} organizations")
        
        print("Seeding users...")
        users = seed_users(db, orgs)
        print(f"  Created {len(users)} users")
        
        print("Seeding datasets...")
        datasets = seed_datasets(db, orgs)
        print(f"  Created {len(datasets)} datasets")
        
        print("Seeding fields...")
        fields = seed_fields(db, datasets)
        print(f"  Created {len(fields)} fields")
        
        print("Seeding grants and requests...")
        grants, requests = seed_grants_and_requests(db, orgs, datasets, fields, users)
        print(f"  Created {len(grants)} grants, {len(requests)} requests")
        
        print("Seeding audit logs...")
        audit_logs = seed_audit_logs(db, users, datasets, grants)
        print(f"  Created {len(audit_logs)} audit log entries")
        
        print("Seeding anomaly alerts...")
        alerts = seed_anomaly_alerts(db, users, datasets, audit_logs)
        print(f"  Created {len(alerts)} anomaly alerts")
        
        db.commit()
        print("\n✓ Seeding completed successfully!")
        
        return {
            "status": "success",
            "organizations": len(orgs),
            "users": len(users),
            "datasets": len(datasets),
            "fields": len(fields),
            "grants": len(grants),
            "requests": len(requests),
            "audit_logs": len(audit_logs),
            "alerts": len(alerts)
        }
        
    except Exception as e:
        db.rollback()
        print(f"\n✗ Seeding failed: {e}")
        raise
    finally:
        db.close()


def clear_all() -> None:
    """Clear all data (use with caution!)."""
    db = SessionLocal()
    try:
        # Delete in reverse dependency order
        db.query(AnomalyAlert).delete()
        db.query(AuditLog).delete()
        db.query(AccessRequest).delete()
        db.query(ConsentGrant).delete()
        db.query(DatasetField).delete()
        db.query(Dataset).delete()
        db.query(User).delete()
        db.query(Organization).delete()
        db.commit()
        print("All data cleared.")
    except Exception as e:
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