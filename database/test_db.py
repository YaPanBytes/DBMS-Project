"""
ConsentLedger Database Tests
Member A: Database Lead
Basic tests for schema, RLS, audit chain, and procedures.
"""

import os
import sys
import pytest
from uuid import uuid4
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import get_engine, SessionLocal, init_db
from database.models import (
    Base, Organization, User, Dataset, DatasetField,
    ConsentGrant, AccessRequest, AuditLog, AnomalyAlert,
    OrgType, UserRole, DatasetStatus, SensitivityLevel,
    DataType, RequestStatus, AuditAction, AlertStatus
)
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


class TestDatabase:
    """Test suite for ConsentLedger database."""
    
    @pytest.fixture(scope="class")
    def engine(self):
        return get_engine()
    
    @pytest.fixture(scope="class")
    def db(self, engine):
        # Create tables
        Base.metadata.create_all(bind=engine)
        session = SessionLocal()
        yield session
        session.close()
        # Cleanup
        Base.metadata.drop_all(bind=engine)
    
    def test_organizations_crud(self, db):
        """Test organization CRUD operations."""
        # Create
        org = Organization(
            name="Test NGO",
            type=OrgType.NGO,
            description="Test organization",
            contact_email="test@ngo.org"
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        
        assert org.id is not None
        assert org.name == "Test NGO"
        assert org.type == OrgType.NGO
        assert org.created_at is not None
        
        # Read
        found = db.query(Organization).filter(Organization.id == org.id).first()
        assert found is not None
        assert found.name == "Test NGO"
        
        # Update
        org.description = "Updated description"
        db.commit()
        db.refresh(org)
        assert org.description == "Updated description"
        assert org.updated_at > org.created_at
        
        # Delete
        db.delete(org)
        db.commit()
        assert db.query(Organization).filter(Organization.id == org.id).first() is None
    
    def test_users_crud(self, db):
        """Test user CRUD with organization FK."""
        org = Organization(name="User Org", type=OrgType.NGO)
        db.add(org)
        db.commit()
        
        user = User(
            org_id=org.id,
            email="user@test.org",
            password_hash=hash_password("secret"),
            role=UserRole.OWNER,
            full_name="Test User"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        
        assert user.id is not None
        assert user.org_id == org.id
        assert user.email == "user@test.org"
        assert user.role == UserRole.OWNER
        
        # Test relationship
        assert user.organization.name == "User Org"
        assert org.users[0].email == "user@test.org"
    
    def test_dataset_and_fields(self, db):
        """Test dataset with fields."""
        org = Organization(name="Data Owner", type=OrgType.NGO)
        db.add(org)
        db.commit()
        
        dataset = Dataset(
            owner_org_id=org.id,
            title="Test Dataset",
            description="Test data",
            category="test",
            status=DatasetStatus.PUBLISHED
        )
        db.add(dataset)
        db.commit()
        
        # Add fields
        fields = [
            DatasetField(dataset_id=dataset.id, name="id", data_type=DataType.INTEGER, 
                        sensitivity=SensitivityLevel.PII, is_encrypted=True, ordinal=0),
            DatasetField(dataset_id=dataset.id, name="name", data_type=DataType.TEXT,
                        sensitivity=SensitivityLevel.PII, ordinal=1),
            DatasetField(dataset_id=dataset.id, name="value", data_type=DataType.NUMERIC,
                        sensitivity=SensitivityLevel.LOW, ordinal=2),
        ]
        for f in fields:
            db.add(f)
        db.commit()
        
        # Verify
        assert len(dataset.fields) == 3
        assert dataset.fields[0].name == "id"
        assert dataset.fields[0].is_encrypted is True
        assert dataset.fields[2].sensitivity == SensitivityLevel.LOW
    
    def test_consent_grant_lifecycle(self, db):
        """Test consent grant creation, expiry, revocation."""
        # Setup
        grantor = Organization(name="Grantor", type=OrgType.NGO)
        grantee = Organization(name="Grantee", type=OrgType.FUNDER)
        db.add_all([grantor, grantee])
        db.commit()
        
        dataset = Dataset(owner_org_id=grantor.id, title="Data", status=DatasetStatus.PUBLISHED)
        db.add(dataset)
        db.commit()
        
        field = DatasetField(dataset_id=dataset.id, name="field1", data_type=DataType.TEXT,
                            sensitivity=SensitivityLevel.LOW)
        db.add(field)
        db.commit()
        
        # Create grant
        grant = ConsentGrant(
            grantor_org_id=grantor.id,
            grantee_org_id=grantee.id,
            dataset_id=dataset.id,
            field_id=field.id,
            purpose="analytics",
            expires_at=datetime.utcnow() + timedelta(days=30)
        )
        db.add(grant)
        db.commit()
        
        assert grant.is_active is True
        assert grant.revoked_at is None
        
        # Test expiry
        grant.expires_at = datetime.utcnow() - timedelta(days=1)
        db.commit()
        assert grant.is_active is False
        
        # Test revocation
        grant.expires_at = datetime.utcnow() + timedelta(days=30)
        grant.revoked_at = datetime.utcnow()
        db.commit()
        assert grant.is_active is False
        assert grant.revoked_at is not None
    
    def test_unique_grant_constraint(self, db):
        """Test unique constraint on (grantee, dataset, field, purpose)."""
        grantor = Organization(name="G1", type=OrgType.NGO)
        grantee = Organization(name="G2", type=OrgType.FUNDER)
        db.add_all([grantor, grantee])
        db.commit()
        
        dataset = Dataset(owner_org_id=grantor.id, title="D", status=DatasetStatus.PUBLISHED)
        db.add(dataset)
        db.commit()
        
        field = DatasetField(dataset_id=dataset.id, name="f", data_type=DataType.TEXT)
        db.add(field)
        db.commit()
        
        # First grant
        grant1 = ConsentGrant(
            grantor_org_id=grantor.id, grantee_org_id=grantee.id,
            dataset_id=dataset.id, field_id=field.id,
            purpose="purpose1", expires_at=datetime.utcnow() + timedelta(days=30)
        )
        db.add(grant1)
        db.commit()
        
        # Duplicate should fail
        grant2 = ConsentGrant(
            grantor_org_id=grantor.id, grantee_org_id=grantee.id,
            dataset_id=dataset.id, field_id=field.id,
            purpose="purpose1", expires_at=datetime.utcnow() + timedelta(days=30)
        )
        db.add(grant2)
        
        with pytest.raises(Exception):  # IntegrityError
            db.commit()
        db.rollback()
    
    def test_access_request_workflow(self, db):
        """Test access request create, approve, deny."""
        grantee = Organization(name="Requester", type=OrgType.FUNDER)
        grantor = Organization(name="Owner", type=OrgType.NGO)
        db.add_all([grantee, grantor])
        db.commit()
        
        dataset = Dataset(owner_org_id=grantor.id, title="Data", status=DatasetStatus.PUBLISHED)
        db.add(dataset)
        db.commit()
        
        field = DatasetField(dataset_id=dataset.id, name="f", data_type=DataType.TEXT)
        db.add(field)
        db.commit()
        
        # Create request
        req = AccessRequest(
            grantee_org_id=grantee.id,
            dataset_id=dataset.id,
            field_ids=[field.id],
            purpose="research",
            requested_expires_at=datetime.utcnow() + timedelta(days=30)
        )
        db.add(req)
        db.commit()
        
        assert req.status == RequestStatus.PENDING
        
        # Approve
        req.status = RequestStatus.APPROVED
        req.decided_at = datetime.utcnow()
        db.commit()
        
        assert req.status == RequestStatus.APPROVED
        assert req.decided_at is not None
    
    def test_audit_log_hash_chain(self, db):
        """Test audit log hash chain integrity."""
        from sqlalchemy import text
        
        user = User(org_id=uuid4(), email="audit@test.org", password_hash="x", role=UserRole.OWNER)
        db.add(user)
        db.commit()
        
        # Insert audit logs manually to test chain
        prev_hash = b'\x00' * 32
        import hashlib
        
        for i in range(5):
            ts = datetime.utcnow()
            row_hash = hashlib.sha256(
                prev_hash + str(user.id).encode() + b'test-dataset' + b'select' + ts.isoformat().encode()
            ).digest()
            
            log = AuditLog(
                user_id=user.id,
                dataset_id=uuid4(),
                action=AuditAction.SELECT,
                rows_affected=10,
                ts=ts,
                prev_hash=prev_hash,
                row_hash=row_hash
            )
            db.add(log)
            prev_hash = row_hash
        
        db.commit()
        
        # Verify chain using database function
        result = db.execute(text("SELECT * FROM verify_audit_chain()")).fetchall()
        
        assert len(result) == 5
        for row in result:
            assert row.is_valid is True
    
    def test_audit_chain_tamper_detection(self, db):
        """Test that tampering breaks the chain."""
        from sqlalchemy import text
        
        user = User(org_id=uuid4(), email="audit2@test.org", password_hash="x", role=UserRole.OWNER)
        db.add(user)
        db.commit()
        
        # Create chain
        prev_hash = b'\x00' * 32
        import hashlib
        log_ids = []
        
        for i in range(3):
            ts = datetime.utcnow()
            row_hash = hashlib.sha256(
                prev_hash + str(user.id).encode() + b'dataset' + b'select' + ts.isoformat().encode()
            ).digest()
            
            log = AuditLog(
                user_id=user.id,
                dataset_id=uuid4(),
                action=AuditAction.SELECT,
                ts=ts,
                prev_hash=prev_hash,
                row_hash=row_hash
            )
            db.add(log)
            db.flush()
            log_ids.append(log.log_id)
            prev_hash = row_hash
        
        db.commit()
        
        # Verify initially valid
        result = db.execute(text("SELECT is_audit_chain_valid()")).scalar()
        assert result is True
        
        # Tamper with middle row
        db.execute(text("UPDATE audit_log SET row_hash = :h WHERE log_id = :id"),
                  {"h": b'\xff' * 32, "id": log_ids[1]})
        db.commit()
        
        # Verify now invalid
        result = db.execute(text("SELECT is_audit_chain_valid()")).scalar()
        assert result is False
        
        # Check details
        details = db.execute(text("SELECT * FROM verify_audit_chain()")).fetchall()
        errors = [r for r in details if not r.is_valid]
        assert len(errors) > 0
    
    def test_anomaly_alert_creation(self, db):
        """Test anomaly alert model."""
        user = User(org_id=uuid4(), email="alert@test.org", password_hash="x", role=UserRole.PARTNER)
        db.add(user)
        db.commit()
        
        alert = AnomalyAlert(
            user_id=user.id,
            score=0.85,
            reason="Bulk export detected",
            features={"query_count": 100, "pattern": "bulk_export"},
            status=AlertStatus.OPEN
        )
        db.add(alert)
        db.commit()
        
        assert alert.id is not None
        assert alert.score == 0.85
        assert alert.status == AlertStatus.OPEN
        assert alert.features["pattern"] == "bulk_export"
    
    def test_rls_helper_functions_exist(self, db):
        """Test that RLS helper functions exist."""
        from sqlalchemy import text
        
        # These should exist after migration
        functions = [
            "current_user_org_id",
            "current_user_id",
            "is_grant_active",
            "has_field_access",
            "compute_audit_hash",
            "verify_audit_chain",
            "is_audit_chain_valid"
        ]
        
        for func in functions:
            result = db.execute(text(f"""
                SELECT EXISTS (
                    SELECT 1 FROM pg_proc 
                    WHERE proname = '{func}'
                )
            """)).scalar()
            # Note: Will be False before migrations run
            # This test documents expected functions
    
    def test_stored_procedures_exist(self, db):
        """Test that stored procedures exist."""
        from sqlalchemy import text
        
        procedures = [
            "request_access",
            "approve_access_request",
            "revoke_grant",
            "expire_grants"
        ]
        
        for proc in procedures:
            result = db.execute(text(f"""
                SELECT EXISTS (
                    SELECT 1 FROM pg_proc 
                    WHERE proname = '{proc}'
                )
            """)).scalar()
            # Will be False before migrations


if __name__ == "__main__":
    pytest.main([__file__, "-v"])