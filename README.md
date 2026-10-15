# ConsentLedger

PostgreSQL-backed data-sharing hub with per-field, purpose-bound consent enforcement, hash-chained audit logs, and AI-driven anomaly detection.

## Branch Structure
- `main` - Production-ready code
- `pc` - Member A: Database layer (schema, RLS, triggers, audit chain, ORM, backup/restore)

## Member A Deliverables (Database Lead)
- Database design (ER diagram, schema, 3NF normalization)
- Database implementation (DDL, CRUD, joins, views, aggregates, transactions, procedures, triggers)
- Row-Level Security policies for consent enforcement
- Hash-chained append-only audit log with verification
- ORM models (SQLAlchemy)
- Backup and restore scripts

## Quick Start

```bash
# Start PostgreSQL
docker-compose up -d

# Run migrations
python -m database.migrate

# Seed demo data
python -m database.seed

# Verify audit chain
python -m database.verify_audit
```