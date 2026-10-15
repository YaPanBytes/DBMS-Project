# ConsentLedger Makefile
# Member A: Database Lead

.PHONY: help install dev-install test lint format migrate seed verify backup restore clean db-up db-down db-logs

# Default target
help:
	@echo "ConsentLedger - Database Commands"
	@echo ""
	@echo "Database:"
	@echo "  db-up          Start PostgreSQL container"
	@echo "  db-down        Stop PostgreSQL container"
	@echo "  db-logs        View PostgreSQL logs"
	@echo "  db-shell       Connect to PostgreSQL shell"
	@echo ""
	@echo "Migrations:"
	@echo "  migrate        Run all pending migrations"
	@echo "  migrate-status Show migration status"
	@echo ""
	@echo "Data:"
	@echo "  seed           Seed database with demo data"
	@echo "  seed-clear     Clear all data and re-seed"
	@echo ""
	@echo "Verification:"
	@echo "  verify         Verify audit chain integrity"
	@echo "  verify-detailed Detailed audit chain verification"
	@echo "  tamper-test    Test tamper detection"
	@echo ""
	@echo "Backup/Restore:"
	@echo "  backup         Create database backup"
	@echo "  backup-list    List available backups"
	@echo "  restore        Restore from backup"
	@echo "  backup-verify  Verify backup integrity"
	@echo ""
	@echo "Testing:"
	@echo "  test           Run database tests"
	@echo "  test-cov       Run tests with coverage"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint           Run ruff linter"
	@echo "  format         Format code with black"
	@echo "  typecheck      Run mypy type checker"
	@echo ""
	@echo "Development:"
	@echo "  install        Install production dependencies"
	@echo "  dev-install    Install development dependencies"
	@echo "  clean          Remove generated files"

# Database
db-up:
	docker-compose up -d postgres
	@echo "Waiting for PostgreSQL to be ready..."
	@sleep 3
	@docker-compose exec postgres pg_isready -U consentledger -d consentledger

db-down:
	docker-compose down

db-logs:
	docker-compose logs -f postgres

db-shell:
	docker-compose exec postgres psql -U consentledger -d consentledger

# Migrations
migrate:
	python -m database.migrate migrate

migrate-status:
	python -m database.migrate status

# Data
seed:
	python -m database.seeds.seed_data

seed-clear:
	python -m database.seeds.seed_data --clear

# Verification
verify:
	python -m database.scripts.verify_audit

verify-detailed:
	python -m database.scripts.verify_audit --detailed

tamper-test:
	python -m database.scripts.verify_audit --tamper-test

# Backup/Restore
backup:
	python -m database.scripts.backup_restore backup

backup-list:
	python -m database.scripts.backup_restore backup --list

restore:
	@read -p "Backup file: " file; \
	python -m database.scripts.backup_restore restore $$file

backup-verify:
	@read -p "Backup file: " file; \
	python -m database.scripts.backup_restore verify $$file

# Testing
test:
	python -m pytest database/test_db.py -v

test-cov:
	python -m pytest database/test_db.py --cov=database --cov-report=term-missing

# Code Quality
lint:
	ruff check database/

format:
	black database/
	ruff check --fix database/

typecheck:
	mypy database/

# Dependencies
install:
	pip install -r requirements.txt

dev-install:
	pip install -e ".[dev]"

# Cleanup
clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Full setup
setup: db-up migrate seed
	@echo ""
	@echo "✓ ConsentLedger database ready!"
	@echo "  PostgreSQL: localhost:5432"
	@echo "  Database: consentledger"
	@echo "  User: consentledger / consentledger"