# ConsentLedger Makefile (run `make help`)

.PHONY: help install db-up db-down db-shell migrate migrate-status seed seed-clear api web dev \
	test lint format verify verify-detailed tamper-test backup backup-list restore backup-verify \
	detector logs docs app-up app-down clean setup

help:
	@echo "Setup:      install, db-up, migrate, seed, setup (all of these)"
	@echo "Run:        api (FastAPI :8000), web (Vite :5173), app-up / app-down (Docker, :8080)"
	@echo "Database:   migrate-status, db-shell, seed-clear, db-down"
	@echo "Audit:      verify, verify-detailed, tamper-test"
	@echo "Backups:    backup, backup-list, restore FILE=..., backup-verify FILE=..."
	@echo "AI:         logs (generate access logs), detector (run anomaly detection)"
	@echo "Quality:    test, lint, format, docs"

install:
	pip install -r requirements.txt
	-python -m spacy download en_core_web_sm
	cd frontend && npm install

db-up:
	docker compose up -d postgres
	@for i in $$(seq 1 30); do \
		docker compose exec -T postgres pg_isready -U consentledger -d consentledger >/dev/null 2>&1 && exit 0; \
		sleep 1; \
	done; echo "PostgreSQL did not become ready in time"; exit 1

db-down:
	docker compose down

db-shell:
	docker compose exec postgres psql -U consentledger -d consentledger

migrate:
	python -m database.migrate

migrate-status:
	python -m database.migrate status

seed:
	python -m database.seeds.seed_data

seed-clear:
	python -m database.seeds.seed_data --clear

api:
	uvicorn backend.app.main:app --reload --port 8000

web:
	cd frontend && npm run dev

app-up:
	docker compose --profile app up -d --build

app-down:
	docker compose --profile app down

verify:
	python -m database.scripts.verify_audit

verify-detailed:
	python -m database.scripts.verify_audit --detailed

tamper-test:
	python -m database.scripts.verify_audit --tamper-test

backup:
	python -m database.scripts.backup_restore backup

backup-list:
	python -m database.scripts.backup_restore backup --list

restore:
	@test -n "$(FILE)" || (echo "Usage: make restore FILE=<backup file>"; exit 1)
	python -m database.scripts.backup_restore restore $(FILE)

backup-verify:
	@test -n "$(FILE)" || (echo "Usage: make backup-verify FILE=<backup file>"; exit 1)
	python -m database.scripts.backup_restore verify $(FILE)

logs:
	python -m ai.log_generator --days 30

detector:
	python -m ai.anomaly

test:
	python -m pytest
	cd frontend && npm run lint

lint:
	ruff check database backend ai scripts conftest.py
	black --check database backend ai scripts conftest.py
	cd frontend && npm run lint

format:
	black database backend ai scripts conftest.py
	ruff check --fix database backend ai scripts conftest.py

docs:
	python scripts/export_openapi.py
	python scripts/data_dictionary.py

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov frontend/dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true

setup: db-up migrate seed
	@echo ""
	@echo "ConsentLedger is ready. Run 'make api' and 'make web', then open http://localhost:5173"
python -m database.migrate