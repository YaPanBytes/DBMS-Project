# ConsentLedger

A data-sharing hub where NGOs, government agencies and funders share sensitive
datasets under **per-field, purpose-bound, expiring consent that PostgreSQL
itself enforces** and that can be revoked instantly. Every read and write lands
in a hash-chained, append-only audit log; an AI layer flags unusual access and
detects personal data before anything is shared. Supports SDG 17 (partnerships
for the goals).

Course: BCSE302P Database Systems Lab (DBTHON, SDG 17).

| Layer | What's in it |
|---|---|
| `database/` | Schema (Alembic + SQL), RLS, masked views, audit chain, procedures, ORM models, seed data, backup/restore, tests |
| `backend/` | FastAPI app: Google OAuth 2.0 + JWT, RBAC, routers for auth, organizations, datasets, consent, requests, audit, alerts |
| `ai/` | Synthetic access-log generator, Isolation Forest anomaly detector with a rule baseline, PII scanner (rules + spaCy NER) |
| `frontend/` | React + TypeScript dashboard for owners, partners, auditors and admins |
| `docs/` | [Database design](docs/DATABASE_DESIGN.md), [ER diagram & 3NF](docs/ER_DIAGRAM.md), [data dictionary](docs/DATA_DICTIONARY.md), [AI services](docs/AI_SERVICES.md), [OpenAPI](docs/api/) |

## How enforcement works

```
React app ──► FastAPI (auth, validation) ──► PostgreSQL: the enforcement point
                 │  per request:                ├─ RLS on datasets, fields, grants, requests, audit, alerts
                 │  set_config(user, org)       ├─ access_dataset(): check consent → masked view → audit entry
                 │  SET LOCAL ROLE app          ├─ request_access / approve / deny / revoke procedures
                 ▼                              └─ append-only, hash-chained audit_log + verify_chain()
           AI services ◄── window-function features ── audit_log
           (Isolation Forest, PII scanner) ──► anomaly_alerts
```

A partner can only read a dataset through `access_dataset(dataset, purpose)`. It
refuses without an active grant for that purpose, returns non-consented fields as
`[REDACTED]`/`[MASKED]`, and records the read. Revoking a grant blocks the very
next read.

## Quick start

Requirements: Python 3.11+, Node 20+, Docker (or a local PostgreSQL 16), and
PostgreSQL client tools for backups.

```bash
cp .env.example .env                       # then set JWT_SECRET and ENCRYPTION_KEY
docker compose up -d postgres

pip install -r requirements.txt
python -m spacy download en_core_web_sm    # optional: NER for the PII scanner

python -m database.migrate                 # alembic upgrade head
python -m database.seeds.seed_data         # demo data, access logs, alerts

uvicorn backend.app.main:app --reload      # API on :8000, docs at /docs
cd frontend && npm install && npm run dev  # web app on http://localhost:5173
```

Or run everything in containers: `docker compose --profile app up -d --build`
(web app on http://localhost:8080). With `make`, see `make help`.

On Windows, use `py -m pip install -r requirements.txt` and `py -m ...` in place
of `pip` and `python -m ...` if `python` is not on your PATH.

### Demo accounts (password `demo123`)

| Account | Role |
|---|---|
| `owner@hope.org` | Data owner, Hope Foundation |
| `funder@globalfund.org` | Partner, Global Fund |
| `partner@health.gov` | Partner, Health Ministry |
| `auditor@transparency.org` | Auditor |
| `admin@consentledger.org` | Platform admin |

A two-minute demo: sign in as the funder and open *Poverty Relief Beneficiaries
2024 → Data*: names, IDs and phones are redacted. In another browser sign in as
the owner, open *Sharing* and revoke Global Fund's access; refresh the funder's
page and the read is refused. As the auditor, open *Audit trail → Verify chain*.

### Google sign-in

Create an OAuth client (type *Web application*) in Google Cloud Console →
APIs & Services → Credentials, add the redirect URI
`http://localhost:5173/api/auth/google/callback`, and set `GOOGLE_CLIENT_ID` and
`GOOGLE_CLIENT_SECRET` in `.env`. Accounts are created by an admin (*Users &
organizations*); a person signs in with the Google account matching their
registered email. Without these settings the Google button is hidden and
password login is used.

## Backend (FastAPI)

The backend lives in `backend/app/` and is the only way users reach the
database. It authenticates the user, sets the per-request session variables
(user and organization) that the RLS policies read, validates input with
Pydantic, and calls into PostgreSQL, which makes the final consent decision.

- **Auth:** Google OAuth 2.0 and password login, both issuing a JWT; `/me`
  returns the signed-in user; logout revokes the token server-side.
- **RBAC:** roles (owner, partner, auditor, admin) come from the single users
  table and roles lookup table, enforced through the `require_roles` dependency.
- **Routers:** auth, organizations, datasets, consent, requests, audit, alerts,
  with search, filter and pagination on list endpoints.
- **CSV handling:** `backend/app/csv_utils.py` normalises column names and
  parses uploaded CSV files into a header list, a type list and rows.
- **Errors:** every error is returned as `{"error": {"code", "message", "details"?}}`.
- **API reference:** run the server and open `http://localhost:8000/docs`, or
  see the exported OpenAPI files in `docs/api/`.

### Backend work on this branch (`backend-surjadeep`)

Contribution by Surjadeep (backend lead), made on top of the `yas` branch:

| Change | File(s) | Why |
|---|---|---|
| Added docstrings to backend modules | `backend/` | Document what each router and helper does |
| Fixed an invalid `//` comment (a Python syntax error caught by ruff) | `backend/app/csv_utils.py` | CI's `ruff check` failed on it |
| Reformatted with ruff so the format check passes | `backend/app/csv_utils.py` | CI's `ruff format --check` failed |
| Wrote this README section | `README.md` | Explain the backend and how to run and test it |

## Security model

- **Database:** RLS + a non-owner application role; masked views; purpose-bound
  reads; pgcrypto encryption of PII columns; append-only, hash-chained audit with
  `RESTRICT` foreign keys; procedures check the acting user and role.
- **API:** JWT in an **httpOnly** cookie (`Secure` in production) with a
  double-submit CSRF token; bearer tokens for API clients; logout revokes the
  token server-side; roles come from the users/roles tables on every request
  (`require_roles` dependency); bcrypt for passwords; Pydantic validation; every
  error is `{"error": {"code", "message", "details"?}}`.
- **Secrets** only in `.env` (database password, JWT secret, encryption key,
  OAuth client secret). Commit `.env.example` only; `.env` stays in `.gitignore`.
  Production refuses to start with development secrets.

## Tests and CI

```bash
python -m pytest                     # database, API and AI tests (creates and drops a test DB)
cd frontend && npm run lint && npm run build
```

The suite creates a throwaway `<db>_test` database, migrates and seeds it, and
covers schema constraints, the audit chain and tamper detection, procedures, RLS
and the masked read path, encryption, window features, a `pg_dump`/`pg_restore`
round trip, authentication (cookies, CSRF, bearer, logout, Google), RBAC, consent
enforcement over HTTP, and the AI modules.

GitHub Actions (`.github/workflows/`) runs on every push: install, lint
(`ruff check` and `ruff format --check` on `database backend ai conftest.py
scripts`, plus ESLint and tsc), migrations up/down/up, tests with coverage,
OpenAPI drift check, frontend build and Docker image builds. `pages.yml`
publishes the API reference in `docs/api/` to GitHub Pages (regenerate with
`python scripts/export_openapi.py`).

Run the same lint checks locally before pushing:

```bash
python -m ruff check database backend ai conftest.py scripts
python -m ruff format --check database backend ai conftest.py scripts
```

Use the same ruff version as CI, or the format check can disagree with CI.

## Git workflow

- Default branch is `yas`; work on a feature branch and open a pull request.
- Backend branch: `backend-surjadeep`.
- Never commit `.env` or any secret.

```bash
git checkout -b <your-branch>
git add <files>
git commit -m "Short, meaningful message"
git push -u origin <your-branch>
```

## Useful commands

| Task | Command |
|---|---|
| Migration status / downgrade | `python -m database.migrate status` / `downgrade -1` |
| Verify the audit chain | `python -m database.scripts.verify_audit [--detailed \| --tamper-test]` |
| Backup / restore | `python -m database.scripts.backup_restore backup` / `restore <file>` |
| Generate access logs | `python -m ai.log_generator --days 30` |
| Run the anomaly detector | `python -m ai.anomaly` |
| Scan a CSV for PII | `python -m ai.pii file.csv` |
| Expire old grants | `psql -c "CALL expire_grants()"` (schedule daily) |
| Regenerate docs | `python scripts/export_openapi.py`, `python scripts/data_dictionary.py` |