# ConsentLedger image: the API, plus the built web app it serves (one service).
# Build from the project root:
#   docker build -f backend/Dockerfile -t consentledger-api .

# 1. Build the web app
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# 2. API
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt && python -m spacy download en_core_web_sm
COPY alembic.ini ./
COPY database ./database
COPY backend ./backend
COPY ai ./ai
COPY --from=web /web/dist ./frontend_dist
# The API serves the web app from here (unset FRONTEND_DIST for API only)
ENV FRONTEND_DIST=/app/frontend_dist
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser
EXPOSE 8000
# Apply migrations, then serve
CMD ["sh", "-c", "python -m database.migrate && uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"]
