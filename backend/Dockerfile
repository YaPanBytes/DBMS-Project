# ConsentLedger API image. Build from the project root:
#   docker build -f backend/Dockerfile -t consentledger-api .
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
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser
EXPOSE 8000
# Apply migrations, then serve
CMD ["sh", "-c", "python -m database.migrate && uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"]
