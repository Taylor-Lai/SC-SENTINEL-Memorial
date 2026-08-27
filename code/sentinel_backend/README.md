# SENTINEL Backend

FastAPI control plane and TaskIQ worker for the SENTINEL audit pipeline.

## Layout

```text
app/api/          HTTP and WebSocket transport
app/core/         configuration, database, broker and reporting infrastructure
app/models/       persistent domain models
app/schemas/      API contracts
app/services/     source ingestion and sandbox adapters
app/worker/       durable pipeline stages and lifecycle middleware
alembic/          database migrations
tests/            isolated unit and contract tests
```

The canonical deployment definition is the repository-root `docker-compose.yaml`; duplicate backend Compose files are intentionally not maintained.

## Local development

```powershell
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 18000 --reload
```

Start a worker in another terminal:

```powershell
python -m taskiq worker app.main:broker --workers 1
```

Run tests:

```powershell
python -m pytest
```

Production deployments must set `AUTO_CREATE_TABLES=false`, run Alembic before application startup, restrict `CORS_ORIGINS`, and inject database credentials through a secret store.
