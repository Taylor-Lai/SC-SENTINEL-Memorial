# Integration contract

The backend calls the internal Agent service through two endpoints:

- `POST /api/agent-a/analyze` for dependency/CVE analysis.
- `POST /api/agent-b/audit` for the static audit chain and Harness generation.

The shared source tree must resolve under the Agent's `AGENT_ALLOWED_SOURCE_ROOTS`. In the default Compose topology both Worker and Agent mount the `uploads_data` volume at `/app/uploads`.

Backend clients use:

- `POST /api/v1/tasks` to create a source record;
- `POST /api/v1/audit/submit` to dispatch the audit;
- `GET /api/v1/audit/status/{task_id}` as the polling fallback;
- `WS /api/v1/ws/tasks/{task_id}/progress` for live events;
- `GET /api/v1/tasks/{task_id}/report` for structured results;
- `GET /api/v1/tasks/{task_id}/export-pdf` for PDF output.

Production code contains no fake Agent response path. Tests should mock the HTTP boundary or run the real Agent against fixtures.
