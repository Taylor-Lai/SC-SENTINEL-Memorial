# SENTINEL Agent

The Agent is the stateless analysis plane for C/C++ source. It exposes dependency analysis and the seven-stage static audit chain while keeping generated Harness/report data outside version control.

## Layout

```text
agents/       analysis stages
core/         scanning, LLM, schemas and shared utilities
cve/          dependency parsing and vulnerability data clients
prompts/      maintained LLM prompts
samples/      immutable fixtures and oracle projects
tools/        operational parsers and connectivity checks
scripts/      reproducible pipeline helpers
main.py       CLI pipeline
service.py    internal FastAPI service
```

## CLI

```powershell
python main.py --project samples/vulnerable_project
```

Real dynamic evidence is opt-in and must be supplied explicitly:

```powershell
python main.py `
  --project samples/vulnerable_project `
  --validation path/to/runtime-evidence
```

The validation directory may contain `asan_validation_results.json`, `afl_result.json` and `ebpf_log.json`. Repository-bundled fake dynamic evidence is never loaded automatically.

## Service

```powershell
python -m uvicorn service:app --host 127.0.0.1 --port 18001
```

Configure `AGENT_ALLOWED_SOURCE_ROOTS` as a comma-separated path list. When set, requests outside those roots receive HTTP 403. The default Compose deployment sets it to `/app/uploads` and does not publish the Agent port to the host.

Endpoints:

- `GET /health`
- `POST /api/agent-a/analyze`
- `POST /api/agent-b/audit`

LLM configuration is read from `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_TIMEOUT` and related environment variables. If no provider is configured, the analysis layer may use its deterministic rule fallback; it does not fabricate backend task results.
