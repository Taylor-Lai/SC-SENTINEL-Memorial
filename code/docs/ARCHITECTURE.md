# Architecture

## Components

| Component | Responsibility | Trust level |
|---|---|---|
| Frontend | Task submission, progress and reports | Untrusted client |
| API | Input validation and report queries | Trusted control plane |
| Worker | Durable pipeline orchestration | Trusted control plane |
| Agent | Static analysis and Harness generation | Trusted service processing untrusted text |
| Sandbox | Compiles and executes submitted source | Untrusted data plane |
| PostgreSQL | Durable business state | Trusted state |
| Redis | Queue, task results and progress streams | Trusted ephemeral state |

## Data flow

1. API streams an uploaded ZIP into a task-specific directory or records an allowlisted repository URL.
2. Worker extracts/clones the source and calls Agent A.
3. Worker calls the remaining static audit chain and materializes embedded Harness files into backend-owned storage.
4. Static-only tasks finish immediately. Dynamic tasks invoke the isolated sandbox runner.
5. Dynamic evidence updates finding verification state and is exposed through the report API. A bounded run with no crash becomes `not_reproduced`, never an automatic false positive.

The dependency context produced by Agent A is persisted once and reused by the static chain. This avoids a second OSV/NVD lookup and keeps the report consistent with the SBOM stage.

## Evidence verdicts

| Verdict | Meaning |
|---|---|
| `confirmed` | Strong runtime evidence reproduced the finding. |
| `unverified` | Static candidate without sufficient runtime evidence. |
| `not_reproduced` | Dynamic verification ran, but the bounded budget did not trigger the finding. |
| `false_positive` | Finding was explicitly dismissed by a deterministic or human review step. |

Stage persistence is replace-based: retried SBOM/static stages replace prior stage output instead of appending duplicates.

## Runtime directories

All mutable data belongs under `uploads/`, `artifacts/` or `tmp/`. These paths are deployment state and are excluded from Git. Source fixtures and oracle data are immutable and live under `sentinel_agent/samples/`.

## Deployment boundary

The Agent has no host port in the default Compose topology. API and Worker reach it through the internal network. The Worker is the only component allowed to invoke the sandbox runtime. Production deployments should replace direct Docker Socket access with a dedicated runner API.
