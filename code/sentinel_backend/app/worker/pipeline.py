import logging
import uuid
from datetime import UTC, datetime

from app.core.broker import broker
from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager
from app.models.task import Task, TaskStatus

logger = logging.getLogger(__name__)


async def _is_task_cancelled(task_db_id: str) -> bool:
    """Return True when the task has already reached a terminal state."""
    from sqlalchemy import select

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Task.status).where(Task.id == uuid.UUID(task_db_id))
            )
            status = result.scalar_one_or_none()
            return status in (TaskStatus.FAILED, TaskStatus.COMPLETED)
    except Exception as exc:
        logger.warning("[Pipeline] failed to check task state task=%s: %s", task_db_id, exc)
        return False


async def dispatch_audit_pipeline(
    task_db_id: str,
    source_path: str,
    is_dynamic: bool = False,
) -> None:
    """
    Start the chained audit pipeline.

    Flow:
      1. SBOM/dependency analysis
      2. Static multi-agent audit and harness generation
      3. Optional AFL++/eBPF dynamic verification
    """
    logger.info("[Pipeline] dispatch task=%s dynamic=%s", task_db_id, is_dynamic)

    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": "pending",
            "percent": 5,
            "message": "审计任务已入队，正在准备 SBOM 分析…",
            "log_stream": "",
        },
    )

    from app.worker.sbom_task import run_sbom_analysis

    await (
        run_sbom_analysis
        .kicker()
        .with_labels(task_db_id=task_db_id, stage="sbom", is_dynamic=str(is_dynamic))
        .kiq(task_db_id, source_path, is_dynamic)
    )

    logger.info("[Pipeline] task=%s SBOM stage queued", task_db_id)


async def trigger_llm_stage(task_db_id: str, source_path: str, is_dynamic: bool) -> None:
    """Queue static audit after SBOM analysis succeeds."""
    if await _is_task_cancelled(task_db_id):
        logger.info("[Pipeline] task=%s terminal; skipping LLM stage", task_db_id)
        return

    target_vulns_json = ""
    try:
        from sqlalchemy import select

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Task.target_vulns).where(Task.id == uuid.UUID(task_db_id))
            )
            target_vulns_json = result.scalar_one_or_none() or ""
    except Exception as exc:
        logger.warning("[Pipeline] failed to load target_vulns task=%s: %s", task_db_id, exc)

    from app.worker.llm_task import run_llm_audit

    await (
        run_llm_audit
        .kicker()
        .with_labels(task_db_id=task_db_id, stage="llm")
        .kiq(task_db_id, source_path, is_dynamic, target_vulns_json)
    )
    logger.info("[Pipeline] task=%s LLM audit stage queued", task_db_id)


async def trigger_fuzzing_stage(
    task_db_id: str,
    source_path: str,
    harness_bundle_root: str | None = None,
) -> None:
    """Queue dynamic verification after static audit and harness generation."""
    if await _is_task_cancelled(task_db_id):
        logger.info("[Pipeline] task=%s terminal; skipping fuzzing stage", task_db_id)
        return

    from app.worker.fuzzing_task import run_dynamic_fuzzing

    await (
        run_dynamic_fuzzing
        .kicker()
        .with_labels(task_db_id=task_db_id, stage="fuzzing")
        .kiq(task_db_id, source_path, harness_bundle_root)
    )
    logger.info(
        "[Pipeline] task=%s fuzzing stage queued harness=%s",
        task_db_id,
        harness_bundle_root,
    )


@broker.task(task_name="finalize_no_fuzzing")
async def finalize_task_no_fuzzing(task_db_id: str) -> None:
    """Mark a static-only audit task as completed."""
    from sqlalchemy import select

    logger.info("[Finalize] static-only task finalizing task=%s", task_db_id)
    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": "report",
            "percent": 98,
            "message": "Agent e：正在汇总静态与 SBOM 结果并准备审计报告。",
            "log_stream": "[Agent e] Aggregating static findings and SBOM evidence.\n",
        },
    )
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Task).where(Task.id == uuid.UUID(task_db_id))
        )
        task = result.scalar_one_or_none()
        if task and task.status not in (TaskStatus.FAILED, TaskStatus.COMPLETED):
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now(UTC)
            await session.commit()
            logger.info("[Finalize] task=%s marked COMPLETED", task_db_id)

    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": "done",
            "percent": 100,
            "message": "静态审计已完成，报告可以查看。",
            "log_stream": "",
        },
    )
