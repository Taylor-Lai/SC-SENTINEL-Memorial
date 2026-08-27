import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from taskiq import TaskiqMessage, TaskiqMiddleware, TaskiqResult

from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager
from app.models.task import TaskStatus

logger = logging.getLogger(__name__)

_STAGE_PERCENT: dict[str, int] = {
    "sbom": 20,
    "llm": 35,
    "fuzzing": 70,
    "report": 98,
    "done": 100,
}

_STAGE_TO_STATUS: dict[str, TaskStatus] = {
    "sbom": TaskStatus.ANALYZING_DEPS,
    "llm": TaskStatus.LLM_AUDITING,
    "fuzzing": TaskStatus.FUZZING,
}

_STAGE_LABEL: dict[str, str] = {
    "sbom": "Agent a：依赖识别智能体",
    "llm": "Agent b/c：假设生成与静态复核智能体",
    "fuzzing": "Agent d：验证工件智能体",
    "report": "Agent e：报告生成智能体",
}

_STAGE_START_MESSAGES: dict[str, tuple[str, str]] = {
    "sbom": (
        "Agent a：依赖识别智能体已启动。",
        "[Agent a] 正在解析项目文件、依赖元数据与 SBOM…\n",
    ),
    "llm": (
        "Agent b/c：假设生成与静态复核已启动。",
        "[Agent b/c] 正在构建漏洞假设并复核数据流…\n",
    ),
    "fuzzing": (
        "Agent d：验证工件智能体已启动。",
        "[Agent d] 正在准备 Harness、隔离沙箱与 eBPF 旁证…\n",
    ),
}


async def _get_task_status(task_db_id: str) -> TaskStatus | None:
    from sqlalchemy import select

    from app.models.task import Task

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Task.status).where(Task.id == uuid.UUID(task_db_id))
            )
            return result.scalar_one_or_none()
    except Exception as exc:
        logger.warning("[Middleware] failed to read task=%s: %s", task_db_id, exc)
        return None


async def _update_task_db(
    task_db_id: str,
    new_status: TaskStatus,
    error_message: str | None = None,
    mark_complete: bool = False,
) -> bool:
    from sqlalchemy import select

    from app.models.task import Task

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Task).where(Task.id == uuid.UUID(task_db_id))
            )
            task = result.scalar_one_or_none()
            if task is None:
                logger.warning("[Middleware] task=%s not found", task_db_id)
                return False

            if task.status in (TaskStatus.FAILED, TaskStatus.COMPLETED) and not mark_complete:
                logger.info("[Middleware] task=%s already terminal status=%s", task_db_id, task.status.value)
                return False

            task.status = new_status
            if error_message is not None:
                task.error_message = error_message
            if mark_complete:
                task.completed_at = datetime.now(UTC)

            await session.commit()
            logger.info("[Middleware] task=%s status=%s", task_db_id, new_status.value)
            return True
    except Exception as exc:
        logger.error("[Middleware] failed to update task=%s: %s", task_db_id, exc, exc_info=True)
        return False


async def _broadcast_progress(
    task_db_id: str,
    stage: str,
    percent: int,
    message: str,
    log_stream: str = "",
) -> None:
    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": stage,
            "percent": percent,
            "message": message,
            "log_stream": log_stream,
        },
    )


class SentinelMiddleware(TaskiqMiddleware):
    async def pre_execute(self, message: TaskiqMessage) -> TaskiqMessage:
        task_db_id: str = message.labels.get("task_db_id", "")
        stage: str = message.labels.get("stage", "unknown")
        if not task_db_id:
            return message

        new_status = _STAGE_TO_STATUS.get(stage, TaskStatus.PENDING)
        percent = _STAGE_PERCENT.get(stage, 0)
        updated = await _update_task_db(task_db_id, new_status)
        if not updated:
            await _broadcast_progress(
                task_db_id,
                stage="failed",
                percent=percent,
                message="任务已取消或结束，流水线已停止。",
                log_stream=f"[{stage.upper()}] 任务已处于终态，跳过该阶段。\n",
            )
            return message

        human_msg, stream_msg = _STAGE_START_MESSAGES.get(
            stage,
            (f"任务阶段 {stage} 已启动。", f"[{stage.upper()}] 阶段已启动。\n"),
        )
        await _broadcast_progress(task_db_id, stage, percent, human_msg, stream_msg)
        return message

    async def post_execute(
        self,
        message: TaskiqMessage,
        result: TaskiqResult[Any],
    ) -> None:
        task_db_id: str = message.labels.get("task_db_id", "")
        stage: str = message.labels.get("stage", "unknown")
        if not task_db_id:
            return

        # A task may have been cancelled while a blocking external call was in
        # flight. Its task function then exits cooperatively; do not overwrite
        # the cancellation event with a misleading stage-success message.
        current_status = await _get_task_status(task_db_id)
        if current_status in (TaskStatus.FAILED, TaskStatus.COMPLETED):
            logger.info(
                "[Middleware] suppressing post-stage event for terminal task=%s status=%s",
                task_db_id,
                current_status.value,
            )
            return

        percent = _STAGE_PERCENT.get(stage, 50)
        if result.is_err:
            err_str = str(result.error)[:1000]
            logger.error("[Middleware] task=%s stage=%s failed: %s", task_db_id, stage, err_str)
            await _update_task_db(
                task_db_id,
                TaskStatus.FAILED,
                error_message=f"[{stage}] {err_str}",
                mark_complete=True,
            )
            await _broadcast_progress(
                task_db_id,
                stage="failed",
                percent=percent,
                message=f"{_STAGE_LABEL.get(stage, stage)} 执行失败，请查看后端日志。",
                log_stream=f"[{stage.upper()}] 错误：{err_str}\n",
            )
            return

        logger.info("[Middleware] task=%s stage=%s succeeded", task_db_id, stage)
        await _broadcast_progress(
            task_db_id,
            stage=stage,
            percent=percent,
            message=f"{_STAGE_LABEL.get(stage, stage)} 已完成。",
            log_stream=f"[{_STAGE_LABEL.get(stage, stage)}] 执行完成。\n",
        )
