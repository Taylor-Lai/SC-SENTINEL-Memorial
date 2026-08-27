"""
审计调度接口
────────────────────────────────────────────────────────────────────────────
POST /api/v1/audit/submit
  接收审计请求（task_id 来自已创建的 Task），下发 TaskIQ Pipeline，
  向前端返回 task_id 和 WebSocket 连接地址。

GET  /api/v1/audit/status/{task_id}
  根据 task_id 查询任务当前阶段及执行进度（轻量级降级轮询接口）。
  WebSocket 断开时由前端每 3 秒调用此接口静默同步状态。

关系说明：
  POST /api/v1/tasks           → 上传源码、创建 Task 记录（阶段一已有）
  POST /api/v1/audit/submit    → 触发异步 Pipeline（阶段二新增）
  GET  /api/v1/audit/status    → 查询进度（阶段二新增，轮询降级）
  WS   /api/v1/ws/tasks/.../progress → 实时推送（阶段一已有，阶段二联通）
"""
import logging
import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.task import Task, TaskStatus
from app.schemas.common import fail, ok
from app.worker.pipeline import dispatch_audit_pipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/audit", tags=["Audit"])


# ── Request / Response Schema ─────────────────────────────────────────────────

class AuditSubmitRequest(BaseModel):
    """POST /audit/submit 请求体"""
    task_id: uuid.UUID = Field(..., description="已创建的 Task UUID（通过 POST /tasks 获得）")


class AuditStatusOut(BaseModel):
    """GET /audit/status/{task_id} 响应体"""
    task_id: uuid.UUID
    project_name: str
    status: str
    status_label: str        # 人类可读的状态描述
    progress_percent: int    # 当前进度百分比（0-100）
    ws_url: str              # WebSocket 连接地址，供前端建立实时连接
    error_message: str | None = None

    class Config:
        from_attributes = True


# ── 阶段 → 进度百分比映射（与 Middleware 保持一致）─────────────────────────────
_STATUS_PERCENT: dict[TaskStatus, int] = {
    TaskStatus.PENDING:       5,
    TaskStatus.ANALYZING_DEPS: 20,
    TaskStatus.LLM_AUDITING:  35,
    TaskStatus.FUZZING:       70,
    TaskStatus.COMPLETED:    100,
    TaskStatus.FAILED:        -1,   # 失败时前端显示错误状态
}

_STATUS_LABEL: dict[TaskStatus, str] = {
    TaskStatus.PENDING:       "排队等待中",
    TaskStatus.ANALYZING_DEPS: "正在分析依赖组件 (SBOM)",
    TaskStatus.LLM_AUDITING:  "LLM Multi-Agent 静态审计中",
    TaskStatus.FUZZING:       "AFL++ + eBPF 动态验证中",
    TaskStatus.COMPLETED:    "审计完成，报告已生成",
    TaskStatus.FAILED:        "任务执行失败",
}


# ════════════════════════════════════════════════════════════════════════════
# API: POST /api/v1/audit/submit — 触发审计 Pipeline
# ════════════════════════════════════════════════════════════════════════════
@router.post(
    "/submit",
    summary="触发审计 Pipeline",
    description=(
        "根据已创建的 Task ID 触发后台异步审计流程（SBOM → LLM → 可选 Fuzzing）。"
        "任务创建请先调用 POST /api/v1/tasks，获取 task_id 后再调用此接口。"
    ),
)
async def submit_audit(
    request: AuditSubmitRequest,
    db: AsyncSession = Depends(get_db),
):
    task_id_str = str(request.task_id)

    # ── 查询任务是否存在 ──────────────────────────────────────────────────────
    # Lock the row so concurrent/retried submit requests cannot enqueue the
    # same audit twice while it is still reported as pending.
    result = await db.execute(
        select(Task).where(Task.id == request.task_id).with_for_update()
    )
    task = result.scalar_one_or_none()

    if not task:
        return fail(404, f"任务 {task_id_str} 不存在，请先调用 POST /api/v1/tasks 创建任务")

    # ── 防重放：非 pending 状态的任务不允许重复触发 ───────────────────────────
    if task.status != TaskStatus.PENDING:
        return fail(
            400,
            f"任务已处于 '{task.status.value}' 状态，不可重复触发。"
            f"如需重新分析，请创建新任务。",
        )

    task.status = TaskStatus.ANALYZING_DEPS
    await db.commit()

    # ── 异步下发 Pipeline（立即返回，不等待 Pipeline 执行完成）──────────────────
    try:
        await dispatch_audit_pipeline(
            task_db_id=task_id_str,
            source_path=task.source_path,
            is_dynamic=task.is_dynamic,
        )
    except Exception:
        logger.exception("[Audit] task=%s Pipeline 下发失败", task_id_str)
        task.status = TaskStatus.PENDING
        await db.commit()
        return fail(503, "任务队列暂时不可用，请稍后重试")

    logger.info(f"[Audit] task={task_id_str} Pipeline 已下发，返回前端")

    return ok(
        {
            "task_id": task_id_str,
            "status": TaskStatus.ANALYZING_DEPS.value,
            "ws_url": f"/api/v1/ws/tasks/{task_id_str}/progress",
            "message": "审计 Pipeline 已启动，请连接 WebSocket 接收实时进度推送",
        },
        "审计任务已成功下发",
    )


# ════════════════════════════════════════════════════════════════════════════
# API: GET /api/v1/audit/status/{task_id} — 任务状态轮询（降级方案）
# ════════════════════════════════════════════════════════════════════════════
@router.get(
    "/status/{task_id}",
    summary="查询审计任务进度",
    description=(
        "轻量级单表查询，返回任务当前阶段、进度百分比和 WebSocket 连接地址。"
        "供前端在 WebSocket 断开时每 3 秒静默轮询使用。"
    ),
)
async def get_audit_status(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one_or_none()

    if not task:
        return fail(404, f"任务 {task_id} 不存在")

    task_id_str = str(task_id)
    percent = _STATUS_PERCENT.get(task.status, 0)
    label = _STATUS_LABEL.get(task.status, task.status.value)

    status_out = {
        "task_id":         task_id_str,
        "project_name":    task.project_name,
        "status":          task.status.value,
        "status_label":    label,
        "progress_percent": percent,
        "ws_url":          f"/api/v1/ws/tasks/{task_id_str}/progress",
        "error_message":   task.error_message,
    }

    return ok(status_out)
