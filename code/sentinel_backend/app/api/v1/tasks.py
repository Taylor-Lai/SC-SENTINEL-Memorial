"""
7 个核心 HTTP 接口实现
POST   /api/v1/tasks                          → 提交审计任务与源码上传
GET    /api/v1/tasks                          → 查询历史任务列表（分页）
GET    /api/v1/tasks/{task_id}                → 单体状态查询（轻量级降级轮询）
GET    /api/v1/tasks/{task_id}/report         → 获取终极审计报告（四表联查）
POST   /api/v1/tasks/{task_id}/cancel         → 强制终止任务
GET    /api/v1/tasks/{task_id}/export-pdf     → 导出 PDF 审计报告（文件流下载）
"""
import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.database import get_db
from app.core.evidence import (
    calculate_report_risk,
    evidence_grade,
    evidence_sources,
    vulnerability_profile,
)
from app.core.pdf_generator import generate_audit_pdf
from app.core.ws_manager import ws_manager
from app.models.component_risk import ComponentRisk, Severity
from app.models.task import SourceType, Task, TaskStatus
from app.models.vulnerability import VerifyStatus, Vulnerability
from app.schemas.common import fail, ok
from app.schemas.task import (
    ComponentOut,
    DashboardStats,
    EbpfLogOut,
    LibRiskCount,
    ReportOut,
    ReportSummary,
    TaskCreateOut,
    TaskListItem,
    TaskStatusOut,
    VulnerabilityOut,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/tasks", tags=["Tasks"])

# ── 文件上传目录（项目根目录下的 uploads/）─────────────────────────────────────
UPLOAD_DIR = settings.UPLOAD_ROOT
UPLOAD_DIR.mkdir(exist_ok=True)


# ════════════════════════════════════════════════════════════════════════════
# API 1: POST /api/v1/tasks — 提交审计任务与源码上传
# ════════════════════════════════════════════════════════════════════════════
@router.post(
    "",
    summary="提交审计任务",
    description="接收 ZIP 文件或 GitHub 仓库地址，创建一条新的审计任务记录，初始状态为 pending。",
)
async def create_task(
    project_name: str = Form(..., description="项目名称，如 Heartbleed-test"),
    source_type: str = Form(..., description="源码来源，只能为 'zip' 或 'github'"),
    source_path: str | None = Form(None, description="GitHub 仓库 URL（source_type 为 github 时必填）"),
    file: UploadFile | None = File(None, description="ZIP 源码包（source_type 为 zip 时必填）"),
    target_vulns: str | None = Form(None, description="目标漏洞类型，JSON 字符串，如 '[\"UAF\",\"Heap_Overflow\"]'"),
    is_dynamic: str | None = Form("false", description="是否开启 eBPF 动态验证，传 'true' 或 'false'"),
    db: AsyncSession = Depends(get_db),
):
    project_name = project_name.strip()
    if not 2 <= len(project_name) <= 120:
        return fail(400, "project_name 长度必须在 2 到 120 个字符之间")

    if target_vulns:
        try:
            parsed_targets = json.loads(target_vulns)
        except json.JSONDecodeError:
            return fail(400, "target_vulns 必须是 JSON 字符串数组")
        if not isinstance(parsed_targets, list) or not all(isinstance(item, str) for item in parsed_targets):
            return fail(400, "target_vulns 必须是字符串数组")
        if len(parsed_targets) > 20:
            return fail(400, "target_vulns 最多允许 20 项")
        target_vulns = json.dumps(parsed_targets, ensure_ascii=False)

    # ── 校验 source_type ──────────────────────────────────────────────────
    try:
        src_type = SourceType(source_type.lower())
    except ValueError:
        return fail(400, f"source_type 必须为 'zip' 或 'github'，收到: '{source_type}'")

    # ── 条件必填校验 & 文件存储 ───────────────────────────────────────────
    task_id = uuid.uuid4()

    if src_type == SourceType.ZIP:
        if not file:
            return fail(400, "source_type 为 zip 时，file 为必传字段")
        if not file.filename or Path(file.filename).suffix.lower() != ".zip":
            await file.close()
            return fail(400, "仅支持 .zip 源码包")

        # 为每个任务创建独立子目录，防止同名文件互相覆盖
        save_dir = UPLOAD_DIR / str(task_id)
        save_dir.mkdir(parents=True, exist_ok=True)
        safe_filename = Path(file.filename).name  # 去掉路径中的目录穿越风险
        file_path = save_dir / safe_filename

        # 异步分块落盘：UploadFile.read 是 async 的，写文件放到线程池，
        # 避免大文件（最高 100MB）阻塞 FastAPI 事件循环。
        def _write_chunk(f, chunk: bytes) -> None:
            f.write(chunk)

        bytes_written = 0
        try:
            with open(file_path, "wb") as f:
                while True:
                    chunk = await file.read(1024 * 1024)  # 每次读 1MB
                    if not chunk:
                        break
                    bytes_written += len(chunk)
                    if bytes_written > settings.MAX_UPLOAD_BYTES:
                        raise ValueError(
                            f"上传文件超过 {settings.MAX_UPLOAD_BYTES // (1024 * 1024)}MB 限制"
                        )
                    await asyncio.to_thread(_write_chunk, f, chunk)
        except ValueError as exc:
            file_path.unlink(missing_ok=True)
            try:
                save_dir.rmdir()
            except OSError:
                pass
            return fail(413, str(exc))
        finally:
            await file.close()

        stored_path = str(file_path)

    else:  # SourceType.GITHUB
        if not source_path:
            return fail(400, "source_type 为 github 时，source_path（仓库 URL）为必传字段")
        from app.services.repository_policy import is_allowed_remote_repository_url

        if not is_allowed_remote_repository_url(source_path):
            return fail(400, "仅允许 GitHub、GitLab、Gitee、Bitbucket 或 Codeup 仓库 URL")
        stored_path = source_path

    # ── 解析布尔字符串 ────────────────────────────────────────────────────
    is_dynamic_bool = isinstance(is_dynamic, str) and is_dynamic.lower() == "true"

    # ── 写入数据库 ────────────────────────────────────────────────────────
    task = Task(
        id=task_id,
        project_name=project_name,
        source_type=src_type,
        source_path=stored_path,
        status=TaskStatus.PENDING,
        target_vulns=target_vulns,
        is_dynamic=is_dynamic_bool,
    )
    db.add(task)
    await db.flush()   # 让 ORM 填充 server_default 字段（created_at 等）
    await db.commit()  # 立即落库，防止 audit/submit 竞态查不到该记录

    return ok(
        TaskCreateOut.model_validate(task).model_dump(mode="json"),
        "审计任务创建成功，等待调度执行",
    )


# ════════════════════════════════════════════════════════════════════════════
# API 2: GET /api/v1/tasks — 查询历史任务列表（分页）
# ════════════════════════════════════════════════════════════════════════════
@router.get(
    "",
    summary="查询历史任务列表",
    description="按创建时间倒序返回分页的审计任务列表。",
)
async def list_tasks(
    page: int = Query(1, ge=1, description="页码，从 1 开始"),
    size: int = Query(10, ge=1, le=100, description="每页条数，最大 100"),
    project_name: str | None = Query(None, description="按项目名模糊筛选"),
    status: str | None = Query(None, description="按任务状态精确筛选"),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * size

    # ── 构建过滤条件 ──────────────────────────────────────────────────────
    filters = []
    if project_name:
        filters.append(Task.project_name.ilike(f"%{project_name}%"))
    if status:
        try:
            filters.append(Task.status == TaskStatus(status.lower()))
        except ValueError:
            return fail(400, f"非法的 status 值: '{status}'")

    # 查总数（含过滤）
    count_stmt = select(func.count()).select_from(Task)
    if filters:
        count_stmt = count_stmt.where(*filters)
    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one()

    # 查分页数据（按创建时间倒序），预加载 vulnerabilities 以统计数量
    list_stmt = (
        select(Task)
        .options(selectinload(Task.vulnerabilities))
        .order_by(Task.created_at.desc())
        .offset(offset)
        .limit(size)
    )
    if filters:
        list_stmt = list_stmt.where(*filters)
    result = await db.execute(list_stmt)
    tasks = result.scalars().all()

    items = []
    for t in tasks:
        item = TaskListItem.model_validate(t)
        # vuln_count 动态计算（ORM 关系已预加载）
        item.vuln_count = len(t.vulnerabilities) if t.vulnerabilities else 0
        items.append(item.model_dump(mode="json"))

    return ok({"total": total, "items": items})


# ════════════════════════════════════════════════════════════════════════════
# API: GET /api/v1/tasks/stats — 全局聚合统计（History 仪表盘）
# 注意：必须定义在 /{task_id} 之前，否则 "stats" 会被当作 task_id 解析。
# ════════════════════════════════════════════════════════════════════════════
@router.get(
    "/stats",
    summary="全局聚合统计",
    description="一次性返回 History 仪表盘所需的全部 KPI 与图表数据，"
                "避免前端对每个已完成任务单独发起报告查询（N+1）。",
)
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    # ── 任务状态计数 ──────────────────────────────────────────────────────
    status_rows = await db.execute(select(Task.status, func.count()).group_by(Task.status))
    status_count: dict[TaskStatus, int] = {s: c for s, c in status_rows.all()}

    total_audits = sum(status_count.values())
    completed = status_count.get(TaskStatus.COMPLETED, 0)
    failed = status_count.get(TaskStatus.FAILED, 0)
    running = total_audits - completed - failed

    # ── 漏洞类型分布 + 确认率 ─────────────────────────────────────────────
    vuln_rows = await db.execute(
        select(Vulnerability.vuln_type, Vulnerability.verify_status)
    )
    vuln_type_dist: dict[str, int] = {}
    total_vulns = 0
    confirmed = 0
    not_reproduced = 0
    pending_verification = 0
    for vtype, vstatus in vuln_rows.all():
        total_vulns += 1
        key = _normalize_vuln_type(vtype)
        vuln_type_dist[key] = vuln_type_dist.get(key, 0) + 1
        if vstatus == VerifyStatus.CONFIRMED:
            confirmed += 1
        elif vstatus in (VerifyStatus.NOT_REPRODUCED, VerifyStatus.FALSE_POSITIVE):
            not_reproduced += 1
        else:
            pending_verification += 1
    dynamically_assessed = confirmed + not_reproduced
    confirm_rate = round(confirmed / dynamically_assessed * 100) if dynamically_assessed else 0
    verification_coverage = round(dynamically_assessed / total_vulns * 100) if total_vulns else 0

    # ── 组件 CVE 风险（按库聚合，拆分等级）────────────────────────────────
    comp_rows = await db.execute(
        select(ComponentRisk.library_name, ComponentRisk.severity)
    )
    cve_risks = 0
    lib_map: dict[str, dict[str, int]] = {}
    for lib_name, severity in comp_rows.all():
        cve_risks += 1
        bucket = lib_map.setdefault(lib_name, {"critical": 0, "high": 0, "other": 0})
        if severity == Severity.CRITICAL:
            bucket["critical"] += 1
        elif severity == Severity.HIGH:
            bucket["high"] += 1
        else:
            bucket["other"] += 1

    top_libs = sorted(
        (LibRiskCount(library_name=name, **counts) for name, counts in lib_map.items()),
        key=lambda x: x.critical + x.high + x.other,
        reverse=True,
    )[:6]

    # ── 平均端到端耗时（仅统计有完成时间的任务）──────────────────────────
    time_rows = await db.execute(
        select(Task.created_at, Task.completed_at).where(
            Task.status == TaskStatus.COMPLETED,
            Task.completed_at.isnot(None),
        )
    )
    durations = []
    for ca, co in time_rows.all():
        if ca and co:
            if ca.tzinfo is None:
                ca = ca.replace(tzinfo=UTC)
            if co.tzinfo is None:
                co = co.replace(tzinfo=UTC)
            durations.append((co - ca).total_seconds())
    avg_scan_seconds = round(sum(durations) / len(durations)) if durations else 0

    stats = DashboardStats(
        total_audits=total_audits,
        completed=completed,
        running=running,
        failed=failed,
        total_vulns=total_vulns,
        confirmed_vulns=confirmed,
        not_reproduced_vulns=not_reproduced,
        pending_verification=pending_verification,
        cve_risks=cve_risks,
        confirm_rate=confirm_rate,
        verification_coverage=verification_coverage,
        avg_scan_seconds=avg_scan_seconds,
        vuln_type_dist=vuln_type_dist,
        top_libs=top_libs,
    )
    return ok(stats.model_dump(mode="json"))


# vuln_type 标准化：把对接规范缩写与 LLM 自由文本归一到展示标签
_VULN_TYPE_LABELS = {
    "uaf": "UAF",
    "use-after-free": "UAF",
    "use_after_free": "UAF",
    "buffer_overflow": "Buffer Overflow",
    "buffer-overflow": "Buffer Overflow",
    "heap_overflow": "Heap Overflow",
    "double_free": "Double Free",
    "stack_overflow": "Stack Overflow",
}


def _normalize_vuln_type(vtype: str) -> str:
    if not vtype:
        return "Other"
    return _VULN_TYPE_LABELS.get(vtype.strip().lower(), vtype)


# ════════════════════════════════════════════════════════════════════════════
# API 3: GET /api/v1/tasks/{task_id} — 单体状态查询（降级轮询）
# ════════════════════════════════════════════════════════════════════════════
@router.get(
    "/{task_id}",
    summary="查询任务状态",
    description="返回完整的任务状态信息，供前端进度页轮询使用。",
)
async def get_task_status(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Task)
        .where(Task.id == task_id)
        .options(selectinload(Task.vulnerabilities))
    )
    task = result.scalar_one_or_none()

    if not task:
        return fail(404, f"任务 {task_id} 不存在")

    out = TaskStatusOut.model_validate(task)
    out.vuln_count = len(task.vulnerabilities) if task.vulnerabilities else 0
    return ok(out.model_dump(mode="json"))


# ════════════════════════════════════════════════════════════════════════════
# API 4: GET /api/v1/tasks/{task_id}/report — 终极审计报告（四表联查）
# ════════════════════════════════════════════════════════════════════════════
@router.get(
    "/{task_id}/report",
    summary="获取终极审计报告",
    description="状态变为 completed 后调用。后端一次性聚合 task + component_risk + "
                "vulnerability + ebpf_event_log 四张表，计算总耗时并返回完整报告。",
)
async def get_task_report(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    # 四表联查：使用 selectinload 预加载所有关联关系，避免 N+1 查询
    result = await db.execute(
        select(Task)
        .where(Task.id == task_id)
        .options(
            selectinload(Task.component_risks),
            selectinload(Task.vulnerabilities).selectinload(Vulnerability.ebpf_events),
        )
    )
    task = result.scalar_one_or_none()

    if not task:
        return fail(404, f"任务 {task_id} 不存在")

    if task.status != TaskStatus.COMPLETED:
        return fail(
            400,
            f"任务尚未完成，当前状态为 '{task.status.value}'，请等待任务执行完毕后再获取报告",
        )

    # ── 计算总耗时 ────────────────────────────────────────────────────────
    total_seconds: float | None = None
    if task.completed_at and task.created_at:
        # 确保两个时间都有时区信息，然后相减
        ca = task.created_at
        co = task.completed_at
        if ca.tzinfo is None:
            ca = ca.replace(tzinfo=UTC)
        if co.tzinfo is None:
            co = co.replace(tzinfo=UTC)
        total_seconds = (co - ca).total_seconds()

    # ── 构建四层嵌套响应 ──────────────────────────────────────────────────
    risk_score, risk_level = calculate_report_risk(
        task.vulnerabilities,
        task.component_risks,
    )
    confirmed_count = sum(
        1 for item in task.vulnerabilities if item.verify_status == VerifyStatus.CONFIRMED
    )
    not_reproduced_count = sum(
        1 for item in task.vulnerabilities
        if item.verify_status in (VerifyStatus.NOT_REPRODUCED, VerifyStatus.FALSE_POSITIVE)
    )
    summary = ReportSummary(
        project_name=task.project_name,
        total_time_seconds=total_seconds,
        is_dynamic=task.is_dynamic,
        risk_score=risk_score,
        risk_level=risk_level,
        confirmed_count=confirmed_count,
        candidate_count=len(task.vulnerabilities) - confirmed_count - not_reproduced_count,
        not_reproduced_count=not_reproduced_count,
    )

    components = [ComponentOut.model_validate(c) for c in task.component_risks]

    vulnerabilities = []
    candidate_vulnerabilities = []
    for v in task.vulnerabilities:
        ebpf_logs = [EbpfLogOut.model_validate(e) for e in v.ebpf_events]
        profile = vulnerability_profile(v.vuln_type)
        vuln_out = VulnerabilityOut(
            id=v.id,
            vuln_type=v.vuln_type,
            file_path=v.file_path,
            line_number=v.line_number,
            code_context=v.code_context,
            description=None,
            trigger_condition=v.trigger_cond,
            fix_suggestion=v.fix_advice,
            verify_status=v.verify_status,
            crash_output=v.afl_log,
            ebpf_logs=ebpf_logs,
            llm_original_type=v.llm_original_type,
            ebpf_corrected=v.ebpf_corrected,
            cwe_id=profile.cwe_id,
            severity=profile.severity,
            evidence_sources=evidence_sources(v),
            evidence_grade=evidence_grade(v),
        )
        if v.verify_status == VerifyStatus.CONFIRMED:
            vulnerabilities.append(vuln_out)
        else:
            candidate_vulnerabilities.append(vuln_out)

    report = ReportOut(
        summary=summary,
        components=components,
        vulnerabilities=vulnerabilities,
        candidate_vulnerabilities=candidate_vulnerabilities,
    )

    return ok(report.model_dump(mode="json"))


# ════════════════════════════════════════════════════════════════════════════
# API 5: POST /api/v1/tasks/{task_id}/cancel — 强制终止任务
# ════════════════════════════════════════════════════════════════════════════
@router.post(
    "/{task_id}/cancel",
    summary="强制终止任务",
    description="紧急制动阀。将任务状态改为 failed，记录取消原因。"
                "如任务处于 Fuzzing 阶段，同步强杀 Docker 沙箱容器。",
)
async def cancel_task(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one_or_none()

    if not task:
        return fail(404, f"任务 {task_id} 不存在")

    # 已终结的任务不可再次取消
    if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
        return fail(
            400,
            f"任务已处于终态（当前状态: '{task.status.value}'），无需取消",
        )

    # ── 如果任务正在进行 Fuzzing，强制销毁 Docker 沙箱容器 ──────────────────
    if task.status == TaskStatus.FUZZING:
        from app.services.sandbox_manager import force_kill_container
        task_id_str = str(task_id)
        try:
            # docker-py 是同步阻塞库，在线程池中执行
            killed = await asyncio.to_thread(force_kill_container, task_id_str)
            if killed:
                task.error_message = "用户手动取消任务，Docker 沙箱容器已强制销毁"
            else:
                task.error_message = "用户手动取消任务（容器不存在或已自动销毁）"
        except Exception as e:
            logger.warning(f"[Cancel] 强杀容器失败 task={task_id}: {e}")
            task.error_message = f"用户手动取消（容器强杀失败: {str(e)[:100]}）"
    else:
        task.error_message = "用户手动取消任务"

    # ── 更新数据库状态 ────────────────────────────────────────────────────────
    task.status = TaskStatus.FAILED
    task.completed_at = datetime.now(UTC)
    await db.commit()

    await ws_manager.broadcast(
        str(task_id),
        {
            "stage": "cancelled",
            "percent": 0,
            "message": "任务已由用户终止。",
            "log_stream": "[CONTROL] Cancellation acknowledged; downstream stages will not start.\n",
        },
    )

    return ok(None, f"任务 {task_id} 已强制终止")



# ════════════════════════════════════════════════════════════════════════════
# API 7: GET /api/v1/tasks/{task_id}/export-pdf — 导出 PDF 审计报告
# 执行手册出处：
#   ML 同学 B 任务分配 → "PDF 报告导出：使用 WeasyPrint 或 ReportLab 生成可下载的 PDF 审计报告"
#   页面三顶部概览卡片 → "下载 PDF 按钮"
# ════════════════════════════════════════════════════════════════════════════
@router.get(
    "/{task_id}/export-pdf",
    summary="导出 PDF 审计报告",
    description=(
        "前端点击【下载 PDF】按钮时调用。后端调用 ReportLab 生成完整的 PDF 审计报告，"
        "以文件流形式返回（Content-Type: application/pdf），浏览器会自动触发文件下载。"
        "任务必须处于 completed 状态才可导出。"
    ),
    response_class=Response,
)
async def export_task_pdf(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    # -- 四表联查（与 report 接口保持一致，预加载所有关联数据） ───────────────
    result = await db.execute(
        select(Task)
        .where(Task.id == task_id)
        .options(
            selectinload(Task.component_risks),
            selectinload(Task.vulnerabilities).selectinload(Vulnerability.ebpf_events),
        )
    )
    task = result.scalar_one_or_none()

    if not task:
        return fail(404, f"任务 {task_id} 不存在")

    if task.status != TaskStatus.COMPLETED:
        return fail(
            400,
            f"任务尚未完成（当前状态: '{task.status.value}'），只有 completed 状态才可导出 PDF",
        )

    # -- 调用 ReportLab 生成 PDF 字节流 ──────────────────────────────────────
    pdf_bytes = generate_audit_pdf(task)

    # -- 生成安全文件名（项目名去除非 ASCII，避免浏览器下载时 Content-Disposition 乱码）
    safe_name = (
        task.project_name.encode("ascii", "ignore").decode("ascii").replace(" ", "_")
        or str(task_id)
    )
    filename = f"SC-SENTINEL_Report_{safe_name}_{str(task_id)[:8]}.pdf"

    # -- 以 StreamingResponse 返回，触发浏览器下载 ────────────────────────────
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )
