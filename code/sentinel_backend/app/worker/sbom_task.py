"""
Agent a：依赖识别智能体（调用依赖识别服务）
──────────────────────────────────────────────────────────────────────
后端职责（执行手册第 3 章）：
  1. 解压 ZIP 源码包，提取依赖声明文件（CMakeLists.txt / Makefile 等）
  2. 将解析后的依赖信息 POST 给依赖识别服务
  3. 接收 Agent a 返回的 CVE 风险列表，批量写入 component_risk 表
  4. 完成后自动触发 LLM 阶段（链式回调）

接收 Agent a 返回格式（约定）：
  {
    "components": [
      {
        "library_name": "openssl",
        "version": "1.0.1e",
        "cve_id": "CVE-2014-0160",
        "cvss_score": 7.8,
        "severity": "high",           // critical/high/medium/low/unknown
        "description": "Heartbleed...",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
      }
    ]
  }
"""
import asyncio
import logging
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import httpx
from sqlalchemy import delete

from app.core.broker import broker
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager
from app.models.component_risk import ComponentRisk, Severity
from app.services.repository_policy import is_allowed_remote_repository_url
from app.services.source_parser import _summarize_description

logger = logging.getLogger(__name__)

# ── Severity 字符串 → 枚举映射 ────────────────────────────────────────────────
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "unknown":  Severity.UNKNOWN,
}


def _component_risk_description(component: dict) -> str:
    """Normalize NVD/OSV prose into a consistent, reviewer-friendly summary."""
    library = str(component.get("library_name") or "unknown")
    version = str(component.get("version") or "版本未识别")
    cve = str(component.get("cve_id") or "")
    raw = str(component.get("description") or "").strip()
    summary = _summarize_description(raw, max_length=220) if raw else "未提供公开漏洞描述"
    match_note = f"已匹配 {cve}" if cve else "暂未匹配具体 CVE"
    return (
        f"{library} {version}：{summary}。{match_note}；"
        "该 SBOM 记录表示组件风险线索，需结合源码调用链和运行时证据进一步确认，"
        "不等同于本项目已经触发该漏洞。"
    )


def _resolve_path(value: str) -> str:
    return str(Path(value).resolve())


def _path_is_absolute(value: str) -> bool:
    return Path(value).is_absolute()


def _path_is_file(value: str) -> bool:
    return Path(value).is_file()


def _path_is_dir(value: str) -> bool:
    return Path(value).is_dir()

async def _call_agent_a(
    dep_files: list[dict],
    includes: list[str],
    cpp_files: list[str],
    source_root_path: str = "",
) -> dict:
    """
    调用依赖识别服务，获取依赖 CVE 风险分析结果。

    Args:
        dep_files:        依赖声明文件内容列表（来自 source_parser）
        includes:         #include 引用列表（来自 source_parser）
        cpp_files:        C/C++ 文件路径列表（供 Agent a 评估覆盖范围）
        source_root_path: 解压后的源码根目录绝对路径（Agent 与后端同机时使用）

    Returns:
        Agent a 返回的原始 JSON 字典
    """
    request_body = {
        "source_root": source_root_path,  # 优先让 Agent a 直接读本地目录
        "dep_files":   dep_files,
        "includes":    includes,
        "cpp_files":   cpp_files,
    }

    logger.info(f"[Agent a] 调用依赖识别服务: {settings.ML_AGENT_A_URL}")
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(settings.ML_AGENT_A_URL, json=request_body)
            resp.raise_for_status()
            data = resp.json()
            logger.info(f"[Agent a] 依赖识别服务响应成功，HTTP {resp.status_code}")
            return data
    except httpx.TimeoutException:
        logger.error("[Agent a] 依赖识别服务调用超时（120s）")
        raise
    except httpx.HTTPStatusError as e:
        logger.error(f"[Agent a] 依赖识别服务返回错误状态码 {e.response.status_code}: {e.response.text[:500]}")
        raise
    except Exception as e:
        logger.error(f"[Agent a] 依赖识别服务调用失败: {e}", exc_info=True)
        raise


# 后端进程运行目录下的 uploads/，与 tasks.py 的 UPLOAD_DIR 保持一致
_UPLOAD_DIR = Path("uploads")


def _looks_like_git_url(value: str) -> bool:
    """Accept only repository hosts explicitly approved by the service."""
    return is_allowed_remote_repository_url(value)


def _clone_github_repo(repo_url: str, task_db_id: str) -> str:
    """
    Shallow clone 远程 Git 仓库到 uploads/{task_id}/repo，返回本地根目录路径。

    - 用 --depth 1 只拉最新一次提交，加快下载、节省磁盘。
    - 关闭 git 交互式凭据询问（GIT_TERMINAL_PROMPT=0），
      避免私有仓库无凭据时进程挂起。
    - 出错时抛异常，让 TaskIQ 的重试机制处理。
    """
    dest_dir = (_UPLOAD_DIR / task_db_id / "repo").resolve()
    if dest_dir.exists():
        # 幂等：清空后重新克隆，避免上次残留半个仓库
        shutil.rmtree(dest_dir, ignore_errors=True)
    dest_dir.parent.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"

    logger.info(f"[SBOM] 开始 git clone {repo_url} -> {dest_dir}")
    try:
        completed = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", repo_url, str(dest_dir)],
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "系统未安装 git，无法克隆远程仓库。请在部署环境安装 git，或改用 ZIP 上传。"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git clone 超时（180s），仓库可能过大或网络受限：{repo_url}") from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()[:500]
        raise RuntimeError(
            f"git clone 失败（exit={completed.returncode}）：{stderr}"
        )

    logger.info(f"[SBOM] git clone 完成，源码根目录: {dest_dir}")
    return str(dest_dir)


async def _save_component_risks(task_db_id: str, flat_components: list[dict]) -> int:
    """
    将已展平的组件风险列表批量写入 component_risk 表。

    Args:
        task_db_id: 任务ID
        flat_components: 已展平的组件列表，每个CVE一条记录

    Returns:
        写入的记录条数
    """
    async with AsyncSessionLocal() as session:
        # Replace this stage's output so TaskIQ retries remain idempotent.
        await session.execute(
            delete(ComponentRisk).where(ComponentRisk.task_id == uuid.UUID(task_db_id))
        )
        if not flat_components:
            await session.commit()
            logger.info(f"[Agent a] task={task_db_id} 未发现组件风险")
            return 0
        records = []
        for comp in flat_components:
            severity_str = str(comp.get("severity", "unknown")).lower()
            severity = _SEVERITY_MAP.get(severity_str, Severity.UNKNOWN)

            record = ComponentRisk(
                task_id=uuid.UUID(task_db_id),
                library_name=comp.get("library_name", "unknown"),
                version=comp.get("version"),
                cve_id=comp.get("cve_id"),
                cvss_score=comp.get("cvss_score"),
                severity=severity,
                description=_component_risk_description(comp),
                nvd_url=comp.get("nvd_url"),
            )
            records.append(record)

        session.add_all(records)
        await session.commit()
        logger.info(f"[SBOM] task={task_db_id} 写入 {len(records)} 条组件风险记录")
        return len(records)


def _flatten_component_risks(components: list[dict]) -> list[dict]:
    """Accept both Agent A's rich component shape and the legacy flat shape.

    The agent service may return either a component containing
    ``matched_vulnerabilities`` or one row per CVE.  Persisting only the outer
    component silently drops all CVEs from the report, so normalize both forms
    before writing the database rows.
    """
    rows: list[dict] = []
    for component in components or []:
        if not isinstance(component, dict):
            continue
        vulnerabilities = (
            component.get("matched_vulnerabilities")
            or component.get("matched_cves")
            or component.get("top_vulnerabilities")
            or []
        )
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            rows.append(component)
            continue

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            row = dict(component)
            row.update({
                "cve_id": vulnerability.get("cve_id") or vulnerability.get("id"),
                "cvss_score": vulnerability.get("cvss_score")
                if vulnerability.get("cvss_score") is not None
                else vulnerability.get("severity_score"),
                "severity": vulnerability.get("severity")
                or vulnerability.get("risk_level")
                or component.get("risk_level")
                or "unknown",
                "description": vulnerability.get("description")
                or vulnerability.get("summary")
                or vulnerability.get("details")
                or component.get("description"),
                "nvd_url": vulnerability.get("nvd_url")
                or next(
                    (ref for ref in vulnerability.get("references", [])
                     if isinstance(ref, str) and "nvd.nist.gov" in ref),
                    None,
                ),
            })
            rows.append(row)
    return rows


async def _publish_sbom_log(task_db_id: str, message: str, log_stream: str) -> None:
    """Publish an Agent-a-specific SBOM event to the shared progress stream."""
    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": "sbom",
            "percent": 20,
            "message": message,
            "log_stream": log_stream,
        },
    )


@broker.task(
    task_name="sbom_analysis",
    max_retries=2,
    retry_on_error=True,
)
async def run_sbom_analysis(task_db_id: str, source_path: str, is_dynamic: bool = False) -> dict:
    """
    SBOM 依赖分析任务（阶段一）。

    执行步骤：
      1. 判断 source_path 是 ZIP 文件还是已解压目录
      2. 调用 source_parser 提取依赖信息
      3. 调用 Agent a 接口获取 CVE 风险列表
      4. 批量写入 component_risk 表
      5. 链式触发 LLM 审计阶段

    Labels（由 pipeline.dispatch_audit_pipeline 注入）：
      task_db_id : str  → PostgreSQL task.id
      stage      : "sbom"

    Returns:
        dict: {"components_found": int, "high_risk_count": int, "source_root": str}
    """
    logger.info(f"[SBOM] 开始分析 task={task_db_id}, source={source_path}")
    from app.worker.pipeline import _is_task_cancelled

    if await _is_task_cancelled(task_db_id):
        return {"cancelled": True, "components_found": 0}

    # ── 步骤 1: 解压 ZIP 或使用已解压目录 ────────────────────────────────────
    from app.services.source_parser import parse_source_context, parse_zip_source

    # 相对路径转绝对路径（兼容本地开发和 Docker 容器两种场景）
    # 注意：Git URL 不能走 Path.resolve，否则会被拼成一个不存在的假本地路径。
    if not _looks_like_git_url(source_path) and not _path_is_absolute(source_path):
        source_path = _resolve_path(source_path)
        logger.info(f"[SBOM] 相对路径已转换为绝对路径: {source_path}")

    source_root = source_path
    ctx = None

    if source_path.endswith(".zip") and _path_is_file(source_path):
        # 用户上传了 ZIP 文件，解压并解析
        logger.info(f"[SBOM] 检测到 ZIP 文件，开始解压: {source_path}")
        ctx = await asyncio.to_thread(parse_zip_source, source_path)
        source_root = ctx.source_root
        logger.info(f"[SBOM] ZIP 解压完成，源码根目录: {source_root}")
    elif _path_is_dir(source_path):
        # 已经是目录（如 GitHub clone 后的路径）
        ctx = await asyncio.to_thread(parse_source_context, source_path)
        source_root = ctx.source_root
    elif _looks_like_git_url(source_path):
        # GitHub / GitLab / Gitee 等远程仓库，先浅克隆到本地再进入解析流程
        logger.info(f"[SBOM] 检测到远程 Git 仓库 URL: {source_path}")
        cloned_root = await asyncio.to_thread(_clone_github_repo, source_path, task_db_id)
        ctx = await asyncio.to_thread(parse_source_context, cloned_root)
        source_root = ctx.source_root
        logger.info(f"[SBOM] 远程仓库克隆并解析完成，源码根目录: {source_root}")
    else:
        # 既不是 ZIP、不是目录，也不匹配 Git URL 模式 —— 明确报错
        logger.error(f"[SBOM] source_path 无法识别: {source_path}")
        raise ValueError(
            f"source_path 无法识别为 ZIP 文件、本地目录或远程 Git 仓库 URL: {source_path}"
        )

    # ── 步骤 2: Agent a 依赖识别 ─────────────────────────────────────────────
    dep_files = ctx.dep_files if ctx else []
    includes  = ctx.includes  if ctx else []
    cpp_files = ctx.cpp_files if ctx else []

    await _publish_sbom_log(
        task_db_id,
        "Agent a：正在解析依赖声明、头文件引用并查询 OSV / NVD。",
        f"[Agent a] dependency files={len(dep_files)}, includes={len(includes)}, C/C++ files={len(cpp_files)}\n",
    )

    agent_a_result = await _call_agent_a(
        dep_files=dep_files,
        includes=includes,
        cpp_files=cpp_files,
        source_root_path=source_root,   # 同机部署时 Agent 直接读本地目录
    )
    if await _is_task_cancelled(task_db_id):
        logger.info("[Agent a] task=%s cancelled while dependency identification was running", task_db_id)
        return {"cancelled": True, "components_found": 0}
    components = agent_a_result.get("components", [])
    if not components and isinstance(agent_a_result.get("agent_a"), dict):
        components = agent_a_result["agent_a"].get("components", [])

    flat_components = _flatten_component_risks(components)
    cve_count = sum(1 for item in flat_components if item.get("cve_id"))
    await _publish_sbom_log(
        task_db_id,
        f"Agent a：识别到 {len(flat_components)} 条组件风险记录，其中 {cve_count} 条已匹配 CVE。",
        f"[Agent a] OSV/NVD query completed: components={len(flat_components)}, cves={cve_count}\n",
    )

    # ── 步骤 3: 写入数据库 ───────────────────────────────────────────────────
    saved_count = await _save_component_risks(task_db_id, flat_components)
    high_risk_count = sum(
        1 for c in flat_components
        if c.get("severity", "").lower() in ("critical", "high")
    )

    result = {
        "components_found": saved_count,
        "high_risk_count": high_risk_count,
        "source_root": source_root,
    }
    logger.info(f"[SBOM] task={task_db_id} 分析完成: {result}")

    # ── 步骤 4: 链式触发 LLM 审计 ───────────────────────────────────────────
    from app.worker.pipeline import trigger_llm_stage
    await trigger_llm_stage(
        task_db_id=task_db_id,
        source_path=source_root,     # 传解压后的目录路径给 LLM 阶段
        is_dynamic=is_dynamic,
    )

    return result
