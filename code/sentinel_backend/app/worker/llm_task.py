import asyncio
import base64
import json
import logging
import uuid
from pathlib import Path

import httpx
from sqlalchemy import delete

from app.core.broker import broker
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager
from app.models.vulnerability import VerifyStatus, Vulnerability

logger = logging.getLogger(__name__)

_SUPPORTED_TARGETS = {
    "buffer-overflow",
    "heap-overflow",
    "stack-overflow",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "possible-buffer-overflow",
    "use-after-free",
    "uaf",
    "double-free",
    "cwe-120",
    "cwe-121",
    "cwe-122",
    "cwe-415",
    "cwe-416",
}


def _resolve_path(value: str) -> str:
    return str(Path(value).resolve())


def _is_absolute(value: str) -> bool:
    return Path(value).is_absolute()


def _is_file(value: str) -> bool:
    return Path(value).is_file()


def _discover_cpp_files(source_path: str, extensions: set[str]) -> list[str] | None:
    source_root = Path(source_path)
    if not source_root.is_dir():
        return None
    return [
        str(file_path.relative_to(source_root))
        for file_path in source_root.rglob("*")
        if file_path.is_file() and file_path.suffix.lower() in extensions
    ]


async def _call_agent_b(
    source_root: str,
    cpp_files: list[str],
    target_vulns: list[str] | None = None,
    dependency_components: list[dict] | None = None,
) -> dict:
    request_body = {
        "source_root": source_root,
        "cpp_files": cpp_files,
        "target_vulns": target_vulns or [],
        "generate_harness": True,
        "dependency_components": dependency_components or [],
    }

    logger.info("[Agent b/c] calling hypothesis and static-review endpoint: %s", settings.ML_AGENT_B_URL)
    try:
        async with httpx.AsyncClient(timeout=900.0) as client:
            resp = await client.post(settings.ML_AGENT_B_URL, json=request_body)
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        logger.error("[Agent b/c] service call timed out")
        raise
    except httpx.HTTPStatusError as exc:
        logger.error(
            "[Agent b/c] service returned HTTP %s: %s",
            exc.response.status_code,
            exc.response.text[:500],
        )
        raise
    except Exception as exc:
        logger.error(f"[Agent b/c] service call failed: {exc}", exc_info=True)
        raise


def _normalize_target(value: str) -> str:
    return str(value or "").strip().lower().replace("_", "-").replace(" ", "-")


def _parse_target_vulns(raw: str) -> list[str]:
    if not raw:
        return []

    parsed_items: list[str] = []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            parsed_items = [str(item) for item in parsed]
        elif isinstance(parsed, str):
            parsed_items = [parsed]
    except Exception:
        stripped = raw.strip().strip("[]")
        parsed_items = [
            item.strip().strip("'\"")
            for item in stripped.split(",")
            if item.strip().strip("'\"")
        ]
        logger.warning(
            "[LLM] target_vulns_json was not strict JSON, parsed permissively: %r -> %s",
            raw,
            parsed_items,
        )

    valid_items = [
        item for item in parsed_items
        if _normalize_target(item) in _SUPPORTED_TARGETS
    ]
    if parsed_items and not valid_items:
        logger.warning(
            "[LLM] ignoring invalid target_vulns=%s; auditing all supported vulnerability types",
            parsed_items,
        )
    return valid_items


async def _load_dependency_context(task_db_id: str) -> list[dict]:
    """Load the already persisted Agent a result instead of scanning CVEs twice."""
    from sqlalchemy import select

    from app.models.component_risk import ComponentRisk

    async with AsyncSessionLocal() as session:
        rows = await session.execute(
            select(ComponentRisk).where(ComponentRisk.task_id == uuid.UUID(task_db_id))
        )
        return [
            {
                "library_name": item.library_name,
                "version": item.version,
                "cve_id": item.cve_id,
                "cvss_score": item.cvss_score,
                "severity": item.severity.value,
                "description": item.description,
                "nvd_url": item.nvd_url,
            }
            for item in rows.scalars().all()
        ]


async def _broadcast_llm_progress(
    task_db_id: str,
    message: str,
    log_stream: str,
    percent: int = 60,
) -> None:
    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": "llm",
            "percent": percent,
            "message": message,
            "log_stream": log_stream,
        },
    )


async def _save_vulnerabilities(task_db_id: str, vulns: list[dict]) -> dict:
    """
    Persist backend vulnerability rows and keep Agent finding_id attribution.
    """
    async with AsyncSessionLocal() as session:
        # Replace static findings atomically; retries must not duplicate rows.
        await session.execute(
            delete(Vulnerability).where(Vulnerability.task_id == uuid.UUID(task_db_id))
        )
        if not vulns:
            await session.commit()
            logger.info(f"[Agent c] task={task_db_id} returned no candidate findings")
            return {"vuln_ids": [], "finding_id_to_vuln_id": {}}
        records = []
        finding_id_to_record = {}

        for item in vulns:
            record = Vulnerability(
                task_id=uuid.UUID(task_db_id),
                vuln_type=item.get("vuln_type", "Unknown"),
                file_path=item.get("file_path"),
                line_number=item.get("line_number"),
                code_context=item.get("code_context"),
                trigger_cond=item.get("trigger_cond"),
                fix_advice=item.get("fix_advice"),
                verify_status=VerifyStatus.UNVERIFIED,
            )
            records.append(record)
            finding_id = item.get("finding_id")
            if finding_id:
                finding_id_to_record[str(finding_id)] = record

        session.add_all(records)
        await session.flush()

        vuln_ids = [str(record.id) for record in records]
        finding_id_to_vuln_id = {
            finding_id: str(record.id)
            for finding_id, record in finding_id_to_record.items()
        }
        await session.commit()

    logger.info(f"[LLM] task={task_db_id} saved {len(vuln_ids)} vulnerabilities")
    return {"vuln_ids": vuln_ids, "finding_id_to_vuln_id": finding_id_to_vuln_id}


def _persist_harness_bundles(
    task_db_id: str,
    agent_b_result: dict,
    finding_id_to_vuln_id: dict[str, str],
) -> str | None:
    """
    Materialize Agent d validation artifacts into backend-owned storage.

    Agent service package paths are not portable across containers. The agent
    embeds file contents in the response; the worker recreates those packages
    under uploads/harness_bundles so the sandbox can mount and execute them.
    """
    packages = (agent_b_result.get("agent_e") or {}).get("harness_packages", [])
    if not packages:
        logger.info(f"[LLM] task={task_db_id} no harness packages returned")
        return None

    bundle_root = Path("uploads") / "harness_bundles" / task_db_id
    bundle_root.mkdir(parents=True, exist_ok=True)

    manifest_packages = []
    for idx, package in enumerate(packages, start=1):
        package_id = str(package.get("package_id") or f"HARNESS-{idx:04d}")
        package_dir = bundle_root / package_id
        seeds_dir = package_dir / "seeds"
        findings_dir = package_dir / "findings"
        seeds_dir.mkdir(parents=True, exist_ok=True)
        findings_dir.mkdir(parents=True, exist_ok=True)

        for name, content in (package.get("embedded_files") or {}).items():
            (package_dir / Path(name).name).write_text(str(content), encoding="utf-8")

        for name, content_b64 in (package.get("embedded_seed_files_b64") or {}).items():
            try:
                payload = base64.b64decode(content_b64)
            except Exception:
                payload = b"default_seed"
            (seeds_dir / Path(name).name).write_bytes(payload)

        harness_config = package_dir / "harness_config.json"
        if not harness_config.exists():
            harness_config.write_text(
                json.dumps(package, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

        finding_id = str(package.get("finding_id") or "")
        manifest_packages.append({
            "package_id": package_id,
            "finding_id": finding_id,
            "vuln_id": finding_id_to_vuln_id.get(finding_id),
            "cwe_id": package.get("cwe_id"),
            "target_file": package.get("target_file"),
            "target_function": package.get("target_function"),
            "package_dir": str(package_dir.resolve()),
        })

    manifest = {
        "task_id": task_db_id,
        "bundle_root": str(bundle_root.resolve()),
        "packages": manifest_packages,
    }
    (bundle_root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    logger.info(
        "[LLM] task=%s materialized %s harness packages at %s",
        task_db_id,
        len(manifest_packages),
        bundle_root,
    )
    return str(bundle_root.resolve())


@broker.task(
    task_name="llm_audit",
    max_retries=1,
    retry_on_error=True,
)
async def run_llm_audit(
    task_db_id: str,
    source_path: str,
    is_dynamic: bool = False,
    target_vulns_json: str = "",
) -> dict:
    logger.info(f"[LLM] Starting audit task={task_db_id}, source={source_path}")
    from app.worker.pipeline import _is_task_cancelled

    if await _is_task_cancelled(task_db_id):
        return {"cancelled": True, "vulns_found": 0}

    # GitHub URL 应当已经在 SBOM 阶段被克隆到本地目录再传过来；
    # 走到这里如果 source_path 仍然是 URL，说明上游 clone 失败，直接停下来更清楚。
    if source_path and source_path.lower().startswith(("http://", "https://", "git@", "ssh://")):
        raise ValueError(
            f"LLM 阶段收到未克隆的远程仓库 URL: {source_path}；"
            "请检查 SBOM 阶段的 git clone 是否正确执行。"
        )

    if not _is_absolute(source_path):
        source_path = _resolve_path(source_path)

    if source_path.endswith(".zip") and _is_file(source_path):
        from app.services.source_parser import parse_zip_source

        ctx = await asyncio.to_thread(parse_zip_source, source_path)
        source_path = ctx.source_root

    cpp_extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}
    discovered = await asyncio.to_thread(_discover_cpp_files, source_path, cpp_extensions)
    cpp_files: list[str] = discovered or []
    if discovered is not None:
        logger.info(f"[LLM] task={task_db_id} found {len(cpp_files)} C/C++ files")
        await _broadcast_llm_progress(
            task_db_id,
            "Agent b：已完成源码切片，正在生成漏洞假设。",
            f"[Agent b] Found {len(cpp_files)} C/C++ source files for hypothesis generation.\n",
            percent=40,
        )
    else:
        logger.warning(f"[LLM] source_path is not a directory: {source_path}")

    target_vulns = _parse_target_vulns(target_vulns_json)
    await _broadcast_llm_progress(
        task_db_id,
        "Agent b：正在结合目标类型与依赖上下文生成候选假设。",
        f"[Agent b] Target vulnerability filter: {target_vulns or 'all'}.\n"
        "[Agent b] Calling hypothesis and static-review service.\n",
        percent=45,
    )

    dependency_components = await _load_dependency_context(task_db_id)
    agent_b_result = await _call_agent_b(
        source_path,
        cpp_files,
        target_vulns,
        dependency_components,
    )
    if await _is_task_cancelled(task_db_id):
        logger.info("[LLM] task=%s cancelled while Agent service was running", task_db_id)
        return {"cancelled": True, "vulns_found": 0}
    vulns = agent_b_result.get("vulnerabilities", [])
    await _broadcast_llm_progress(
        task_db_id,
        "Agent c：正在复核候选发现的边界条件、数据流与可达路径。",
        f"[Agent c] Static review returned {len(vulns)} candidate findings.\n",
        percent=55,
    )

    saved = await _save_vulnerabilities(task_db_id, vulns)
    harness_bundle_root = _persist_harness_bundles(
        task_db_id=task_db_id,
        agent_b_result=agent_b_result,
        finding_id_to_vuln_id=saved["finding_id_to_vuln_id"],
    )
    await _broadcast_llm_progress(
        task_db_id,
        "Agent c：静态复核完成，验证工件已就绪。",
        "[Agent c] Findings persisted; harness packages prepared for Agent d.\n",
        percent=65,
    )

    result = {
        "vulns_found": len(saved["vuln_ids"]),
        "vuln_ids": saved["vuln_ids"],
        "harness_bundle_root": harness_bundle_root,
    }
    logger.info(f"[LLM] task={task_db_id} audit completed: {result}")

    if is_dynamic:
        from app.worker.pipeline import trigger_fuzzing_stage

        await trigger_fuzzing_stage(
            task_db_id=task_db_id,
            source_path=source_path,
            harness_bundle_root=harness_bundle_root,
        )
    else:
        from app.worker.pipeline import finalize_task_no_fuzzing

        await finalize_task_no_fuzzing.kiq(task_db_id)

    return result
