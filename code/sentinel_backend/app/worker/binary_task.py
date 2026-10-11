"""Static ELF/PE audit stage. Uploaded binaries are never executed."""
import asyncio
import json
import logging
import uuid
from pathlib import Path

from sqlalchemy import select

from app.core.broker import broker
from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager
from app.models.task import Task
from app.services.binary_analyzer import analyze_binary
from app.worker.llm_task import _save_vulnerabilities
from app.worker.pipeline import _is_task_cancelled, finalize_static_task

logger = logging.getLogger(__name__)


@broker.task(task_name="binary_audit", max_retries=1, retry_on_error=True)
async def run_binary_audit(task_db_id: str, source_path: str) -> dict:
    if await _is_task_cancelled(task_db_id):
        return {"cancelled": True}
    async with AsyncSessionLocal() as session:
        task = (await session.execute(select(Task).where(Task.id == uuid.UUID(task_db_id)))).scalar_one()
        targets = json.loads(task.target_vulns or "[]")
    result = await asyncio.to_thread(analyze_binary, source_path, targets)
    if await _is_task_cancelled(task_db_id):
        return {"cancelled": True}
    await ws_manager.broadcast(task_db_id, {
        "stage": "binary",
        "percent": 70,
        "message": "二进制画像完成，正在整理静态风险候选…",
        "log_stream": f"[Binary] {len(result['libraries'])} libraries, {len(result['named_functions'])} named functions, {len(result['external_input_apis'])} input APIs.\n",
    })
    saved = await _save_vulnerabilities(task_db_id, result["findings"])
    analysis_path = Path(source_path).parent / "binary_analysis.json"
    temporary_path = analysis_path.with_suffix(".tmp")
    temporary_path.write_text(json.dumps({
        "format": result["metadata"]["format"],
        "bits": result["metadata"]["bits"],
        "kind": result["metadata"]["kind"],
        "libraries": result["libraries"],
        "named_functions": result["named_functions"],
        "external_input_apis": result["external_input_apis"],
        "call_sites": result["call_sites"],
        "disassembly_truncated": result["disassembly_truncated"],
        "disassembly_error": result["disassembly_error"],
    }, ensure_ascii=False), encoding="utf-8")
    temporary_path.replace(analysis_path)
    logger.info("[Binary] task=%s format=%s libraries=%s candidates=%s", task_db_id,
                result["metadata"]["format"], len(result["libraries"]), len(saved["vuln_ids"]))
    await finalize_static_task(task_db_id)
    return {"vulns_found": len(saved["vuln_ids"]), "format": result["metadata"]["format"]}
