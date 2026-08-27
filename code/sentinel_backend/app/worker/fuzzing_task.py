import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.core.broker import broker
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.ws_manager import ws_manager

logger = logging.getLogger(__name__)


def _event_timestamp(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


async def _save_fuzzing_results(task_db_id: str, sandbox_result) -> None:
    from sqlalchemy import select

    from app.models.ebpf_event_log import EbpfEventLog, EbpfEventType
    from app.models.vulnerability import VerifyStatus, Vulnerability

    strong_ebpf_to_vuln_type = {
        "double_free": "double_free",
        "use_after_free": "use_after_free",
        "heap_overflow": "buffer_overflow",
        "stack_overflow": "buffer_overflow",
    }
    weak_ebpf_events = {
        "double_free_suspected",
        "use_after_free_suspected",
        "heap_overflow_suspected",
        "stack_write_suspected",
        "possible_buffer_overflow",
        "format_string_suspected",
    }
    # Weak sink-reachability events are recorded, but they are not proof of a
    # concrete heap/stack overflow.
    ebpf_type_map = {
        "double_free": EbpfEventType.DOUBLE_FREE,
        "double_free_suspected": EbpfEventType.DOUBLE_FREE,
        "use_after_free": EbpfEventType.USE_AFTER_FREE,
        "use_after_free_suspected": EbpfEventType.USE_AFTER_FREE,
        "heap_overflow": EbpfEventType.HEAP_OVERFLOW,
        "heap_overflow_suspected": EbpfEventType.OUT_OF_BOUNDS,
        "stack_overflow": EbpfEventType.STACK_OVERFLOW,
        "stack_write_suspected": EbpfEventType.OUT_OF_BOUNDS,
        "possible_buffer_overflow": EbpfEventType.OUT_OF_BOUNDS,
        "format_string_suspected": EbpfEventType.FORMAT_STRING,
        "null_deref": EbpfEventType.NULL_DEREF,
        "out_of_bounds": EbpfEventType.OUT_OF_BOUNDS,
    }

    package_results = list(getattr(sandbox_result, "package_results", []) or [])

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Vulnerability).where(Vulnerability.task_id == uuid.UUID(task_db_id))
        )
        vulns = result.scalars().all()
        vulns_by_id = {str(v.id): v for v in vulns}

        if package_results:
            for package_result in package_results:
                vuln = vulns_by_id.get(str(package_result.get("vuln_id") or ""))
                if not vuln:
                    continue

                crash_found = bool(package_result.get("crash_found"))
                error = package_result.get("error")
                vuln_type_lower = vuln.vuln_type.lower() if vuln.vuln_type else ""

                ebpf_events = list(package_result.get("ebpf_events") or [])

                # Correct the static category only when strong runtime evidence
                # demonstrates a different concrete vulnerability type.
                strong_detected_types = set()
                weak_event_names = set()
                for evt in ebpf_events:
                    event_name = evt.get("event") or evt.get("event_type") or ""
                    if event_name in strong_ebpf_to_vuln_type:
                        strong_detected_types.add(strong_ebpf_to_vuln_type[event_name])
                    elif event_name in weak_ebpf_events:
                        weak_event_names.add(event_name)

                if strong_detected_types:
                    ebpf_primary_type = sorted(strong_detected_types)[0]
                    if ebpf_primary_type != vuln_type_lower and vuln_type_lower not in strong_detected_types:
                        vuln.llm_original_type = vuln.vuln_type
                        vuln.vuln_type = ebpf_primary_type
                        vuln.ebpf_corrected = True
                        logger.info(
                            "[eBPF Correction] vuln=%s corrected %s -> %s based on strong events: %s",
                            vuln.id,
                            vuln.llm_original_type,
                            ebpf_primary_type,
                            sorted(strong_detected_types),
                        )

                if crash_found:
                    vuln.verify_status = VerifyStatus.CONFIRMED
                elif vuln_type_lower in strong_detected_types:
                    vuln.verify_status = VerifyStatus.CONFIRMED
                    logger.info(
                        "[eBPF Confirmation] vuln=%s confirmed by strong eBPF events: %s",
                        vuln.id,
                        sorted(strong_detected_types),
                    )
                elif strong_detected_types:
                    vuln.verify_status = VerifyStatus.UNVERIFIED
                elif weak_event_names:
                    vuln.verify_status = VerifyStatus.UNVERIFIED
                    logger.info(
                        "[eBPF Weak Evidence] vuln=%s left unverified; weak events only: %s",
                        vuln.id,
                        sorted(weak_event_names),
                    )
                elif error:
                    vuln.verify_status = VerifyStatus.UNVERIFIED
                else:
                    # A bounded fuzzing budget cannot prove the absence of a
                    # vulnerability. Keep this distinct from a dismissed finding.
                    vuln.verify_status = VerifyStatus.NOT_REPRODUCED

                # Aggregate bounded runtime evidence for the final report.
                log_parts = []
                if package_result.get("package_id"):
                    log_parts.append(f"[SENTINEL] harness={package_result['package_id']}")
                if error:
                    log_parts.append(f"[SENTINEL] error={error}")
                if package_result.get("afl_crash_log"):
                    log_parts.append(package_result["afl_crash_log"])
                elif package_result.get("afl_log"):
                    log_parts.append(package_result["afl_log"])
                if package_result.get("runtime_evidence_log"):
                    log_parts.append("[SENTINEL] runtime evidence:\n" + package_result["runtime_evidence_log"])
                vuln.afl_log = "\n".join(log_parts)[:5000] if log_parts else None

                # Persist structured eBPF/runtime probe events.
                for evt in ebpf_events[:100]:
                    event_name = evt.get("event") or evt.get("event_type") or "other"
                    session.add(EbpfEventLog(
                        vuln_id=vuln.id,
                        timestamp=_event_timestamp(evt.get("ts") or evt.get("timestamp")),
                        event_type=ebpf_type_map.get(event_name, EbpfEventType.OTHER),
                        function_name=evt.get("fn") or evt.get("function"),
                        memory_addr=evt.get("addr") or evt.get("address"),
                        raw_data=str(evt),
                    ))
        else:
            # Compatibility path for the legacy single-target sandbox.
            for vuln in vulns:
                if sandbox_result.crash_found:
                    vuln.verify_status = VerifyStatus.CONFIRMED
                    vuln.afl_log = sandbox_result.afl_crash_log[:5000]
                elif sandbox_result.error:
                    vuln.verify_status = VerifyStatus.UNVERIFIED
                    vuln.afl_log = sandbox_result.error[:5000]
                else:
                    vuln.verify_status = VerifyStatus.NOT_REPRODUCED

        await session.commit()
        logger.info(
            "[Fuzzing] task=%s saved dynamic results: vulns=%s package_results=%s ebpf=%s",
            task_db_id,
            len(vulns),
            len(package_results),
            len(getattr(sandbox_result, "ebpf_events", []) or []),
        )

@broker.task(
    task_name="dynamic_fuzzing",
    max_retries=0,
    retry_on_error=False,
)
async def run_dynamic_fuzzing(
    task_db_id: str,
    source_path: str,
    harness_bundle_root: str | None = None,
) -> dict:
    from app.models.task import Task, TaskStatus
    from app.services.sandbox_manager import SandboxResult, run_sandbox_verification
    from app.worker.pipeline import _is_task_cancelled

    if await _is_task_cancelled(task_db_id):
        return {"cancelled": True, "crash_found": False}

    logger.info(
        "[Fuzzing] Starting dynamic verification task=%s source=%s harness=%s",
        task_db_id,
        source_path,
        harness_bundle_root,
    )

    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": "fuzzing",
            "percent": 70,
            "message": "正在启动 AFL++ 并加载 Harness...",
            "log_stream": "[FUZZING] Starting dynamic verification...\n",
        },
    )

    # Emit heartbeat progress while the blocking sandbox run is active.
    async def progress_heartbeat():
        progress_messages = [
            "[FUZZING] AFL++ initializing corpus...\n",
            "[FUZZING] eBPF uprobe monitoring active...\n",
            "[FUZZING] Mutation engine running...\n",
            "[FUZZING] Collecting coverage feedback...\n",
            "[FUZZING] Exploring new paths...\n",
        ]
        msg_idx = 0
        while True:
            await asyncio.sleep(5)
            if msg_idx < len(progress_messages):
                await ws_manager.broadcast(
                    task_db_id,
                    {
                        "stage": "fuzzing",
                        "percent": 70 + msg_idx * 5,
                        "message": "AFL++ fuzzing in progress...",
                        "log_stream": progress_messages[msg_idx],
                    },
                )
                msg_idx += 1

    heartbeat_task = asyncio.create_task(progress_heartbeat())

    sandbox_result: SandboxResult = SandboxResult()
    try:
        sandbox_result = await asyncio.wait_for(
            asyncio.to_thread(
                run_sandbox_verification,
                task_db_id=task_db_id,
                source_path=source_path,
                harness_bundle_root=harness_bundle_root,
                sandbox_image=settings.SANDBOX_IMAGE,
                timeout_secs=settings.SANDBOX_TIMEOUT_SECONDS,
                cpu_quota=settings.SANDBOX_CPU_QUOTA,
                mem_limit=settings.SANDBOX_MEM_LIMIT,
                package_timeout_secs=settings.SANDBOX_PACKAGE_TIMEOUT_SECONDS,
                allow_privileged=settings.SANDBOX_ALLOW_PRIVILEGED,
                network_disabled=settings.SANDBOX_NETWORK_DISABLED,
                pids_limit=settings.SANDBOX_PIDS_LIMIT,
            ),
            timeout=settings.SANDBOX_TIMEOUT_SECONDS + 60,
        )
    except TimeoutError:
        from app.services.sandbox_manager import force_kill_container

        sandbox_result.timed_out = True
        sandbox_result.error = f"Sandbox verification timed out after {settings.SANDBOX_TIMEOUT_SECONDS}s"
        logger.error("[Fuzzing] task=%s timed out", task_db_id)
        await asyncio.to_thread(force_kill_container, task_db_id)
    except Exception as exc:
        sandbox_result.error = str(exc)
        logger.error("[Fuzzing] task=%s failed: %s", task_db_id, exc, exc_info=True)
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass

    try:
        await _save_fuzzing_results(task_db_id, sandbox_result)
    except Exception as exc:
        logger.error("[Fuzzing] task=%s failed to save results: %s", task_db_id, exc, exc_info=True)
        raise RuntimeError("failed to persist dynamic verification results") from exc

    # Give the fifth agent an explicit, ordered checkpoint. Previously the
    # task was marked completed only around the fuzzing event, so a late 90%
    # update could overwrite the UI after dynamic verification had finished.
    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": "report",
            "percent": 98,
            "message": "Agent e：正在汇总动态证据并准备审计报告。",
            "log_stream": "[Agent e] Aggregating static findings, SBOM and runtime evidence.\n",
        },
    )

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Task).where(Task.id == uuid.UUID(task_db_id)))
        task = result.scalar_one_or_none()
        if task and task.status not in (TaskStatus.FAILED, TaskStatus.COMPLETED):
            task.status = TaskStatus.COMPLETED
            if sandbox_result.error:
                task.error_message = (
                    f"[fuzzing] dynamic verification incomplete: {sandbox_result.error}"
                )[:1000]
            task.completed_at = datetime.now(UTC)
            await session.commit()

    package_results = list(getattr(sandbox_result, "package_results", []) or [])
    confirmed = sum(1 for item in package_results if item.get("crash_found"))
    errored = sum(1 for item in package_results if item.get("error"))

    if sandbox_result.error and not sandbox_result.crash_found:
        final_msg = f"动态验证结束，但出现错误：{sandbox_result.error[:160]}"
    elif package_results:
        final_msg = (
            f"动态验证完成：{len(package_results)} 个 Harness 包中有 {confirmed} 个复现异常，"
            f"{errored} 个包执行出错。"
        )
    elif sandbox_result.crash_found:
        final_msg = "动态验证完成：隔离沙箱捕获到异常退出。"
    else:
        final_msg = f"动态验证在 {sandbox_result.elapsed_seconds:.1f} 秒内完成，未触发异常退出。"

    await ws_manager.broadcast(
        task_db_id,
        {
            "stage": "done",
            "percent": 100,
            "message": final_msg,
            "log_stream": sandbox_result.afl_crash_log[:2000],
        },
    )

    return {
        "crash_found": sandbox_result.crash_found,
        "package_results": len(package_results),
        "confirmed_package_results": confirmed,
        "ebpf_events": len(getattr(sandbox_result, "ebpf_events", []) or []),
        "elapsed_seconds": sandbox_result.elapsed_seconds,
        "timed_out": sandbox_result.timed_out,
        "error": sandbox_result.error,
        "dynamic_incomplete": bool(sandbox_result.error),
    }
