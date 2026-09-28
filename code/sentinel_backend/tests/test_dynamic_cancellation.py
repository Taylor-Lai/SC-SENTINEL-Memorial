from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.models.task import TaskStatus
from app.worker.fuzzing_task import _monitor_dynamic_verification
from app.worker.middleware import _update_task_db
from app.worker.pipeline import finalize_task_no_fuzzing


@pytest.mark.asyncio
async def test_worker_cleans_sandbox_when_persisted_task_is_cancelled(monkeypatch):
    cancelled = AsyncMock(side_effect=[False, True])
    killed = Mock(return_value=True)
    broadcast = AsyncMock()
    monkeypatch.setattr("app.worker.pipeline._is_task_cancelled", cancelled)
    monkeypatch.setattr("app.services.sandbox_manager.force_kill_container", killed)
    monkeypatch.setattr("app.worker.fuzzing_task.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("app.worker.fuzzing_task.ws_manager.broadcast", broadcast)

    await _monitor_dynamic_verification("task-id")

    killed.assert_called_once_with("task-id")
    broadcast.assert_awaited_once()
    message = broadcast.call_args.args[1]
    assert message["percent"] == 70
    assert "no new evidence" in message["log_stream"]
    assert "eBPF" not in message["log_stream"]


@pytest.mark.asyncio
async def test_cancelled_task_emits_no_more_fuzzing_progress(monkeypatch):
    killed = Mock(return_value=False)
    broadcast = AsyncMock()
    monkeypatch.setattr("app.worker.pipeline._is_task_cancelled", AsyncMock(return_value=True))
    monkeypatch.setattr("app.services.sandbox_manager.force_kill_container", killed)
    monkeypatch.setattr("app.worker.fuzzing_task.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("app.worker.fuzzing_task.ws_manager.broadcast", broadcast)

    await _monitor_dynamic_verification("task-id")

    killed.assert_called_once_with("task-id")
    broadcast.assert_not_awaited()


@pytest.mark.asyncio
async def test_static_finalizer_does_not_report_cancelled_task_as_done(monkeypatch):
    result = Mock()
    result.scalar_one_or_none.return_value = SimpleNamespace(status=TaskStatus.FAILED)
    session = SimpleNamespace(execute=AsyncMock(return_value=result), commit=AsyncMock())

    @asynccontextmanager
    async def fake_session():
        yield session

    broadcast = AsyncMock()
    monkeypatch.setattr("app.worker.pipeline.AsyncSessionLocal", fake_session)
    monkeypatch.setattr("app.worker.pipeline.ws_manager.broadcast", broadcast)

    await finalize_task_no_fuzzing("00000000-0000-0000-0000-000000000001")

    session.commit.assert_not_awaited()
    assert all(call.args[1]["stage"] != "done" for call in broadcast.call_args_list)


@pytest.mark.asyncio
async def test_stage_failure_does_not_overwrite_a_cancelled_terminal_task(monkeypatch):
    task = SimpleNamespace(status=TaskStatus.FAILED, error_message="user cancelled")
    result = Mock()
    result.scalar_one_or_none.return_value = task
    session = SimpleNamespace(execute=AsyncMock(return_value=result), commit=AsyncMock())

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr("app.worker.middleware.AsyncSessionLocal", fake_session)
    updated = await _update_task_db(
        "00000000-0000-0000-0000-000000000001",
        TaskStatus.FAILED, error_message="late sandbox error", mark_complete=True,
    )

    assert updated is False
    assert task.error_message == "user cancelled"
    session.commit.assert_not_awaited()
    assert "FOR UPDATE" in str(session.execute.call_args.args[0])
