import asyncio
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.progress_stream import stream_progress
from app.core.ws_manager import ws_manager

ws_router = APIRouter(prefix="/ws", tags=["WebSocket"])


@ws_router.websocket("/tasks/{task_id}/progress")
async def task_progress_ws(task_id: uuid.UUID, websocket: WebSocket):
    """Stream task progress to the browser.

    Worker processes publish progress into Redis. The API process owns the browser
    WebSocket and forwards those Redis events here.
    """
    task_id_str = str(task_id)
    await ws_manager.connect(task_id_str, websocket)

    await websocket.send_json({
        "stage": "connected",
        "percent": 0,
        "message": f"已连接任务 {task_id_str} 的实时进度流。",
        "log_stream": "",
    })

    async def forward_redis_events() -> None:
        # Replay this task's buffered lifecycle events first.  Connecting with
        # "$" loses the Agent-a start/result logs when the page opens after
        # the worker has already begun the SBOM stage.
        async for event in stream_progress(task_id_str, last_id="0-0"):
            await websocket.send_json(event)

    forward_task = asyncio.create_task(forward_redis_events())
    try:
        while True:
            data = await websocket.receive_text()
            if data.strip().lower() == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        forward_task.cancel()
        try:
            await forward_task
        except asyncio.CancelledError:
            pass
        ws_manager.disconnect(task_id_str, websocket)
