import logging

from fastapi import WebSocket

from app.core.progress_stream import publish_progress

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manage local WebSocket clients and publish progress events cross-process."""

    def __init__(self) -> None:
        self.active: dict[str, list[WebSocket]] = {}

    async def connect(self, task_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.setdefault(task_id, []).append(websocket)
        logger.info("[WS] client connected task=%s count=%s", task_id, len(self.active[task_id]))

    def disconnect(self, task_id: str, websocket: WebSocket) -> None:
        if task_id in self.active:
            try:
                self.active[task_id].remove(websocket)
            except ValueError:
                pass
            if not self.active[task_id]:
                del self.active[task_id]
        logger.info("[WS] client disconnected task=%s", task_id)

    async def broadcast(self, task_id: str, message: dict) -> None:
        await publish_progress(task_id, message)

    async def send_local(self, task_id: str, message: dict) -> None:
        if task_id not in self.active:
            return

        dead: list[WebSocket] = []
        for ws in list(self.active[task_id]):
            try:
                await ws.send_json(message)
            except Exception as exc:
                logger.warning("[WS] failed to push local message task=%s: %s", task_id, exc)
                dead.append(ws)

        for ws in dead:
            self.disconnect(task_id, ws)

    def get_connection_count(self, task_id: str) -> int:
        return len(self.active.get(task_id, []))


ws_manager = ConnectionManager()
