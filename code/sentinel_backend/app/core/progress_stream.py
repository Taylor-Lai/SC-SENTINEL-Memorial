import asyncio
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import redis.asyncio as redis

from app.core.config import settings

logger = logging.getLogger(__name__)

STREAM_TTL_SECONDS = 60 * 60
MAX_STREAM_LENGTH = 1000


def _stream_key(task_id: str) -> str:
    return f"sentinel:progress:{task_id}"


def _client():
    return redis.from_url(settings.REDIS_URL, decode_responses=True)


async def publish_progress(task_id: str, message: dict[str, Any]) -> None:
    """Publish one task progress event to Redis so API and worker processes can share it."""
    key = _stream_key(task_id)
    payload = json.dumps(message, ensure_ascii=False, default=str)
    client = _client()
    try:
        await client.xadd(
            key,
            {"data": payload},
            maxlen=MAX_STREAM_LENGTH,
            approximate=True,
        )
        await client.expire(key, STREAM_TTL_SECONDS)
    except Exception as exc:
        logger.warning("[ProgressStream] failed to publish task=%s: %s", task_id, exc)
    finally:
        await client.aclose()


async def stream_progress(task_id: str, last_id: str = "$") -> AsyncIterator[dict[str, Any]]:
    """Yield progress events for a task from Redis Stream."""
    key = _stream_key(task_id)
    current_id = last_id
    client = _client()
    try:
        while True:
            try:
                rows = await client.xread(
                    {key: current_id},
                    block=30_000,
                    count=20,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("[ProgressStream] failed to read task=%s: %s", task_id, exc)
                await asyncio.sleep(1)
                continue

            for _, events in rows:
                for event_id, fields in events:
                    current_id = event_id
                    raw = fields.get("data")
                    if not raw:
                        continue
                    try:
                        decoded = json.loads(raw)
                    except json.JSONDecodeError:
                        decoded = {"stage": "log", "percent": 0, "message": raw, "log_stream": raw}
                    if isinstance(decoded, dict):
                        yield decoded
    finally:
        await client.aclose()
