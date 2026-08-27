"""
TaskIQ Broker 核心配置
─────────────────────
• Broker  : ListQueueBroker backed by Redis（任务投递 & 消费）
• Backend : RedisAsyncResultBackend（任务结果持久化）
• Middleware: SentinelMiddleware（拦截生命周期事件，写 DB + WS 推送）

使用方式：
    from app.core.broker import broker

在 FastAPI lifespan 中：
    async with broker:
        yield

在 Worker 进程启动时：
    taskiq worker app.core.broker:broker app.worker.*
"""
import logging

from taskiq_redis import ListQueueBroker, RedisAsyncResultBackend

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Result Backend：任务执行结果写入 Redis ──────────────────────────────────────
# result_ex_time=3600 → 结果 TTL 1 小时，防止 Redis 内存无限增长
result_backend = RedisAsyncResultBackend(
    redis_url=settings.REDIS_URL,
    result_ex_time=3600,
)

# ── Broker：基于 Redis List 的队列 Broker ─────────────────────────────────────
# ListQueueBroker 使用 LPUSH/BRPOP 实现可靠队列，适合单机场景
# 生产环境可无缝替换为 taskiq_aio_pika (RabbitMQ) 或 taskiq_nats
broker = ListQueueBroker(
    url=settings.REDIS_URL,
).with_result_backend(result_backend)

# ── 注册 Middleware（在 task 模块导入后再附加，见 main.py）──────────────────────
# Middleware 在 app/worker/middleware.py 中定义，导入顺序敏感，
# 统一在 lifespan 启动前完成注册，避免循环导入。
