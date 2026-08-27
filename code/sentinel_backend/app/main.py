"""
SENTINEL — FastAPI 应用入口
面向 C/C++ 开源供应链的 eBPF-LLM 协同漏洞审计系统
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import text
from taskiq_fastapi import init as taskiq_init

# 触发所有模型的注册（让 Base.metadata 感知到所有表）
import app.models  # noqa: F401
from app.core.broker import broker
from app.core.config import settings
from app.core.database import Base, engine

# ── 注册 SentinelMiddleware（必须在 broker 启动前完成注册）─────────────────────
# 导入顺序敏感：先导入 broker，再导入 Middleware，再注册
from app.worker.middleware import SentinelMiddleware  # noqa: E402

broker.add_middlewares(SentinelMiddleware())

# ── 触发所有 Task 函数的注册（让 broker 感知到所有 @broker.task）──────────────
import app.worker.fuzzing_task  # noqa: F401, E402
import app.worker.llm_task  # noqa: F401, E402
import app.worker.pipeline  # noqa: F401, E402
import app.worker.sbom_task  # noqa: F401, E402

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


async def ensure_runtime_enum_values(conn) -> None:
    """Keep existing local Postgres volumes compatible with model enum growth."""
    await conn.execute(text("""
DO $$
DECLARE
    enum_value text;
BEGIN
    FOREACH enum_value IN ARRAY ARRAY['OUT_OF_BOUNDS', 'FORMAT_STRING']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ebpf_event_type_enum')
           AND NOT EXISTS (
               SELECT 1
               FROM pg_enum e
               JOIN pg_type t ON t.oid = e.enumtypid
               WHERE t.typname = 'ebpf_event_type_enum'
                 AND e.enumlabel = enum_value
           )
        THEN
            EXECUTE format('ALTER TYPE ebpf_event_type_enum ADD VALUE %L', enum_value);
        END IF;
    END LOOP;
END $$;
"""))
    await conn.execute(text("""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'verify_status_enum')
       AND NOT EXISTS (
           SELECT 1 FROM pg_enum e
           JOIN pg_type t ON t.oid = e.enumtypid
           WHERE t.typname = 'verify_status_enum'
             AND e.enumlabel = 'NOT_REPRODUCED'
       )
    THEN
        ALTER TYPE verify_status_enum ADD VALUE 'NOT_REPRODUCED';
    END IF;
END $$;
"""))


# ── 生命周期管理 ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    应用启动 / 关闭时的钩子。
    开发阶段：启动时自动建表（等价于 create_all）。
    生产阶段：注释掉 create_all，改用 Alembic 做迁移。
    """
    logger.info("🚀 SENTINEL 启动中，正在连接数据库并初始化表结构...")
    async with engine.begin() as conn:
        await ensure_runtime_enum_values(conn)
        if settings.AUTO_CREATE_TABLES:
            # Development convenience only. Production deployments migrate with Alembic.
            await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ 数据库表结构初始化完毕")

    # ── TaskIQ Broker 启动 ────────────────────────────────────────────────────
    # is_worker_process=False → 当前进程是 FastAPI Server（不是 Worker）
    # 此调用会建立 Broker 与 Redis 的连接，使 FastAPI 可以投递任务
    if not broker.is_worker_process:
        await broker.startup()
        logger.info("✅ TaskIQ Broker 已连接到 Redis，任务队列就绪")

    yield

    # ── TaskIQ Broker 关闭 ────────────────────────────────────────────────────
    if not broker.is_worker_process:
        await broker.shutdown()
        logger.info("🔒 TaskIQ Broker 连接已释放")

    # 关闭时清理连接池
    await engine.dispose()
    logger.info("🔒 数据库连接池已释放，SENTINEL 关闭")


# ── FastAPI 实例 ────────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── taskiq-fastapi：将 FastAPI 依赖注入上下文共享给 Worker 进程 ─────────────────
# 这使得 Worker 中的任务函数可以通过 Depends(get_db) 获取数据库 Session
# 注意：Worker 进程启动时会 import 此 main.py，init_taskiq_deps 会被调用
# taskiq-fastapi v0.5.0: init(broker, app_or_path)
# 在 Worker 进程中运行时，会触发 FastAPI 的 startup 事件，
# 使 Worker 中的任务可以复用 FastAPI 的依赖注入（如 get_db）
taskiq_init(broker, app)

# ── CORS 中间件（前端调试用，生产环境按需收紧）──────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── 健康检查路由 ─────────────────────────────────────────────────────────────────
@app.get("/health/live", tags=["System"])
async def liveness_check():
    """Process-level liveness probe; does not touch external dependencies."""
    return {
        "status": "ok",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
    }


async def _readiness_payload() -> tuple[dict, bool]:
    checks: dict[str, str] = {}
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        logger.error("Readiness database check failed: %s", exc)
        checks["database"] = "unavailable"

    redis = Redis.from_url(settings.REDIS_URL, socket_connect_timeout=2, socket_timeout=2)
    try:
        await redis.ping()
        checks["redis"] = "ok"
    except Exception as exc:
        logger.error("Readiness Redis check failed: %s", exc)
        checks["redis"] = "unavailable"
    finally:
        await redis.aclose()

    ready = all(value == "ok" for value in checks.values())
    return {
        "status": "ok" if ready else "degraded",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "checks": checks,
    }, ready


@app.get("/health/ready", tags=["System"])
async def readiness_check():
    """Dependency-aware readiness probe for traffic and Compose orchestration."""
    payload, ready = await _readiness_payload()
    return JSONResponse(payload, status_code=200 if ready else 503)


@app.get("/health", tags=["System"])
async def health_check():
    """Backward-compatible alias for the dependency-aware readiness probe."""
    return await readiness_check()


# ── API 路由注册 ────────────────────────────────────────────────────────────────
from app.api.v1.router import v1_router  # noqa: E402

app.include_router(v1_router)


if __name__ == "__main__":
    import asyncio
    import platform
    import sys

    import uvicorn

    if platform.system() == "Windows" and sys.version_info < (3, 14):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # 通过 python app/main.py 启动时，开启热重载与指定端口
    uvicorn.run("app.main:app", host="127.0.0.1", port=18000, reload=True)
