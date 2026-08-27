import asyncio
import platform
import sys
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

# 解决 Windows 下 ProactorEventLoop 导致 asyncpg 关闭连接的 Bug
if platform.system() == "Windows" and sys.version_info < (3, 14):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from app.core.config import settings

# ──────────────────────────────────────────────
# 1. 全异步数据库引擎
#    echo=True → 在终端打印执行的 SQL，调试极度友好
#    pool_pre_ping=True → 每次取连接前先 ping 一下，避免"僵尸连接"
# ──────────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.SQL_ECHO,
    pool_pre_ping=True,
)

# ──────────────────────────────────────────────
# 2. 异步 Session 工厂
#    expire_on_commit=False → commit 后对象属性不会被立即过期，
#    避免在异步场景下访问已关闭 Session 的属性时出现懒加载错误
# ──────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ──────────────────────────────────────────────
# 3. 所有 ORM 模型的基类
#    所有 models/*.py 里的表都必须继承 Base
# ──────────────────────────────────────────────
Base = declarative_base()


# ──────────────────────────────────────────────
# 4. FastAPI 依赖注入函数
#    在路由函数里 Depends(get_db) 即可拿到一个独立的 Session，
#    请求结束后自动关闭，异常时自动回滚
# ──────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
