"""
Alembic 环境配置 — 异步版本
支持 asyncpg 驱动的全异步迁移，同时保留 offline 模式。
"""
import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# ── 读取 alembic.ini 配置 ───────────────────────────────────────────────────
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── 注入项目配置：用 settings 里的 URL 覆盖 alembic.ini 里的占位符 ──────────
from app.core.config import settings  # noqa: E402

config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# ── 导入所有模型，让 autogenerate 能感知到全部表结构 ───────────────────────────
import app.models  # noqa: F401, E402
from app.core.database import Base  # noqa: E402

target_metadata = Base.metadata


# ── Offline 模式（生成 SQL 脚本，不需要实际连接数据库）────────────────────────
def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # compare_type=True 让 Alembic 检测字段类型变更
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ── Online 模式（真正连接数据库执行迁移）────────────────────────────────────
def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """使用异步引擎建立连接，然后同步执行迁移逻辑。"""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


# ── 入口判断 ─────────────────────────────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
