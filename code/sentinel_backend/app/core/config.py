from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "SC-SENTINEL"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "面向 C/C++ 开源供应链的 eBPF-LLM 协同漏洞审计系统"
    API_V1_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    SQL_ECHO: bool = False
    AUTO_CREATE_TABLES: bool = True
    CORS_ORIGINS: Annotated[list[str], NoDecode] = [
        "http://localhost:8080",
        "http://127.0.0.1:5400",
    ]

    # Source ingestion limits. These are enforced while streaming and extracting,
    # not merely documented at the API boundary.
    UPLOAD_ROOT: Path = Path("uploads")
    MAX_UPLOAD_BYTES: int = 100 * 1024 * 1024
    MAX_ARCHIVE_FILES: int = 10_000
    MAX_ARCHIVE_UNCOMPRESSED_BYTES: int = 512 * 1024 * 1024
    MAX_ARCHIVE_SINGLE_FILE_BYTES: int = 64 * 1024 * 1024
    MAX_ARCHIVE_COMPRESSION_RATIO: int = 200
    MAX_SOURCE_FILES: int = 20_000
    MAX_SOURCE_BYTES: int = 1024 * 1024 * 1024

    # 数据库异步连接 URL
    # 格式: postgresql+asyncpg://用户名:密码@主机:端口/数据库名
    # 生产环境必须通过 .env 或环境变量覆盖下面的开发占位值。
    DATABASE_URL: str = (
        "postgresql+asyncpg://sentinel_admin:CHANGE_ME@127.0.0.1:5433/sentinel_db"
    )

    # Redis 连接 URL（与 docker-compose.yaml 中 sentinel_redis 保持一致）
    # docker-compose 映射：宿主机 6380 → 容器内 6379
    REDIS_URL: str = "redis://127.0.0.1:6380/0"

    # ── ML 队友的 Agent 接口地址 ───────────────────────────────────────────────
    # Agent a 依赖识别智能体（CVE 查询）接口
    ML_AGENT_A_URL: str = "http://127.0.0.1:18001/api/agent-a/analyze"
    # Agent b/c 假设生成与静态复核智能体接口
    ML_AGENT_B_URL: str = "http://127.0.0.1:18001/api/agent-b/audit"

    # ── Docker 沙箱配置 ────────────────────────────────────────────────────────
    # 沙箱镜像名称(需提前 docker build 构建）
    SANDBOX_IMAGE: str = "sentinel-sandbox:latest"
    # 单次动态验证任务的最大运行时间（秒），超时后强制销毁容器
    # 执行手册：「运行 5 分钟，收集崩溃样本」
    SANDBOX_TIMEOUT_SECONDS: int = 960   # 16 分钟（编译60s + AFL 900s = 15分钟fuzzing）
    # 单个 harness package 的 AFL++ 运行时间。拉长到 900 秒（15分钟）提升crash发现率。
    SANDBOX_PACKAGE_TIMEOUT_SECONDS: int = 900
    # 沙箱容器 CPU 限制（纳秒/100ms，即 nano_cpus；1 核 = 1_000_000_000）
    SANDBOX_CPU_QUOTA: int = 2_000_000_000  # 限制 2 核（提升稳定性）
    # 沙箱容器内存限制（字节），防止 OOM 拖垮宿主机
    SANDBOX_MEM_LIMIT: str = "2g"   # 2 GB（提升稳定性）
    SANDBOX_PIDS_LIMIT: int = 512
    SANDBOX_NETWORK_DISABLED: bool = True
    # Privileged containers materially weaken isolation. Keep this opt-in for
    # dedicated eBPF hosts only; normal fuzzing runs with Docker's default seccomp.
    SANDBOX_ALLOW_PRIVILEGED: bool = False

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


# 全局单例，供其他模块 from app.core.config import settings 调用
settings = Settings()
