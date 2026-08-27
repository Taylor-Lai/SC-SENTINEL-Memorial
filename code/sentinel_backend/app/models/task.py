"""
审计任务主表 (task)
全局调度中心：记录每一次审计任务从上传到出报告的完整生命周期。
"""
import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

# ── 枚举类型 ──────────────────────────────────────────────────────────────────

class SourceType(StrEnum):
    """源码来源"""
    ZIP = "zip"
    GITHUB = "github"


class TaskStatus(StrEnum):
    """任务当前阶段"""
    PENDING = "pending"           # 排队中
    ANALYZING_DEPS = "analyzing_deps"   # 分析依赖中 (SBOM)
    LLM_AUDITING = "llm_auditing"       # 大模型审计中
    FUZZING = "fuzzing"           # Fuzzing / eBPF 动态验证中
    COMPLETED = "completed"       # 已完成
    FAILED = "failed"             # 失败


# ── ORM 模型 ──────────────────────────────────────────────────────────────────

class Task(Base):
    __tablename__ = "task"

    # 主键：UUID，比自增 int 更安全，天然防枚举攻击
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="唯一任务流水号",
    )

    project_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="项目名称，如 Heartbleed-test",
    )

    source_type: Mapped[SourceType] = mapped_column(
        Enum(SourceType, name="source_type_enum"),
        nullable=False,
        comment="源码来源：zip 或 github",
    )

    source_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="源码文件存储路径或 GitHub 仓库地址",
    )

    status: Mapped[TaskStatus] = mapped_column(
        Enum(TaskStatus, name="task_status_enum"),
        nullable=False,
        default=TaskStatus.PENDING,
        comment="任务当前阶段",
    )

    # JSON 字符串存储用户自定义配置，例如 {"vuln_types": ["UAF", "heap_overflow"]}
    target_vulns: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="用户自定义漏洞扫描配置（JSON 字符串）",
    )

    is_dynamic: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="是否开启 eBPF 动态验证（决定是否拉起 Docker 沙箱）",
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="任务失败时的错误原因，供排错使用",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="任务创建时间",
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="任务完成时间（成功或失败时填写）",
    )

    # ── 关联关系 ───────────────────────────────────────────────────────────────
    component_risks: Mapped[list["ComponentRisk"]] = relationship(
        "ComponentRisk",
        back_populates="task",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="task",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Task id={self.id} project={self.project_name} status={self.status}>"


# 避免循环导入，在文件底部引入
from app.models.component_risk import ComponentRisk  # noqa: E402
from app.models.vulnerability import Vulnerability  # noqa: E402
