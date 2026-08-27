"""
组件风险表 (component_risk)
项目依赖的"安检单"：通过比对 NVD/OSV 数据库，记录引入的第三方开源库是否存在已知漏洞。
"""
import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Severity(StrEnum):
    """漏洞危险等级（前端渲染颜色使用）"""
    CRITICAL = "critical"   # 严重（红色）
    HIGH = "high"           # 高危（橙色）
    MEDIUM = "medium"       # 中危（黄色）
    LOW = "low"             # 低危（绿色）
    UNKNOWN = "unknown"     # 未知


class ComponentRisk(Base):
    __tablename__ = "component_risk"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="主键",
    )

    task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("task.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="关联的审计任务 ID",
    )

    library_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="开源库名称，如 OpenSSL",
    )

    version: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="识别出的版本号，如 1.0.1e",
    )

    cve_id: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
        index=True,
        comment="CVE 漏洞编号，如 CVE-2014-0160",
    )

    cvss_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="CVSS 漏洞严重评分（0.0 ~ 10.0）",
    )

    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity_enum"),
        nullable=False,
        default=Severity.UNKNOWN,
        comment="危险等级，前端根据此字段渲染颜色",
    )

    nvd_url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="NVD 漏洞详情页链接",
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="漏洞简述（来自 NVD/OSV）",
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="检测到该风险的时间",
    )

    # ── 关联关系 ───────────────────────────────────────────────────────────────
    task: Mapped["Task"] = relationship(
        "Task",
        back_populates="component_risks",
    )

    def __repr__(self) -> str:
        return (
            f"<ComponentRisk lib={self.library_name} "
            f"cve={self.cve_id} severity={self.severity}>"
        )


# 避免循环导入
from app.models.task import Task  # noqa: E402
