"""
models 包的公共入口
统一导出所有 ORM 模型，方便 Alembic 自动发现表结构。
"""

# 必须先导入 Base，再导入所有模型，Alembic 才能通过 Base.metadata 感知所有表
from app.core.database import Base  # noqa: F401
from app.models.component_risk import ComponentRisk  # noqa: F401
from app.models.ebpf_event_log import EbpfEventLog  # noqa: F401
from app.models.task import Task  # noqa: F401
from app.models.vulnerability import Vulnerability  # noqa: F401

__all__ = [
    "Base",
    "Task",
    "ComponentRisk",
    "Vulnerability",
    "EbpfEventLog",
]
