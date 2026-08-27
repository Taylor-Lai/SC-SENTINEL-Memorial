"""
内核级内存事件表 (ebpf_event_log)
动态验证的"铁证记录"：存放 eBPF 从内核抓取的内存非法操作行为。
"""
import uuid
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Enum,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class EbpfEventType(StrEnum):
    """eBPF 捕获的内核事件类型"""
    DOUBLE_FREE = "double_free"           # Double Free
    HEAP_OVERFLOW = "heap_overflow"       # 堆溢出
    USE_AFTER_FREE = "use_after_free"     # UAF
    NULL_DEREF = "null_deref"             # 空指针解引用
    STACK_OVERFLOW = "stack_overflow"     # 栈溢出
    OUT_OF_BOUNDS = "out_of_bounds"       # 内存越界读写
    FORMAT_STRING = "format_string"       # CWE-134 格式化字符串 sink 触达
    OTHER = "other"                       # 其他异常


class EbpfEventLog(Base):
    __tablename__ = "ebpf_event_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="主键",
    )

    vuln_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerability.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="关联到具体漏洞的 ID",
    )

    # 使用 BigInteger 存纳秒级时间戳，保留内核精度
    timestamp: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        comment="内核事件精确时间戳（纳秒级 Unix 时间戳）",
    )

    event_type: Mapped[EbpfEventType] = mapped_column(
        Enum(EbpfEventType, name="ebpf_event_type_enum"),
        nullable=False,
        comment="内核事件类型，如 Double Free、UAF",
    )

    function_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="触发异常的函数名，如 malloc / free",
    )

    # 十六进制内存地址字符串，如 "0xffff888012345678"
    memory_addr: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
        comment="异常发生时的内存地址（十六进制字符串，硬核铁证）",
    )

    stack_trace: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="内核调用栈（可选，便于溯源）",
    )

    raw_data: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="eBPF 上报的原始事件 JSON 数据",
    )

    # ── 关联关系 ───────────────────────────────────────────────────────────────
    vulnerability: Mapped["Vulnerability"] = relationship(
        "Vulnerability",
        back_populates="ebpf_events",
    )

    def __repr__(self) -> str:
        return (
            f"<EbpfEventLog type={self.event_type} "
            f"addr={self.memory_addr} fn={self.function_name}>"
        )


# 避免循环导入
from app.models.vulnerability import Vulnerability  # noqa: E402
