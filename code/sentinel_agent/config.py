from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SUPPORTED_C_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}

# 简化漏洞类型：合并heap/stack overflow为buffer_overflow
TARGET_CWES = [
    "CWE-120",  # Buffer Overflow (包含heap/stack)
    "CWE-416",  # Use-After-Free
    "CWE-415",  # Double Free
]

VULN_TYPE_MAPPING = {
    "CWE-120": "buffer_overflow",
    "CWE-416": "use_after_free",
    "CWE-415": "double_free",
}

# eBPF事件到漏洞类型的通用映射
EBPF_EVENT_TO_VULN_TYPE = {
    "heap_overflow": "buffer_overflow",
    "stack_overflow": "buffer_overflow",
    "heap_overflow_suspected": "buffer_overflow",
    "stack_write_suspected": "buffer_overflow",
    "possible_buffer_overflow": "buffer_overflow",
    "use_after_free": "use_after_free",
    "use_after_free_suspected": "use_after_free",
    "double_free": "double_free",
    "double_free_suspected": "double_free",
}
