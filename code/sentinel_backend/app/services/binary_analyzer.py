"""Bounded, non-executing ELF/PE intake and imported-symbol triage."""

import re
import struct
import subprocess
from pathlib import Path


_RISK_APIS = {
    "gets": ("buffer_overflow", "无长度限制的输入函数 gets"),
    "strcpy": ("buffer_overflow", "无目标缓冲区长度检查的 strcpy"),
    "strcat": ("buffer_overflow", "无目标缓冲区长度检查的 strcat"),
    "sprintf": ("buffer_overflow", "无输出长度限制的 sprintf"),
    "vsprintf": ("buffer_overflow", "无输出长度限制的 vsprintf"),
}


def inspect_binary(path: str | Path) -> dict:
    """Validate a binary header without executing or loading the program."""
    path = Path(path)
    with path.open("rb") as stream:
        header = stream.read(64)
        if header.startswith(b"MZ") and len(header) >= 64:
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            if pe_offset > 1024 * 1024:
                raise ValueError("PE 签名偏移超出安全检查范围")
            stream.seek(pe_offset)
            pe_header = stream.read(26)
    if header.startswith(b"\x7fELF"):
        if len(header) < 52 or header[4] not in (1, 2) or header[5] not in (1, 2):
            raise ValueError("ELF 文件头无效或不完整")
        endian = "<" if header[5] == 1 else ">"
        kind = struct.unpack_from(endian + "H", header, 16)[0]
        if kind not in (2, 3):
            raise ValueError("仅支持 ELF 可执行文件或共享库")
        return {"format": "ELF", "bits": 32 if header[4] == 1 else 64,
                "kind": "shared" if kind == 3 else "executable"}
    if header.startswith(b"MZ"):
        if len(header) < 64:
            raise ValueError("PE 文件头无效或不完整")
        if len(pe_header) < 26 or pe_header[:4] != b"PE\0\0":
            raise ValueError("PE 签名无效或超出文件头检查范围")
        magic = struct.unpack_from("<H", pe_header, 24)[0]
        if magic not in (0x10B, 0x20B):
            raise ValueError("PE 可选头类型不受支持")
        characteristics = struct.unpack_from("<H", pe_header, 22)[0]
        return {"format": "PE", "bits": 32 if magic == 0x10B else 64,
                "kind": "shared" if characteristics & 0x2000 else "executable"}
    raise ValueError("文件内容不是 ELF 或 PE 格式")


def analyze_binary(path: str | Path, target_vulns: list[str] | None = None) -> dict:
    """Inspect binary metadata and imported APIs; findings remain unverified."""
    path = Path(path)
    metadata = inspect_binary(path)
    try:
        result = subprocess.run(
            ["objdump", "-p", str(path)], capture_output=True, text=True,
            errors="replace", timeout=30, check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("二进制分析需要 binutils/objdump，请检查后端镜像") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("objdump 分析超时") from exc
    if result.returncode != 0:
        raise ValueError(f"objdump 无法解析该二进制文件：{result.stderr[:240]}")

    output = result.stdout[:1_000_000]
    libraries = sorted(set(re.findall(
        r"(?:NEEDED\s+|DLL Name:\s*)([^\s]+)", output, re.IGNORECASE,
    )))[:200]
    # objdump -p lists PE imports under DLL Name and ELF imports through
    # dynamic relocations. The symbol table is read separately for ELF.
    try:
        symbols_result = subprocess.run(
            ["objdump", "-T", str(path)], capture_output=True, text=True,
            errors="replace", timeout=30, check=False,
        )
        symbols = output + "\n" + symbols_result.stdout[:1_000_000]
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("objdump 符号分析超时") from exc
    allowed = {item.lower().replace("_", "-") for item in (target_vulns or [])}
    findings = []
    for symbol, (vuln_type, label) in _RISK_APIS.items():
        if allowed and not allowed.intersection({"buffer-overflow", "heap-overflow", "stack-overflow", "cwe-120", "cwe-121", "cwe-122"}):
            continue
        if not re.search(rf"(?<![\w])_?{symbol}(?:@[^\s]+)?(?![\w])", symbols):
            continue
        findings.append({
            "vuln_type": vuln_type,
            "file_path": path.name,
            "line_number": None,
            "code_context": f"{metadata['format']} {metadata['bits']}-bit {metadata['kind']} · imported symbol: {symbol}",
            "trigger_cond": f"检测到 {label} 的导入符号；需确认调用点、参数边界和可达性，尚未证明漏洞存在。",
            "fix_advice": "检查该函数的所有调用点与缓冲区边界；如适用，改用带显式长度的接口。",
        })
    return {"metadata": metadata, "libraries": libraries, "findings": findings}
