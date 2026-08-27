"""
源码解析服务 — ZIP 解压与依赖文件提取
────────────────────────────────────────────────────────────────────────────
职责：
  1. 解压用户上传的 ZIP 源码包到临时工作目录
  2. 遍历目录树，提取 C/C++ 依赖声明文件（CMakeLists.txt / Makefile /
     conanfile.txt / vcpkg.json）和 #include 引用列表
  3. 构建 SourceContext 对象，供 Agent a / Agent b-c 接口调用时作为请求体

输出 SourceContext 包含的信息：
  - 解压后的源码根目录路径（绝对路径）
  - 依赖声明文件内容列表（供 Agent a 依赖识别）
  - 所有 .c / .cpp / .h 文件的路径列表（供 Agent b-c 语义复核）
  - #include 引用摘要（辅助 Agent a 识别引入的第三方库）
"""
import logging
import re
import shutil
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── 支持识别的依赖声明文件名（全小写匹配）────────────────────────────────────
_DEP_FILE_NAMES = {
    "cmakelists.txt",
    "makefile",
    "makefile.am",
    "configure.ac",
    "conanfile.txt",
    "conanfile.py",
    "vcpkg.json",
    ".vcpkg-configuration.json",
    "meson.build",
    "build.gradle",
}

# ── C/C++ 源码文件扩展名 ──────────────────────────────────────────────────────
_CPP_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh", ".hxx"}

# ── 从 #include 提取库名的正则（非系统头文件：< 开头且 / 分隔 or 含点）─────────
_INCLUDE_PATTERN = re.compile(
    r'^\s*#\s*include\s+[<"]([^>"]+)[>"]', re.MULTILINE
)


@dataclass
class SourceContext:
    """解析后的源码上下文，供 Worker 任务传递给 ML Agent 接口"""

    # 解压后的源码根目录（绝对路径字符串）
    source_root: str

    # 原始 ZIP 文件路径（用于溯源）
    zip_path: str | None = None

    # 依赖声明文件内容列表（供 Agent a 进行依赖识别）
    # 每项：{"filename": "CMakeLists.txt", "content": "...", "path": "..."}
    dep_files: list[dict] = field(default_factory=list)

    # C/C++ 源文件路径列表（相对于 source_root）
    cpp_files: list[str] = field(default_factory=list)

    # 所有 #include 引用集合（去重），辅助 Agent a 识别第三方库
    includes: list[str] = field(default_factory=list)

    # 整个目录树（相对路径列表，供 Agent b-c 文件选择）
    file_tree: list[str] = field(default_factory=list)


def extract_zip(zip_path: str, extract_to: str | None = None) -> str:
    """
    解压 ZIP 文件到指定目录。

    Args:
        zip_path: ZIP 文件的绝对路径
        extract_to: 解压目标目录，默认与 ZIP 同目录下同名子文件夹

    Returns:
        解压后的根目录路径（字符串）

    Raises:
        ValueError: ZIP 文件无效或路径不合法
        zipfile.BadZipFile: ZIP 文件损坏
    """
    zip_path_obj = Path(zip_path)
    if not zip_path_obj.exists():
        raise ValueError(f"ZIP 文件不存在: {zip_path}")
    if not zipfile.is_zipfile(zip_path):
        raise ValueError(f"文件不是合法的 ZIP 格式: {zip_path}")

    # 默认解压到同目录下的 `<filename>_extracted/` 子目录
    if extract_to is None:
        extract_to = str(zip_path_obj.parent / (zip_path_obj.stem + "_extracted"))

    extract_path = Path(extract_to)
    extract_path.mkdir(parents=True, exist_ok=True)

    extract_root = extract_path.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        entries = zf.infolist()
        if len(entries) > settings.MAX_ARCHIVE_FILES:
            raise ValueError(f"ZIP 文件数量超过限制: {len(entries)} > {settings.MAX_ARCHIVE_FILES}")

        total_size = 0
        for info in entries:
            # Windows-created ZIPs frequently use backslashes. Normalize them
            # before validation and extraction so Linux receives src/main.c
            # instead of one literal file named src\\main.c.
            normalized_name = info.filename.replace("\\", "/")
            member_path = (extract_root / normalized_name).resolve()
            try:
                member_path.relative_to(extract_root)
            except ValueError as exc:
                raise ValueError(f"ZIP 内包含危险的路径穿越文件名: {info.filename}") from exc

            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError(f"ZIP 内不允许符号链接: {info.filename}")
            if info.file_size > settings.MAX_ARCHIVE_SINGLE_FILE_BYTES:
                raise ValueError(f"ZIP 单文件解压后过大: {info.filename}")
            if info.compress_size and info.file_size / info.compress_size > settings.MAX_ARCHIVE_COMPRESSION_RATIO:
                raise ValueError(f"ZIP 文件压缩率异常: {info.filename}")
            total_size += info.file_size
            if total_size > settings.MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ValueError("ZIP 解压后总大小超过限制")

        # Validation is complete before any member is written.
        for info in entries:
            normalized_name = info.filename.replace("\\", "/")
            target_path = (extract_root / normalized_name).resolve()
            if info.is_dir() or normalized_name.endswith("/"):
                target_path.mkdir(parents=True, exist_ok=True)
                continue
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as source, target_path.open("wb") as target:
                shutil.copyfileobj(source, target)

    # 如果解压后只有一个顶层目录（常见的 GitHub 下载 zip 格式），进入该目录
    entries = list(extract_path.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        effective_root = str(entries[0])
    else:
        effective_root = str(extract_path)

    logger.info(f"[SourceParser] ZIP 解压完成 -> {effective_root}")
    return effective_root


def _summarize_description(desc: str, max_length: int = 120) -> str:
    """
    总结过长的英文描述，保留关键信息

    Args:
        desc: 原始描述文本
        max_length: 最大长度限制

    Returns:
        总结后的中英文混合描述
    """
    if not desc or len(desc) <= max_length:
        return desc

    # 提取关键词：CVE编号、版本号、漏洞类型
    import re
    cve_match = re.search(r'CVE-\d{4}-\d+', desc)
    version_match = re.search(r'version[s]?\s+([0-9.]+(?:\s+(?:through|to|before|and)\s+[0-9.]+)?)', desc, re.IGNORECASE)
    vuln_types = re.findall(r'(buffer overflow|use after free|double free|injection|denial of service|memory leak|integer overflow|code execution)', desc, re.IGNORECASE)

    summary_parts = []
    if cve_match:
        summary_parts.append(cve_match.group(0))

    if vuln_types:
        vuln_cn = {
            'buffer overflow': '缓冲区溢出',
            'use after free': '释放后使用',
            'double free': '重复释放',
            'injection': '注入漏洞',
            'denial of service': '拒绝服务',
            'memory leak': '内存泄漏',
            'integer overflow': '整数溢出',
            'code execution': '代码执行'
        }
        vuln_type = vuln_types[0].lower()
        cn_name = vuln_cn.get(vuln_type, vuln_type)
        summary_parts.append(f"{vuln_type} ({cn_name})")

    if version_match:
        summary_parts.append(f"影响版本: {version_match.group(1)}")

    if summary_parts:
        return ' · '.join(summary_parts)

    # 如果没有找到关键信息，截取前max_length字符
    return desc[:max_length] + '…' if len(desc) > max_length else desc


def parse_source_context(
    source_root: str,
    zip_path: str | None = None,
) -> SourceContext:
    """
    遍历解压后的源码目录，提取依赖声明文件、C/C++ 文件列表和 #include 引用。

    Args:
        source_root: 解压后的源码根目录
        zip_path: 原始 ZIP 路径（可选，仅用于记录）

    Returns:
        SourceContext 对象
    """
    root = Path(source_root)
    if not root.exists():
        raise ValueError(f"源码目录不存在: {source_root}")

    ctx = SourceContext(source_root=source_root, zip_path=zip_path)
    includes_set: set[str] = set()
    source_file_count = 0
    source_total_bytes = 0

    for file_path in root.rglob("*"):
        if file_path.is_symlink():
            logger.warning("[SourceParser] 跳过符号链接: %s", file_path)
            continue
        if not file_path.is_file():
            continue

        source_file_count += 1
        source_total_bytes += file_path.stat().st_size
        if source_file_count > settings.MAX_SOURCE_FILES:
            raise ValueError(f"源码文件数量超过限制: {settings.MAX_SOURCE_FILES}")
        if source_total_bytes > settings.MAX_SOURCE_BYTES:
            raise ValueError("源码目录总大小超过限制")

        # Only inspect path segments *inside* source_root.  The upload itself
        # may legitimately have a leading dot (for example a CI fixture named
        # ``.acceptance-fixture.zip``); checking absolute path segments caused
        # every file below such a root to be skipped.
        relative_parts = file_path.relative_to(root).parts
        if any(
            part.startswith(".") or part in ("__pycache__", "node_modules", ".git")
            for part in relative_parts
        ):
            continue

        rel_path = str(file_path.relative_to(root))
        ctx.file_tree.append(rel_path)

        # ── 检查是否为依赖声明文件 ────────────────────────────────────────────
        if file_path.name.lower() in _DEP_FILE_NAMES:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                ctx.dep_files.append({
                    "filename": file_path.name,
                    "path": rel_path,
                    "content": content[:8000],  # 截断防止过长，8KB 足够 Agent a 使用
                })
                logger.debug(f"[SourceParser] 发现依赖文件: {rel_path}")
            except Exception as e:
                logger.warning(f"[SourceParser] 读取依赖文件失败 {rel_path}: {e}")

        # ── 检查是否为 C/C++ 源码文件 ─────────────────────────────────────────
        if file_path.suffix.lower() in _CPP_EXTENSIONS:
            ctx.cpp_files.append(rel_path)

            # 提取 #include 引用（只读前 200 行，性能优化）
            try:
                lines = []
                with open(file_path, encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f):
                        if i >= 200:
                            break
                        lines.append(line)
                content_head = "".join(lines)
                for inc in _INCLUDE_PATTERN.findall(content_head):
                    includes_set.add(inc)
            except Exception as e:
                logger.debug(f"[SourceParser] 提取 include 失败 {rel_path}: {e}")

    ctx.includes = sorted(includes_set)

    logger.info(
        f"[SourceParser] 解析完成: 依赖文件={len(ctx.dep_files)}, "
        f"C/C++文件={len(ctx.cpp_files)}, #include={len(ctx.includes)}"
    )
    return ctx


def parse_zip_source(zip_path: str) -> SourceContext:
    """
    便捷入口：解压 ZIP 并返回完整的 SourceContext。

    Args:
        zip_path: 上传的 ZIP 文件路径

    Returns:
        SourceContext 对象，包含解压后路径 + 依赖信息
    """
    source_root = extract_zip(zip_path)
    return parse_source_context(source_root, zip_path=zip_path)
