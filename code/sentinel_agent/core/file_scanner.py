from pathlib import Path
from config import SUPPORTED_C_EXTENSIONS


def _regular_project_files(root):
    if not root.is_dir():
        raise FileNotFoundError(f"Project directory does not exist: {root}")
    for path in sorted(root.rglob("*")):
        # Git repositories and local inputs may contain links even though ZIP
        # ingestion rejects them. Never read a linked file or a junction escape.
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            continue
        if path.is_file():
            yield path


def scan_source_files(project_path):
    root = Path(project_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Project path does not exist: {root}")
    result = []
    for path in _regular_project_files(root):
        if path.is_file() and path.suffix.lower() in SUPPORTED_C_EXTENSIONS:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result.append({
                "absolute_path": str(path),
                "relative_path": str(path.relative_to(root)),
                "suffix": path.suffix.lower(),
                "content": content,
                "lines": content.splitlines()
            })
    return result

def scan_project_metadata_files(project_path):
    root = Path(project_path).resolve()
    names = {"CMakeLists.txt", "Makefile", "makefile", "conanfile.txt", "vcpkg.json"}
    result = []
    for path in _regular_project_files(root):
        if path.is_file() and path.name in names:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result.append({
                "absolute_path": str(path),
                "relative_path": str(path.relative_to(root)),
                "name": path.name,
                "content": content,
                "lines": content.splitlines()
            })
    return result
