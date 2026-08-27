from pathlib import Path
from config import SUPPORTED_C_EXTENSIONS

def scan_source_files(project_path):
    root = Path(project_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Project path does not exist: {root}")
    result = []
    for path in root.rglob("*"):
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
    for path in root.rglob("*"):
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
