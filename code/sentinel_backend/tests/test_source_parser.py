import stat
import zipfile
from pathlib import Path

import pytest

from app.services.source_parser import extract_zip, parse_source_context


def test_extract_zip_accepts_normal_project(tmp_path: Path) -> None:
    archive = tmp_path / "project.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("project/src/main.c", "int main(void) { return 0; }")

    root = Path(extract_zip(str(archive), str(tmp_path / "extract")))

    assert root.name == "project"
    assert (root / "src" / "main.c").is_file()


def test_extract_zip_normalizes_windows_member_separators(tmp_path: Path) -> None:
    archive = tmp_path / "windows-project.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("src\\main.c", "int main(void) { return 0; }")
        bundle.writestr("include\\demo.h", "#pragma once\n")

    root = Path(extract_zip(str(archive), str(tmp_path / "extract")))

    assert (root / "src" / "main.c").is_file()
    assert (root / "include" / "demo.h").is_file()
    assert not (root / "src\\main.c").exists()


def test_extract_zip_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "traversal.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escape.c", "bad")

    with pytest.raises(ValueError, match="路径穿越"):
        extract_zip(str(archive), str(tmp_path / "extract"))

    assert not (tmp_path / "escape.c").exists()


def test_extract_zip_rejects_symbolic_links(tmp_path: Path) -> None:
    archive = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("project/link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(info, "../outside")

    with pytest.raises(ValueError, match="符号链接"):
        extract_zip(str(archive), str(tmp_path / "extract"))


def test_parse_source_context_accepts_hidden_named_root(tmp_path: Path) -> None:
    root = tmp_path / ".acceptance-fixture_extracted"
    root.mkdir()
    (root / "CMakeLists.txt").write_text("add_executable(app main.c)", encoding="utf-8")
    (root / "main.c").write_text(
        "#include <stdio.h>\nint main(void) { return 0; }",
        encoding="utf-8",
    )

    context = parse_source_context(str(root))

    assert context.cpp_files == ["main.c"]
    assert [item["filename"] for item in context.dep_files] == ["CMakeLists.txt"]
    assert context.includes == ["stdio.h"]
