from pathlib import Path

import pytest

from core.file_scanner import scan_project_metadata_files, scan_source_files


@pytest.mark.parametrize(
    ("scanner", "filename"),
    [(scan_source_files, "target.c"), (scan_project_metadata_files, "Makefile")],
)
def test_scanner_does_not_read_symlinked_files(tmp_path, scanner, filename):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / filename
    outside.write_text("outside project", encoding="utf-8")
    try:
        (project / filename).symlink_to(outside)
    except OSError:
        pytest.skip("Creating symlinks requires additional privileges on this host")

    assert scanner(project) == []


@pytest.mark.parametrize(
    ("scanner", "filename"),
    [(scan_source_files, "target.c"), (scan_project_metadata_files, "Makefile")],
)
def test_scanner_rejects_resolved_paths_outside_project(
    tmp_path, monkeypatch, scanner, filename
):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / filename
    outside.write_text("outside project", encoding="utf-8")
    # Model an escaped descendant (such as a Windows junction) without relying
    # on platform-specific link creation privileges.
    monkeypatch.setattr(Path, "rglob", lambda self, pattern: iter([outside]))

    assert scanner(project) == []


def test_scanner_preserves_regular_source_and_metadata(tmp_path):
    (tmp_path / "main.c").write_text("int main(void) { return 0; }", encoding="utf-8")
    (tmp_path / "Makefile").write_text("all:\n\tcc main.c\n", encoding="utf-8")

    sources = scan_source_files(tmp_path)
    metadata = scan_project_metadata_files(tmp_path)
    assert [item["relative_path"] for item in sources] == ["main.c"]
    assert sources[0]["content"] == "int main(void) { return 0; }"
    assert [item["relative_path"] for item in metadata] == ["Makefile"]
