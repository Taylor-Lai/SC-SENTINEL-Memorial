import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from app.worker.llm_task import _persist_harness_bundles


def test_only_finding_linked_harness_is_materialized() -> None:
    original_dir = Path.cwd()
    with TemporaryDirectory() as scratch:
        try:
            os.chdir(scratch)
            result = _persist_harness_bundles(
                "task-1",
                {"agent_e": {"harness_packages": [
                    {"package_id": "../unsafe", "finding_id": "F-1", "embedded_files": {"Makefile": "all:\n\t@true\n"}},
                    {"package_id": "unlinked", "finding_id": "F-2"},
                ]}},
                {"F-1": "V-1"},
            )
            assert result is not None
            root = Path(result)
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            assert len(manifest["packages"]) == 1
            assert manifest["packages"][0]["package_id"] == "unsafe"
            assert manifest["packages"][0]["vuln_id"] == "V-1"
            assert (root / "unsafe" / "Makefile").is_file()
            assert not (root / "unlinked").exists()
        finally:
            os.chdir(original_dir)
