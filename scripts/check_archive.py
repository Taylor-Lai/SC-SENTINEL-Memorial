"""Check preserved code and archive navigation without running the application."""

from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = "ce5a1308b7daceb2de8f3b537fddbd325b31c7a0"
# Reviewed deployment, binary-input, and runtime-evidence additions. All other
# original source files must continue to match the initial upload byte-for-byte.
SURFACE_FILES = {
    'code/.env.example',
    'code/DOCKER.md',
    'code/INTEGRATION_GUIDE.md',
    'code/README.md',
    'code/sentinel_agent/service.py',
    'code/sentinel_agent/agents/agent_d_harness.py',
    'code/docker-compose.yaml',
    'code/docs/ARCHITECTURE.md',
    'code/docs/COMPETITION_RUNBOOK.md',
    'code/sentinel_agent/.dockerignore',
    'code/sentinel_agent/README.md',
    'code/sentinel_backend/README.md',
    'code/sentinel_backend/app/api/v1/tasks.py',
    'code/sentinel_backend/app/api/v1/audit.py',
    'code/sentinel_backend/app/core/pdf_generator.py',
    'code/sentinel_backend/app/core/evidence.py',
    'code/sentinel_backend/app/main.py',
    'code/sentinel_backend/app/models/task.py',
    'code/sentinel_backend/app/schemas/task.py',
    'code/sentinel_backend/app/services/binary_analyzer.py',
    'code/sentinel_backend/app/services/sandbox_manager.py',
    'code/sentinel_backend/app/worker/binary_task.py',
    'code/sentinel_backend/app/worker/middleware.py',
    'code/sentinel_backend/app/worker/pipeline.py',
    'code/sentinel_backend/alembic/versions/2026_10_10_0002_add_binary_source_type.py',
    'code/sentinel_backend/Dockerfile',
    'code/sentinel_backend/docker/ebpf/monitor.bt',
    'code/sentinel_backend/app/worker/fuzzing_task.py',
    'code/sentinel_backend/app/worker/llm_task.py',
    'code/sentinel_backend/tests/test_runtime_verdict.py',
    'code/sentinel_backend/poetry.lock',
    'code/sentinel_backend/pyproject.toml',
    'code/sentinel_backend/requirements.txt',
    'code/sentinel_backend/tests/test_binary_analyzer.py',
    'code/sentinel_backend/tests/test_evidence.py',
    'code/sentinel_backend/tests/test_sandbox_policy.py',
    'code/sentinel_backend/tests/test_source_parser.py',
    'code/sentinel_backend/tests/test_harness_materialization.py',
    'code/sentinel_frontend/README.md',
    'code/sentinel_frontend/src/views/ReportView.vue',
    'code/sentinel_frontend/src/views/MonitorView.vue',
    'code/sentinel_frontend/src/views/HomeView.vue',
    'code/sentinel_frontend/src/views/SubmitView.vue',
    'code/sentinel_frontend/src/types/api.ts',
    'code/sentinel_frontend/src/components/report/FindingCard.vue',
}
REMOVED_FILES = {"code/sentinel_backend/poetry.lock"}


def git(*args, input=None):
    return subprocess.run(
        ["git", *args], cwd=ROOT, input=input, capture_output=True, check=True
    ).stdout


def check_code():
    entries = git("ls-tree", "-rz", ORIGINAL, "--", "code").split(b"\0")
    expected = {}
    for entry in filter(None, entries):
        metadata, path = entry.split(b"\t", 1)
        expected[path.decode("utf-8")] = metadata.split()[2].decode("ascii")
    paths = [p for p in expected if p not in SURFACE_FILES]
    hashes = git(
        "hash-object", "--stdin-paths",
        input=("\n".join(paths) + "\n").encode("utf-8"),
    ).decode("ascii").splitlines()
    errors = [f"Original code changed: {p}" for p, h in zip(paths, hashes)
              if expected[p] != h]
    if len(hashes) != len(paths):
        errors.append("Could not hash all original files")
    current = git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "code")
    for path in filter(None, current.decode("utf-8").split("\0")):
        if path not in expected and path not in SURFACE_FILES and (ROOT / path).exists():
            errors.append(f"Unexpected code file: {path}")
    for path in SURFACE_FILES - REMOVED_FILES:
        if not (ROOT / path).is_file():
            errors.append(f"Missing deployment/documentation file: {path}")
    for path in REMOVED_FILES:
        if (ROOT / path).exists():
            errors.append(f"Obsolete deployment file returned: {path}")
    print(f"Checked {len(paths)} original files and {len(SURFACE_FILES)} surface updates")
    return errors


def anchors(text):
    result = set(re.findall(r'\bid=["\']([^"\']+)', text))
    counts = {}
    for heading in re.findall(r"^#{1,6}\s+(.+)$", text, re.MULTILINE):
        slug = re.sub(r"[^\w\-\s]", "", heading.lower()).replace(" ", "-")
        count = counts.get(slug, 0)
        result.add(f"{slug}-{count}" if count else slug)
        counts[slug] = count + 1
    return result


def check_navigation():
    documents = sorted(ROOT.glob("*.md"))
    documents += sorted((ROOT / "assets").glob("*.md"))
    documents += sorted((ROOT / "materials").glob("*.md"))
    documents += sorted((ROOT / ".github").rglob("*.md"))
    documents += sorted(ROOT / p for p in SURFACE_FILES if p.endswith(".md"))
    documents += [ROOT / "code/INTEGRATION_GUIDE.md", ROOT / "code/docs/SECURITY.md"]
    errors = []
    for document in documents:
        text = document.read_text(encoding="utf-8")
        text = re.sub(r"^```[^\n]*\n.*?^```\s*$", "", text,
                      flags=re.MULTILINE | re.DOTALL)
        links = re.findall(r"\]\(([^\s)]+)(?:\s+[^)]*)?\)", text)
        links += re.findall(r'(?:href|src)=["\']([^"\']+)', text)
        for link in links:
            parsed = urlsplit(link.strip("<>"))
            if parsed.scheme or parsed.netloc:
                continue
            target = document.parent / unquote(parsed.path) if parsed.path else document
            if not target.exists():
                errors.append(f"Missing link in {document.relative_to(ROOT)}: {link}")
            elif parsed.fragment and target.suffix == ".md":
                if unquote(parsed.fragment) not in anchors(target.read_text(encoding="utf-8")):
                    errors.append(f"Missing heading in {document.relative_to(ROOT)}: {link}")
    print(f"Checked local links in {len(documents)} archive documents")
    return errors


def main():
    try:
        errors = check_code() + check_navigation()
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.decode("utf-8", errors="replace"), file=sys.stderr)
        print("Clone with full history so the original commit is available.", file=sys.stderr)
        return 1
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print("Archive checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
