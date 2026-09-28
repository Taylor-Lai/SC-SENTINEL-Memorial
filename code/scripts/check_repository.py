"""Check tracked Markdown links and dependency baseline files without services."""

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=ROOT
    ).decode("utf-8").split("\0")
    errors = []
    checked = 0
    for name in tracked:
        if not name.endswith(".md"):
            continue
        path = ROOT / name
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        if len(re.findall(r"^\s*```", content, re.MULTILINE)) % 2:
            errors.append(f"{name}: unclosed code fence")
        # Code examples are not rendered links.
        prose = re.sub(r"```.*?```", "", content, flags=re.DOTALL)
        links = re.findall(r"\]\(([^)]+)\)", prose)
        links += re.findall(r'(?:href|src)="([^"]+)"', prose)
        for target in links:
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            checked += 1
            if not (path.parent / unquote(url.path)).exists():
                errors.append(f"{name}: missing local target {target}")

    for module in ("sentinel_backend", "sentinel_agent"):
        directory = ROOT / "code" / module
        requirements = (directory / "requirements.txt").read_text(encoding="utf-8")
        if "-c constraints.txt" not in requirements:
            errors.append(f"{module}: archive dependency constraints are not enabled")
        if not (directory / "constraints.txt").is_file():
            errors.append(f"{module}: missing constraints.txt")

    for error in errors:
        print(error)
    print(f"Checked {checked} local Markdown targets and both dependency baselines.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
