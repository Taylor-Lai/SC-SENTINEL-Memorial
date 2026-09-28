"""Check preserved code and archive navigation without running the application."""

from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = "ce5a1308b7daceb2de8f3b537fddbd325b31c7a0"


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
    paths = list(expected)
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
        if path not in expected and (ROOT / path).exists():
            errors.append(f"Unexpected code file: {path}")
    print(f"Checked {len(paths)} original code files")
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
