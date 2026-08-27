import argparse
import json
import re
from pathlib import Path

ASAN_ERROR_RE = re.compile(r"ERROR:\s+AddressSanitizer:\s+([a-zA-Z0-9_\-]+)")
ASAN_SUMMARY_RE = re.compile(r"SUMMARY:\s+AddressSanitizer:\s+([a-zA-Z0-9_\-]+)")
STACK_SRC_RE = re.compile(r"(?P<file>[\w\-/\\.]+\.c):(?P<line>\d+)")
WRITE_SIZE_RE = re.compile(r"WRITE of size\s+(\d+)")
READ_SIZE_RE = re.compile(r"READ of size\s+(\d+)")


def main():
    parser = argparse.ArgumentParser(
        description="Parse real ASan logs and generate Agent E dynamic validation input."
    )
    parser.add_argument("--harness-root", default="harness_packages")
    parser.add_argument("--output", default="validation/asan_validation_results.json")
    args = parser.parse_args()

    result = parse_harness_logs(Path(args.harness_root))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=== SENTINEL ASan Log Parser ===")
    print(f"Harness root: {Path(args.harness_root).resolve()}")
    print(f"Output: {output_path.resolve()}")
    print(f"Total logs: {result['summary']['total_logs']}")
    print(f"Confirmed findings: {result['summary']['confirmed_findings']}")
    print(f"Failed or unconfirmed: {result['summary']['failed_or_unconfirmed']}")


def parse_harness_logs(harness_root: Path):
    harness_root = harness_root.resolve()
    harness_dirs = sorted(p for p in harness_root.glob("HARNESS-*") if p.is_dir())

    results = []
    for harness_dir in harness_dirs:
        config = load_json(harness_dir / "harness_config.json", default={})
        logs = sorted(harness_dir.glob("*.log"))

        if not logs:
            results.append(make_unconfirmed_result(config, harness_dir, reason="no_log_file"))
            continue

        log_path = max(logs, key=lambda p: p.stat().st_mtime)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        results.append(parse_single_asan_log(text, log_path, config, harness_dir))

    confirmed = [item for item in results if item.get("dynamic_status") == "confirmed"]

    return {
        "source": "ASAN",
        "schema_version": "part4.2",
        "crash_found": bool(confirmed),
        "summary": {
            "total_harness_packages": len(harness_dirs),
            "total_logs": sum(1 for item in results if item.get("log_file")),
            "confirmed_findings": len(confirmed),
            "failed_or_unconfirmed": sum(1 for item in results if item.get("dynamic_status") != "confirmed")
        },
        "results": results,
        "results_by_finding_id": {
            item.get("finding_id"): item
            for item in results
            if item.get("finding_id")
        }
    }


def parse_single_asan_log(text, log_path: Path, config: dict, harness_dir: Path):
    error_match = ASAN_ERROR_RE.search(text)
    summary_match = ASAN_SUMMARY_RE.search(text)

    bug_type = None
    if error_match:
        bug_type = error_match.group(1)
    elif summary_match:
        bug_type = summary_match.group(1)

    bug_type = normalize_asan_bug_type(bug_type, text)

    expected = expected_asan_keyword(config.get("cwe_id"))
    confirmed = bool(bug_type)

    source_locations = extract_source_locations(text)
    access = extract_access_info(text)

    consistency = "unknown"
    if confirmed and expected:
        consistency = "matched_expected_cwe" if expected in bug_type else "asan_type_differs_from_expected"
    elif confirmed:
        consistency = "confirmed_without_expected_mapping"

    return {
        "harness_id": config.get("package_id") or harness_dir.name,
        "finding_id": config.get("finding_id"),
        "target_file": config.get("target_file"),
        "target_function": config.get("target_function"),
        "cwe_id": config.get("cwe_id"),
        "vulnerability_type": config.get("vulnerability_type"),
        "log_file": str(log_path),
        "dynamic_status": "confirmed" if confirmed else "unconfirmed",
        "sanitizer": "AddressSanitizer",
        "asan_bug_type": bug_type,
        "expected_asan_keyword": expected,
        "consistency": consistency,
        "crash_found": confirmed,
        "access": access,
        "source_locations": source_locations,
        "stderr_excerpt": extract_relevant_excerpt(text),
        "evidence": build_evidence(config, bug_type, source_locations, access)
    }


def make_unconfirmed_result(config: dict, harness_dir: Path, reason: str):
    return {
        "harness_id": config.get("package_id") or harness_dir.name,
        "finding_id": config.get("finding_id"),
        "target_file": config.get("target_file"),
        "target_function": config.get("target_function"),
        "cwe_id": config.get("cwe_id"),
        "vulnerability_type": config.get("vulnerability_type"),
        "log_file": None,
        "dynamic_status": "unconfirmed",
        "sanitizer": "AddressSanitizer",
        "asan_bug_type": None,
        "expected_asan_keyword": expected_asan_keyword(config.get("cwe_id")),
        "consistency": "no_log_file",
        "crash_found": False,
        "access": {},
        "source_locations": [],
        "stderr_excerpt": "",
        "evidence": [f"No ASan log file found. Reason: {reason}"]
    }


def normalize_asan_bug_type(raw_type, text):
    if not raw_type:
        return None

    text_lower = text.lower()
    raw_lower = str(raw_type).lower()

    known_types = [
        "heap-use-after-free",
        "stack-use-after-free",
        "double-free",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "global-buffer-overflow",
        "use-after-poison",
        "format-string",
        "format",
    ]

    for bug_type in known_types:
        if bug_type in text_lower:
            return bug_type

    return raw_lower


def expected_asan_keyword(cwe_id):
    return {
        "CWE-415": "double-free",
        "CWE-416": "heap-use-after-free",
        "CWE-122": "heap-buffer-overflow",
        "CWE-121": "stack-buffer-overflow",
        "CWE-134": "format"
    }.get(cwe_id)


def extract_source_locations(text):
    locations = []
    seen = set()
    for match in STACK_SRC_RE.finditer(text):
        file_path = match.group("file")
        line_no = int(match.group("line"))
        if not (
            "samples/vulnerable_project" in file_path
            or "harness_packages" in file_path
            or file_path.endswith(".c")
        ):
            continue
        key = (file_path, line_no)
        if key in seen:
            continue
        seen.add(key)
        locations.append({"file": file_path, "line": line_no})
    return locations[:12]


def extract_access_info(text):
    access = {}
    write_match = WRITE_SIZE_RE.search(text)
    read_match = READ_SIZE_RE.search(text)
    if write_match:
        access["access_type"] = "WRITE"
        access["size"] = int(write_match.group(1))
    elif read_match:
        access["access_type"] = "READ"
        access["size"] = int(read_match.group(1))
    return access


def extract_relevant_excerpt(text, max_lines=45):
    lines = text.splitlines()
    selected = []
    capture = False
    for line in lines:
        if "ERROR: AddressSanitizer:" in line:
            capture = True
        if capture:
            selected.append(line)
        if capture and "ABORTING" in line:
            break
        if len(selected) >= max_lines:
            break
    if not selected:
        selected = lines[:max_lines]
    return "\n".join(selected)


def build_evidence(config, bug_type, locations, access):
    evidence = []
    if bug_type:
        evidence.append(f"AddressSanitizer reported: {bug_type}")
    if config.get("cwe_id"):
        evidence.append(f"Expected CWE from static audit: {config.get('cwe_id')}")
    if access:
        evidence.append(f"Memory access: {access.get('access_type')} of size {access.get('size')}")
    target_locs = [
        loc for loc in locations
        if config.get("target_file") and config.get("target_file") in loc.get("file", "")
    ]
    for loc in target_locs[:4]:
        evidence.append(f"Target source location: {loc['file']}:{loc['line']}")
    if not evidence:
        evidence.append("No ASan error pattern was extracted from the log.")
    return evidence


def load_json(path: Path, default=None):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


if __name__ == "__main__":
    main()
