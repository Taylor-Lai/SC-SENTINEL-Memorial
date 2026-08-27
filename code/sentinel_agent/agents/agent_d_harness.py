
import shutil
import subprocess
import re
import os
import json
from pathlib import Path
from core.id_generator import make_id
from core.json_utils import save_json
from core.llm_client import LLMClient, extract_json_object

BUFFER_OVERFLOW_CWES = {"CWE-120", "CWE-121", "CWE-122"}

# Agent D - Harness Automatic Generation
#
# Part 4.1 upgraded version:
# - Keeps Part 4 CWE-aware harness generation.
# - Fixes Makefile compilation issue:
#   The old Makefile passed -Dmain=sentinel_original_main to both harness and target source.
#   That could rename the harness's own main() and cause "undefined reference to main".
# - New Makefile compiles:
#   1. target source with -Dmain=sentinel_original_main
#   2. harness source without -Dmain=...
#   3. links both object files into ASan/AFL++/libFuzzer targets.


def run_agent_d(agent_c_result, harness_root="harness_packages", project_root=None, enable_compile_check=False):
    harness_root = Path(harness_root)
    harness_root.mkdir(parents=True, exist_ok=True)
    project_root = Path(project_root).resolve() if project_root else None

    packages = []
    for idx, finding in enumerate(agent_c_result.get("static_findings", []), start=1):
        package_id = make_id("HARNESS", idx)
        package_dir = harness_root / package_id
        seeds_dir = package_dir / "seeds"
        crashes_dir = package_dir / "findings"
        seeds_dir.mkdir(parents=True, exist_ok=True)
        crashes_dir.mkdir(parents=True, exist_ok=True)

        strategy = infer_harness_strategy(finding, project_root)
        quality_gate = infer_harness_quality(strategy)
        build_profile = infer_build_profile(finding, project_root)

        (package_dir / "afl_harness.c").write_text(
            make_afl_harness(finding, strategy),
            encoding="utf-8"
        )
        (package_dir / "libfuzzer_harness.c").write_text(
            make_libfuzzer_harness(finding, strategy),
            encoding="utf-8"
        )
        (package_dir / "Makefile").write_text(
            make_makefile(finding, strategy, project_root, build_profile),
            encoding="utf-8"
        )
        (package_dir / "README.md").write_text(
            make_readme(finding, strategy),
            encoding="utf-8"
        )

        seed_files = write_seed_files(seeds_dir, finding, strategy, project_root=project_root)

        package = {
            "package_id": package_id,
            "finding_id": finding["finding_id"],
            "target_file": finding["file"],
            "target_function": finding["function"],
            "cwe_id": finding["cwe_id"],
            "vulnerability_type": finding["vulnerability_type"],
            "risk_level": finding.get("risk_level", "unknown"),
            "line_range": finding.get("line_range"),
            "trigger_condition": finding.get("trigger_condition", ""),
            "strategy": strategy,
            "build_profile": build_profile,
            "package_dir": str(package_dir),
            "afl_harness_file": str(package_dir / "afl_harness.c"),
            "libfuzzer_harness_file": str(package_dir / "libfuzzer_harness.c"),
            "makefile": str(package_dir / "Makefile"),
            "seed_dir": str(seeds_dir),
            "seed_files": seed_files,
            "asan_build_command": "make asan",
            "compile_command": "make asan",
            "afl_build_command": "make afl",
            "libfuzzer_build_command": "make libfuzzer",
            "asan_run_command": "./asan_target seeds/seed_001.bin",
            "afl_run_command": "afl-fuzz -i seeds -o findings -- ./afl_target @@",
            "prototype_confidence": quality_gate["prototype_confidence"],
            "build_ready": quality_gate["build_ready"],
            "manual_adaptation_required": quality_gate["manual_adaptation_required"],
            "compile_check": run_compile_check(package_dir, enable_compile_check),
            "llm_fixer": {
                "enabled": False,
                "status": "reserved",
                "notes": "Compile stderr is captured for a future LLM harness fixer, but automatic mutation is disabled by default."
            },
            "notes": (
                "Agent E generated harness package. "
                "The target source and harness are compiled separately so -Dmain only affects the target source."
            )
        }

        save_json(package, package_dir / "harness_config.json")
        packages.append(package)

    return {
        "agent": "Agent E - Harness Builder and Fixer Agent",
        "harness_packages": packages,
        "summary": {
            "total_packages": len(packages),
            "packages_by_cwe": count_by_cwe(packages),
            "build_ready_packages": sum(1 for p in packages if p.get("build_ready")),
            "manual_adaptation_required": sum(1 for p in packages if p.get("manual_adaptation_required")),
            "compile_checks_executed": sum(1 for p in packages if p.get("compile_check", {}).get("executed"))
        }
    }


def infer_harness_strategy(finding, project_root=None):
    cwe = finding.get("cwe_id")
    if should_replay_via_original_main(finding, project_root):
        return {
            "strategy_name": "original_main_file_replay",
            "argument_model": "original_main_file_arg",
            "min_input_size": 1,
            "description": (
                "Compile the target source with main renamed to sentinel_original_main "
                "and replay fuzzer-generated files through the program's own argv path. "
                "This is preferred for CTF-style samples and static/internal target functions."
            ),
            "expected_sanitizer": "AddressSanitizer",
            "expected_symptom": expected_symptom_for_cwe(cwe)
        }

    if cwe in {"CWE-416", "CWE-415"}:
        return {
            "strategy_name": "flag_path_trigger",
            "argument_model": "int_flag",
            "trigger_value": 1,
            "description": (
                "Call the target function with flag=1 to force the vulnerable branch, "
                "such as double free or use-after-free path."
            ),
            "expected_sanitizer": "AddressSanitizer",
            "expected_symptom": "double-free or heap-use-after-free"
        }

    if cwe in BUFFER_OVERFLOW_CWES:
        return {
            "strategy_name": "oversized_string_input",
            "argument_model": "const_char_ptr",
            "min_input_size": 256,
            "description": (
                "Read fuzzer-controlled bytes, ensure null termination, and pass them as "
                "a string argument to trigger unsafe copy operations."
            ),
            "expected_sanitizer": "AddressSanitizer",
            "expected_symptom": "heap-buffer-overflow or stack-buffer-overflow"
        }

    if cwe == "CWE-134":
        return {
            "strategy_name": "format_string_payload",
            "argument_model": "const_char_ptr",
            "min_input_size": 32,
            "description": (
                "Pass fuzzer-controlled bytes as a format string payload. Seeds include "
                "%x/%p/%s/%n patterns that can expose or corrupt memory when the target "
                "uses attacker input as the format argument."
            ),
            "expected_sanitizer": "AddressSanitizer",
            "expected_symptom": "format string memory disclosure or write via %n"
        }

    return {
        "strategy_name": "generic_file_input",
        "argument_model": "manual_adaptation_required",
        "description": "Generic template. Manual adaptation is needed.",
        "expected_sanitizer": "AddressSanitizer",
        "expected_symptom": "memory safety violation"
    }


def should_replay_via_original_main(finding, project_root=None):
    if not project_root:
        return False
    if source_declares_main(project_root, finding):
        return True
    build_profile = infer_build_profile(finding, project_root)
    if build_profile.get("has_main_source"):
        if build_profile.get("target_function_is_static"):
            return True
        if not build_profile.get("target_function_declared_publicly"):
            return True
        if not is_strategy_signature_compatible(finding, build_profile):
            return True
    return False


def is_strategy_signature_compatible(finding, build_profile):
    signature = str(build_profile.get("target_signature") or "")
    cwe = str(finding.get("cwe_id") or "")
    if not signature:
        return False
    normalized = " ".join(signature.split())
    if cwe in BUFFER_OVERFLOW_CWES or cwe == "CWE-134":
        return bool(re.search(r'\(\s*const\s+char\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\)$', normalized))
    if cwe in {"CWE-415", "CWE-416"}:
        return bool(re.search(r'\(\s*int\s+[A-Za-z_][A-Za-z0-9_]*\s*\)$', normalized))
    return False


def source_declares_main(project_root, finding):
    if not project_root:
        return False
    target_file = finding.get("file")
    if not target_file:
        return False
    try:
        source_path = (Path(project_root) / target_file).resolve()
        if not source_path.is_file():
            return False
        text = source_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    return bool(re.search(r"\b(?:int|void)\s+main\s*\(", text))


def expected_symptom_for_cwe(cwe):
    return {
        "CWE-416": "heap-use-after-free",
        "CWE-415": "double-free",
        "CWE-120": "heap-buffer-overflow or stack-buffer-overflow",
        "CWE-122": "heap-buffer-overflow",
        "CWE-121": "stack-buffer-overflow",
        "CWE-134": "format string memory disclosure or write via %n",
    }.get(cwe, "memory safety violation")


def make_afl_harness(finding, strategy):
    cwe = finding.get("cwe_id")
    function = finding.get("function")
    file = finding.get("file")
    signature = infer_function_prototype(finding, strategy)
    call_code = make_target_call_for_afl(function, strategy)

    return f"""
/*
 * SENTINEL Agent D - AFL++ / ASan file-input harness
 *
 * Finding ID: {finding.get("finding_id")}
 * Target file: {file}
 * Target function: {function}
 * CWE: {cwe}
 * Strategy: {strategy.get("strategy_name")}
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

{signature}

static unsigned char *read_file(const char *path, size_t *out_size) {{
    FILE *fp = fopen(path, "rb");
    if (!fp) {{
        return NULL;
    }}

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size < 0) {{
        fclose(fp);
        return NULL;
    }}

    unsigned char *buf = (unsigned char *)malloc((size_t)size + 1);
    if (!buf) {{
        fclose(fp);
        return NULL;
    }}

    size_t n = fread(buf, 1, (size_t)size, fp);
    fclose(fp);

    buf[n] = '\\0';
    *out_size = n;
    return buf;
}}

int main(int argc, char **argv) {{
    if (argc < 2) {{
        return 0;
    }}

    size_t size = 0;
    unsigned char *data = read_file(argv[1], &size);
    if (!data) {{
        return 0;
    }}

{indent(call_code, 4)}

    free(data);
    return 0;
}}
""".strip() + "\n"


def make_libfuzzer_harness(finding, strategy):
    cwe = finding.get("cwe_id")
    function = finding.get("function")
    file = finding.get("file")
    signature = infer_function_prototype(finding, strategy)
    call_code = make_target_call_for_libfuzzer(function, strategy)

    return f"""
/*
 * SENTINEL Agent D - libFuzzer-style harness
 *
 * Finding ID: {finding.get("finding_id")}
 * Target file: {file}
 * Target function: {function}
 * CWE: {cwe}
 * Strategy: {strategy.get("strategy_name")}
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

{signature}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    if (Data == NULL) {{
        return 0;
    }}

{indent(call_code, 4)}

    return 0;
}}
""".strip() + "\n"


def infer_function_prototype(finding, strategy):
    function = finding.get("function")
    argument_model = strategy.get("argument_model")

    if argument_model == "original_main_file_arg":
        return "int sentinel_original_main(int argc, char **argv);"

    if argument_model == "int_flag":
        return f"void {function}(int flag);"

    if argument_model == "const_char_ptr":
        return f"void {function}(const char *input);"

    return f"/* TODO: declare the real target function prototype for {function}. */"


def infer_harness_quality(strategy):
    manual = strategy.get("argument_model") == "manual_adaptation_required"
    return {
        "prototype_confidence": 0.25 if manual else 0.78,
        "build_ready": not manual,
        "manual_adaptation_required": manual,
    }


def infer_build_profile(finding, project_root=None):
    if not project_root:
        return {
            "mode": "single_source",
            "source_entries": [],
            "include_dirs": [],
            "target_relpath": finding.get("file", ""),
            "target_function_is_static": False,
            "target_function_declared_publicly": True,
            "target_signature": "",
            "has_main_source": False,
            "main_source_relpaths": [],
        }

    target_path = (Path(project_root) / finding.get("file", "")).resolve()
    root = Path(project_root).resolve()
    source_relpaths = []
    include_dirs = set()
    main_source_relpaths = []

    for ext in (".c", ".cc", ".cpp", ".cxx"):
        for file_path in root.rglob(f"*{ext}"):
            if file_path.is_file():
                relpath = str(file_path.relative_to(root)).replace("\\", "/")
                source_relpaths.append(relpath)
                try:
                    text = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    text = ""
                if re.search(r"\b(?:int|void)\s+main\s*\(", text):
                    main_source_relpaths.append(relpath)

    for header in root.rglob("*.h"):
        if header.is_file():
            include_dirs.add(str(header.parent.relative_to(root)).replace("\\", "/"))

    include_dirs.add(".")
    include_dirs = sorted(d for d in include_dirs if d not in {"."} or True)

    if any((root / name).exists() for name in ("CMakeLists.txt", "cmake_lists.txt")):
        mode = "cmake"
    elif any((root / name).exists() for name in ("Makefile", "makefile")):
        mode = "makefile"
    else:
        mode = "multi_source"

    target_dir = str(target_path.parent.relative_to(root)).replace("\\", "/") if target_path.exists() else "."
    def obj_name(relpath):
        return relpath.replace("/", "_").replace("\\", "_").rsplit(".", 1)[0] + ".o"

    unique_sources = sorted(dict.fromkeys(source_relpaths))
    source_entries = [{"src": rel, "obj": obj_name(rel)} for rel in unique_sources]
    target_signature = ""
    target_declared_publicly = False
    target_is_static = False
    function_name = str(finding.get("function") or "")
    if target_path.exists() and function_name:
        try:
            target_text = target_path.read_text(encoding="utf-8", errors="ignore")
            signature_match = re.search(
                rf'^\s*((?:static\s+)?(?:inline\s+)?(?:extern\s+)?[A-Za-z_][\w\s\*\(\)]*?\b{re.escape(function_name)}\s*\([^;]*\))\s*\{{',
                target_text,
                re.MULTILINE,
            )
            if signature_match:
                target_signature = signature_match.group(1)
                target_is_static = bool(re.search(r'^\s*static\b', target_signature))
        except Exception:
            target_signature = ""

    for header in root.rglob("*.h"):
        try:
            header_text = header.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if function_name and re.search(rf'\b{re.escape(function_name)}\s*\([^;]*\)\s*;', header_text):
            target_declared_publicly = True
            break

    return {
        "mode": mode,
        "source_entries": source_entries,
        "include_dirs": sorted(dict.fromkeys(include_dirs + [target_dir])),
        "target_relpath": str(target_path.relative_to(root)).replace("\\", "/") if target_path.exists() else finding.get("file", ""),
        "target_function_is_static": target_is_static,
        "target_function_declared_publicly": target_declared_publicly,
        "target_signature": target_signature,
        "has_main_source": bool(main_source_relpaths),
        "main_source_relpaths": sorted(dict.fromkeys(main_source_relpaths)),
    }


def run_compile_check(package_dir, enable_compile_check):
    if not enable_compile_check:
        return {
            "executed": False,
            "status": "skipped",
            "reason": "compile_check_disabled",
            "stderr_excerpt": "",
        }
    if not shutil.which("make"):
        return {
            "executed": False,
            "status": "skipped",
            "reason": "make_not_found",
            "stderr_excerpt": "",
        }
    try:
        completed = subprocess.run(
            ["make", "asan"],
            cwd=str(package_dir),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return {
            "executed": True,
            "status": "passed" if completed.returncode == 0 else "failed",
            "returncode": completed.returncode,
            "stdout_excerpt": (completed.stdout or "")[-1200:],
            "stderr_excerpt": (completed.stderr or "")[-1200:],
        }
    except Exception as exc:
        return {
            "executed": True,
            "status": "failed",
            "returncode": None,
            "stdout_excerpt": "",
            "stderr_excerpt": str(exc)[-1200:],
        }


def make_target_call_for_afl(function, strategy):
    argument_model = strategy.get("argument_model")

    if argument_model == "original_main_file_arg":
        return """
/*
 * Reuse the target program's real input path. The target source is compiled
 * with -Dmain=sentinel_original_main, so static helper functions remain
 * reachable through the original main().
 */
char *target_argv[] = { (char *)"sentinel_original_main", argv[1], NULL };
sentinel_original_main(2, target_argv);
""".strip()

    if argument_model == "int_flag":
        return f"""
/*
 * For UAF / Double Free demos, flag=1 triggers the vulnerable branch.
 */
{function}(1);
""".strip()

    if argument_model == "const_char_ptr":
        return f"""
/*
 * data is null-terminated by read_file().
 * Passing it as a string can trigger unsafe strcpy/memcpy-style code.
 */
if (size > 0) {{
    {function}((const char *)data);
}}
""".strip()

    return f"""
/*
 * TODO: Convert data/size into parameters for {function}.
 */
(void)data;
(void)size;
""".strip()


def make_target_call_for_libfuzzer(function, strategy):
    argument_model = strategy.get("argument_model")

    if argument_model == "original_main_file_arg":
        return """
/*
 * Materialize libFuzzer bytes as a temporary file and replay the target's
 * original argv-based input path.
 */
const char *path = "/tmp/sentinel_libfuzzer_input.bin";
FILE *fp = fopen(path, "wb");
if (!fp) {
    return 0;
}
fwrite(Data, 1, Size, fp);
fclose(fp);
char *target_argv[] = { (char *)"sentinel_original_main", (char *)path, NULL };
sentinel_original_main(2, target_argv);
""".strip()

    if argument_model == "int_flag":
        return f"""
/*
 * Non-zero input triggers the vulnerable flag branch.
 */
int flag = (Size > 0 && Data[0] != 0) ? 1 : 0;
{function}(flag);
""".strip()

    if argument_model == "const_char_ptr":
        return f"""
/*
 * Make a null-terminated string from fuzzer bytes.
 */
char *buf = (char *)malloc(Size + 1);
if (!buf) {{
    return 0;
}}
memcpy(buf, Data, Size);
buf[Size] = '\\0';

{function}((const char *)buf);

free(buf);
""".strip()

    return f"""
/*
 * TODO: Convert Data/Size into parameters for {function}.
 */
(void)Data;
(void)Size;
""".strip()


def make_makefile(finding, strategy, project_root=None, build_profile=None):
    target_file = finding.get("file")
    if project_root:
        target_src = str((project_root / target_file).resolve()).replace("\\", "/")
    else:
        target_src = f"../../samples/vulnerable_project/{target_file}"

    build_profile = build_profile or {}
    include_dirs = build_profile.get("include_dirs") or []
    source_entries = list(build_profile.get("source_entries") or [])
    target_relpath = build_profile.get("target_relpath") or target_file
    main_source_relpaths = set(build_profile.get("main_source_relpaths") or [])
    replay_original_main = strategy.get("argument_model") == "original_main_file_arg"

    if source_entries:
        filtered_entries = []
        for entry in source_entries:
            src = entry["src"]
            if replay_original_main:
                # Replay the target through the project's real entry point. A
                # finding often lives in a helper translation unit while main()
                # is defined in src/main.c, so both files are required. Keep
                # unrelated sources out to avoid optional SDKs and duplicate
                # renamed entry points.
                replay_main = None
                if target_relpath not in main_source_relpaths:
                    replay_main = next(iter(sorted(main_source_relpaths)), None)
                if src == target_relpath or src == replay_main:
                    filtered_entries.append(entry)
                continue
            # 只保留目标文件本身，排除其他带main的文件
            if src == target_relpath:
                filtered_entries.append(entry)
            elif src not in main_source_relpaths:
                # 保留不含main的辅助文件（库函数、头文件实现等）
                filtered_entries.append(entry)
        source_entries = filtered_entries
    include_flags = " ".join(f"-I$(TARGET_ROOT)/{inc}" for inc in include_dirs if inc and inc != ".")
    project_objects = " ".join(entry["obj"] for entry in source_entries) if source_entries else "target_asan.o"

    asan_rules = []
    afl_rules = []
    libfuzzer_rules = []
    for entry in source_entries:
        src = entry["src"]
        obj = entry["obj"]
        asan_obj = obj
        afl_obj = obj.replace(".o", ".afl.o")
        libfuzzer_obj = obj.replace(".o", ".fuzz.o")
        src_path = f"$(TARGET_ROOT)/{src}"
        rename_main_for_this_source = src in main_source_relpaths
        if rename_main_for_this_source:
            asan_rules.append(f"{asan_obj}:\n\t$(CC) $(COMMON_FLAGS) $(TARGET_RENAME_MAIN) -c {src_path} -o {asan_obj}")
            afl_rules.append(f"{afl_obj}:\n\t$(AFL_CC) $(COMMON_FLAGS) $(TARGET_RENAME_MAIN) -c {src_path} -o {afl_obj}")
            libfuzzer_rules.append(f"{libfuzzer_obj}:\n\t$(CC) -g -O0 -fsanitize=fuzzer-no-link,address $(TARGET_RENAME_MAIN) -c {src_path} -o {libfuzzer_obj}")
        else:
            asan_rules.append(f"{asan_obj}:\n\t$(CC) $(COMMON_FLAGS) -c {src_path} -o {asan_obj}")
            afl_rules.append(f"{afl_obj}:\n\t$(AFL_CC) $(COMMON_FLAGS) -c {src_path} -o {afl_obj}")
            libfuzzer_rules.append(f"{libfuzzer_obj}:\n\t$(CC) -g -O0 -fsanitize=fuzzer-no-link,address -c {src_path} -o {libfuzzer_obj}")

    asan_objects = " ".join(entry["obj"] for entry in source_entries) if source_entries else "target_asan.o"
    afl_objects = " ".join(entry["obj"].replace(".o", ".afl.o") for entry in source_entries) if source_entries else "target_afl.o"
    fuzz_objects = " ".join(entry["obj"].replace(".o", ".fuzz.o") for entry in source_entries) if source_entries else "target_libfuzzer.o"

    return f"""
# SENTINEL Agent D generated Makefile - Part 4.1
#
# This Makefile fixes the -Dmain problem:
# - target source is compiled with -Dmain=sentinel_original_main
# - harness source is compiled without -Dmain
#
# Linux / WSL2 / Docker recommended.

TARGET_SRC ?= {target_src}
TARGET_ROOT ?= /sentinel-work/target
CC ?= clang
AFL_CC ?= afl-clang

COMMON_FLAGS ?= -g -O0 -fsanitize=address -fno-omit-frame-pointer {include_flags}
TARGET_RENAME_MAIN ?= -Dmain=sentinel_original_main
PROJECT_OBJECTS ?= {project_objects}

.PHONY: all asan afl libfuzzer clean run-asan run-afl

all: asan

{chr(10).join(asan_rules)}

harness_asan.o:
\t$(CC) $(COMMON_FLAGS) -c afl_harness.c -o harness_asan.o

asan: {asan_objects} harness_asan.o
\t$(CC) $(COMMON_FLAGS) harness_asan.o {asan_objects} -o asan_target

{chr(10).join(afl_rules)}

harness_afl.o:
\t$(AFL_CC) $(COMMON_FLAGS) -c afl_harness.c -o harness_afl.o

afl: {afl_objects} harness_afl.o
\t$(AFL_CC) $(COMMON_FLAGS) harness_afl.o {afl_objects} -o afl_target

{chr(10).join(libfuzzer_rules)}

harness_libfuzzer.o:
\t$(CC) -g -O0 -fsanitize=fuzzer-no-link,address -c libfuzzer_harness.c -o harness_libfuzzer.o

libfuzzer: {fuzz_objects} harness_libfuzzer.o
\t$(CC) -g -O0 -fsanitize=fuzzer,address harness_libfuzzer.o {fuzz_objects} -o libfuzzer_target

run-asan: asan
\t./asan_target seeds/seed_001.bin

run-afl: afl
\tafl-fuzz -i seeds -o findings -- ./afl_target @@

clean:
\trm -f *.o *.afl.o *.fuzz.o asan_target afl_target libfuzzer_target
\trm -rf findings/default findings/*/queue findings/*/crashes findings/*/hangs
""".strip() + "\n"


def write_seed_files(seeds_dir, finding, strategy, project_root=None):
    """Generate seeds for fuzzing. Priority: LLM > project seeds > hardcoded."""
    cwe = finding.get("cwe_id")
    argument_model = strategy.get("argument_model")

    # Try LLM-generated seeds first
    llm_client = LLMClient()
    if llm_client.is_available():
        try:
            llm_seeds = generate_seeds_with_llm(finding, strategy, project_root)
            if llm_seeds:
                seed_files = []
                for name, content in llm_seeds.items():
                    path = seeds_dir / name
                    path.write_bytes(content)
                    seed_files.append(str(path))
                return seed_files
        except Exception as e:
            print(f"[Agent-E] LLM seed generation failed: {e}, falling back to rules")

    # Fallback: project seeds
    if argument_model == "original_main_file_arg" and project_root:
        imported = import_project_seed_files(seeds_dir, project_root)
        if imported:
            return imported

    # Fallback: hardcoded CWE-specific seeds (增强版)
    if cwe in BUFFER_OVERFLOW_CWES:
        seeds = {
            "seed_001.bin": b"A" * 16,           # 小size触发边界检查
            "seed_002.bin": b"B" * 128,          # 中等size
            "seed_003.bin": b"C" * 256,          # 接近常见buffer大小
            "seed_004.bin": b"D" * 512,          # 更大size
            "seed_005_pattern.bin": (b"0123456789abcdef" * 16),  # 有结构的数据
            "seed_006_nulls.bin": b"\x00" * 100,  # 含null字节
        }
    elif cwe == "CWE-134":
        seeds = {
            "seed_001.bin": b"%x.%x.%x.%x",
            "seed_002_pointer_leak.bin": b"%p %p %p %p",
            "seed_003_write_probe.bin": b"%n%n%n%n",
            "seed_004_fmt_prefix_leak.bin": b"FMT:%x.%x.%x.%x",
            "seed_005_fmt_prefix_pointer.bin": b"FMT:%p %p %p %p",
        }
    elif cwe in {"CWE-416", "CWE-415"}:
        seeds = {
            "seed_001.bin": b"\x01",
            "seed_002_trigger_flag.bin": b"trigger=1",
            "seed_003_nonzero.bin": b"\xff"
        }
    else:
        seeds = {
            "seed_001.bin": b"default_seed"
        }

    seed_files = []
    for name, content in seeds.items():
        path = seeds_dir / name
        path.write_bytes(content)
        seed_files.append(str(path))

    return seed_files


def import_project_seed_files(seeds_dir, project_root, limit=8):
    project_root = Path(project_root)
    candidates = []
    for rel_dir in ("seeds", "seed", "corpus", "samples"):
        seed_root = project_root / rel_dir
        if not seed_root.is_dir():
            continue
        for file_path in sorted(seed_root.rglob("*")):
            if file_path.is_file():
                candidates.append(file_path)
    if not candidates:
        return []

    imported = []
    for idx, src in enumerate(candidates[:limit], start=1):
        name = src.name
        if not name:
            suffix = src.suffix or ".bin"
            name = f"seed_{idx:03d}{suffix}"
        dest = seeds_dir / name
        shutil.copyfile(src, dest)
        imported.append(str(dest))
    return imported


def make_readme(finding, strategy):
    return f"""
# SENTINEL Harness Package

## Finding

- Finding ID: `{finding.get("finding_id")}`
- Target file: `{finding.get("file")}`
- Target function: `{finding.get("function")}`
- CWE: `{finding.get("cwe_id")}`
- Vulnerability type: `{finding.get("vulnerability_type")}`
- Line range: `{finding.get("line_range")}`

## Trigger condition

{finding.get("trigger_condition", "")}

## Strategy

- Strategy name: `{strategy.get("strategy_name")}`
- Argument model: `{strategy.get("argument_model")}`
- Expected sanitizer: `{strategy.get("expected_sanitizer")}`
- Expected symptom: `{strategy.get("expected_symptom")}`

## Commands in WSL2 / Docker

```bash
make clean
make asan
make run-asan
```

Optional:

```bash
make afl
make run-afl
```

```bash
make libfuzzer
./libfuzzer_target seeds
```

## Notes

Part 4.1 compiles the target source and harness separately.
Only the target source receives `-Dmain=sentinel_original_main`, so the harness main function remains valid.
""".strip() + "\n"


def count_by_cwe(packages):
    result = {}
    for pkg in packages:
        cwe = pkg.get("cwe_id", "UNKNOWN")
        result[cwe] = result.get(cwe, 0) + 1
    return result


def indent(text, spaces):
    prefix = " " * spaces
    return "\n".join(prefix + line if line.strip() else line for line in text.splitlines())


def generate_seeds_with_llm(finding, strategy, project_root=None):
    """
    Use LLM to generate targeted seed files based on vulnerability context.
    Returns dict {filename: bytes_content} or None on failure.
    """
    llm = LLMClient()

    # Read vulnerable code snippet if available
    code_snippet = ""
    if project_root and finding.get("file"):
        try:
            vuln_file = Path(project_root) / finding["file"]
            if vuln_file.exists():
                code_snippet = vuln_file.read_text(encoding="utf-8", errors="replace")[:2000]
        except Exception:
            pass

    prompt = f"""You are a security fuzzing expert. Generate AFL++ seed files to trigger the following vulnerability.

**Vulnerability Details:**
- Type: {finding.get('vulnerability_type')}
- CWE: {finding.get('cwe_id')}
- Function: {finding.get('function')}
- File: {finding.get('file')}
- Line: {finding.get('line_range')}
- Trigger Condition: {finding.get('trigger_condition', 'N/A')}

**Code Snippet:**
```c
{code_snippet[:800] if code_snippet else 'Not available'}
```

**Input Strategy:**
- Argument Model: {strategy.get('argument_model')}
- Entry Point: {strategy.get('entry_point')}

**Task:**
Generate 3-5 seed files that are most likely to trigger this vulnerability. Consider:
1. Input format expected by the function
2. Boundary conditions that violate constraints
3. Special values that bypass validation

Return JSON format:
{{
  "seeds": [
    {{"name": "seed_001_baseline.bin", "content_hex": "41414141...", "description": "Basic trigger"}},
    {{"name": "seed_002_boundary.bin", "content_hex": "42424242...", "description": "Boundary case"}},
    ...
  ]
}}

IMPORTANT:
- content_hex must be valid hexadecimal (0-9a-f)
- For buffer overflow (CWE-120/121/122): generate long strings (256-1024 bytes)
- For format string (CWE-134): use %x, %p, %n patterns
- For UAF/double-free (CWE-416/415): use trigger flags like 0x01
- Adapt to the actual input parsing logic shown in code"""

    try:
        response = llm.chat([{"role": "user", "content": prompt}], temperature=0.3)
        data = extract_json_object(response)

        seeds = {}
        for item in data.get("seeds", [])[:5]:
            name = item.get("name", "seed.bin")
            hex_content = item.get("content_hex", "").replace(" ", "").replace("\n", "")

            # Validate hex and convert to bytes
            if not hex_content or not all(c in "0123456789abcdefABCDEF" for c in hex_content):
                continue
            if len(hex_content) % 2 != 0:
                hex_content = "0" + hex_content

            seeds[name] = bytes.fromhex(hex_content)

        return seeds if seeds else None

    except Exception as e:
        print(f"[Agent-E] LLM seed generation error: {e}")
        return None
