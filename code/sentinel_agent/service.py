import base64
import os
import sys
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

AGENT_ROOT = Path(__file__).resolve().parent


def _allowed_source_roots() -> list[Path]:
    raw = os.environ.get("AGENT_ALLOWED_SOURCE_ROOTS", "").strip()
    return [Path(item).resolve() for item in raw.split(",") if item.strip()]


def _resolve_source_root(value: str) -> Path:
    source_root = Path(value).resolve()
    if not source_root.is_dir():
        raise HTTPException(status_code=400, detail=f"source_root is not a directory: {source_root}")

    allowed_roots = _allowed_source_roots()
    if allowed_roots:
        try:
            allowed = any(source_root == root or source_root.is_relative_to(root) for root in allowed_roots)
        except OSError:
            allowed = False
        if not allowed:
            raise HTTPException(status_code=403, detail="source_root is outside configured allowed roots")
    return source_root
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from agents.agent_a_dependency import run_agent_a
from agents.agent_b_slicer import run_agent_b
from agents.agent_c_hypothesis import run_agent_c
from agents.agent_d_harness import run_agent_d as run_agent_e
from agents.agent_d_llm_audit import run_agent_d
from agents.agent_f_dynamic_evidence import run_agent_f
from agents.agent_g_final_report import run_agent_g
from core.file_scanner import scan_project_metadata_files, scan_source_files
from core.integration_schema import to_backend_components, to_backend_vulnerabilities
from core.llm_client import LLMClient


class AgentARequest(BaseModel):
    source_root: str | None = None
    dep_files: list[dict[str, Any]] = Field(default_factory=list)
    includes: list[str] = Field(default_factory=list)
    cpp_files: list[str] = Field(default_factory=list)


class AgentBAuditRequest(BaseModel):
    source_root: str
    cpp_files: list[str] = Field(default_factory=list)
    target_vulns: list[str] = Field(default_factory=list)
    generate_harness: bool = True
    dependency_components: list[dict[str, Any]] = Field(default_factory=list)


app = FastAPI(
    title="SENTINEL ML Agent Service",
    version="1.0.0",
    description="Seven-agent ML service for dependency CVE analysis, slicing, hypothesis generation, audit, harness generation, evidence attribution, and final reporting.",
)


@app.get("/health")
def health():
    llm_client = LLMClient()
    return {
        "status": "ok",
        "service": "sentinel-ml-agent",
        "version": "1.0.0",
        "llm_configured": llm_client.is_available(),
        "llm_mode": "configured" if llm_client.is_available() else "rule_fallback_only",
    }


@app.post("/api/agent-a/analyze")
def analyze_dependencies(request: AgentARequest):
    source_files, metadata_files = load_agent_a_inputs(request)
    result = run_agent_a(source_files, metadata_files)
    backend_components = to_backend_components(result)["components"]
    return {
        "components": backend_components,
        "summary": result.get("summary", {}),
        "agent_a": result,
    }


@app.post("/api/agent-b/audit")
def audit_source(request: AgentBAuditRequest):
    source_root = _resolve_source_root(request.source_root)

    run_id = uuid.uuid4().hex[:12]
    output_dir = AGENT_ROOT / "outputs" / f"service_{run_id}"
    harness_dir = AGENT_ROOT / "harness_packages" / f"service_{run_id}"

    source_files = scan_source_files(str(source_root))
    metadata_files = scan_project_metadata_files(str(source_root))

    if request.dependency_components:
        agent_a_result = dependency_context_to_agent_a(request.dependency_components)
    else:
        agent_a_result = run_agent_a(source_files, metadata_files)
    agent_b_result = run_agent_b(source_files)
    agent_c_result = run_agent_c(agent_a_result, agent_b_result)
    agent_d_result = run_agent_d(agent_a_result, agent_b_result, agent_c_result)
    filter_findings_by_target_vulns(agent_d_result, request.target_vulns)

    if request.generate_harness:
        agent_e_result = run_agent_e(agent_d_result, harness_root=harness_dir, project_root=source_root)
        embed_harness_package_files(agent_e_result)
    else:
        agent_e_result = {
            "agent": "Agent E - Harness Builder and Fixer Agent",
            "harness_packages": [],
            "summary": {"total_packages": 0, "packages_by_cwe": {}},
        }

    agent_f_result = run_agent_f(
        agent_d_result=agent_d_result,
        agent_e_result=agent_e_result,
        afl_result={"crash_found": False},
        ebpf_log={"events": []},
        asan_result={},
    )

    agent_g_result = run_agent_g(
        project_name=source_root.name,
        agent_a_result=agent_a_result,
        agent_b_result=agent_b_result,
        agent_c_result=agent_c_result,
        agent_d_result=agent_d_result,
        agent_e_result=agent_e_result,
        agent_f_result=agent_f_result,
        output_dir=output_dir,
    )
    final_report = agent_g_result["final_report"]

    backend_vulns = final_report.get("backend_vulnerabilities") or to_backend_vulnerabilities(agent_d_result)["vulnerabilities"]
    llm_client = LLMClient()
    return {
        "vulnerabilities": backend_vulns,
        "summary": {
            "components": agent_a_result.get("summary", {}),
            "slices": agent_b_result.get("summary", {}),
            "hypotheses": agent_c_result.get("summary", {}),
            "findings": agent_d_result.get("summary", {}),
            "harness": agent_e_result.get("summary", {}),
            "evidence": agent_f_result.get("summary", {}),
            "overall_risk": final_report.get("overall_risk"),
            "llm": {
                "configured": llm_client.is_available(),
                "mode": agent_d_result.get("audit_mode", "rule_fallback_only"),
            },
        },
        "artifacts": {
            "output_dir": str(output_dir),
            "harness_dir": str(harness_dir),
            "final_report_json": str(output_dir / "final_report.json"),
            "final_report_md": str(output_dir / "final_report.md"),
        },
        "agent_a": agent_a_result,
        "agent_b": agent_b_result,
        "agent_c": agent_c_result,
        "agent_d": agent_d_result,
        "agent_e": agent_e_result,
        "agent_f": agent_f_result,
        "agent_g": agent_g_result,
        "final_report": final_report,
    }


def dependency_context_to_agent_a(components: list[dict[str, Any]]) -> dict[str, Any]:
    """Rehydrate the persisted Agent A context for the static chain.

    This prevents the combined audit endpoint from repeating OSV/NVD requests
    that the dedicated dependency stage already completed.
    """
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in components:
        name = str(item.get("library_name") or "unknown")
        version = str(item.get("version") or "unknown")
        component = grouped.setdefault(
            (name, version),
            {
                "library_name": name,
                "version": version,
                "risk_level": item.get("severity") or "unknown",
                "matched_vulnerabilities": [],
            },
        )
        if item.get("cve_id"):
            component["matched_vulnerabilities"].append(
                {
                    "cve_id": item.get("cve_id"),
                    "cvss_score": item.get("cvss_score"),
                    "severity_score": item.get("cvss_score"),
                    "risk_level": item.get("severity") or "unknown",
                    "summary": item.get("description") or "",
                    "references": [item["nvd_url"]] if item.get("nvd_url") else [],
                }
            )
    values = list(grouped.values())
    return {
        "agent": "Agent A - persisted dependency context",
        "components": values,
        "summary": {
            "total_components": len(values),
            "context_reused": True,
        },
    }


def load_agent_a_inputs(request: AgentARequest):
    if request.source_root:
        source_root = _resolve_source_root(request.source_root)
        return scan_source_files(str(source_root)), scan_project_metadata_files(str(source_root))

    source_files = synthetic_source_files(request.includes, request.cpp_files)
    metadata_files = normalize_dep_files(request.dep_files)
    return source_files, metadata_files


def synthetic_source_files(includes, cpp_files):
    include_lines = [f"#include <{header}>" for header in includes]
    content = "\n".join(include_lines)
    if not content and cpp_files:
        content = "\n".join(f"/* {path} */" for path in cpp_files)
    return [{
        "absolute_path": "<request:includes>",
        "relative_path": cpp_files[0] if cpp_files else "request_includes.c",
        "suffix": ".c",
        "content": content,
        "lines": content.splitlines(),
    }]


def normalize_dep_files(dep_files):
    normalized = []
    for idx, item in enumerate(dep_files or [], start=1):
        name = item.get("name") or item.get("filename") or Path(str(item.get("path", f"dep_{idx}"))).name
        rel = item.get("relative_path") or item.get("path") or name
        content = item.get("content") or ""
        normalized.append({
            "absolute_path": item.get("absolute_path") or f"<request:{rel}>",
            "relative_path": rel,
            "name": name,
            "content": content,
            "lines": content.splitlines(),
        })
    return normalized


def filter_findings_by_target_vulns(agent_c_result, target_vulns):
    if not target_vulns:
        return
    targets = set()
    for item in target_vulns:
        targets.update(expand_target_vuln_aliases(item))
    targets.discard("")
    if not targets:
        return

    filtered = []
    for finding in agent_c_result.get("static_findings", []):
        finding_keys = set()
        for value in (
            finding.get("cwe_id", ""),
            finding.get("vulnerability_type", ""),
            finding.get("vuln_type", ""),
        ):
            finding_keys.update(expand_target_vuln_aliases(value))
        if finding_keys & targets:
            filtered.append(finding)

    agent_c_result["static_findings"] = filtered
    agent_c_result["vulnerabilities"] = to_backend_vulnerabilities(agent_c_result)["vulnerabilities"]
    agent_c_result["integration"] = {"vulnerabilities": agent_c_result["vulnerabilities"]}
    agent_c_result["summary"]["total_findings"] = len(filtered)
    agent_c_result["summary"]["high_risk_findings"] = sum(
        1 for f in filtered if f.get("risk_level") in {"high", "critical"}
    )


def normalize_target_vuln(value):
    return str(value or "").strip().lower().replace("_", "-").replace(" ", "-")


def expand_target_vuln_aliases(value):
    normalized = normalize_target_vuln(value)
    aliases = {
        "uaf": {"uaf", "use-after-free", "use-after-free-suspected", "cwe-416"},
        "use-after-free": {"uaf", "use-after-free", "use-after-free-suspected", "cwe-416"},
        "use-after-free-suspected": {"uaf", "use-after-free", "use-after-free-suspected", "cwe-416"},
        "cwe-416": {"uaf", "use-after-free", "use-after-free-suspected", "cwe-416"},
        "double-free": {"double-free", "double-free-suspected", "cwe-415"},
        "double-free-suspected": {"double-free", "double-free-suspected", "cwe-415"},
        "cwe-415": {"double-free", "double-free-suspected", "cwe-415"},
        "buffer-overflow": {"buffer-overflow", "heap-overflow", "heap-buffer-overflow", "possible-buffer-overflow", "stack-overflow", "stack-buffer-overflow", "cwe-120", "cwe-121", "cwe-122"},
        "cwe-120": {"buffer-overflow", "heap-overflow", "heap-buffer-overflow", "possible-buffer-overflow", "stack-overflow", "stack-buffer-overflow", "cwe-120", "cwe-121", "cwe-122"},
        "heap-overflow": {"buffer-overflow", "heap-overflow", "heap-buffer-overflow", "possible-buffer-overflow", "cwe-120", "cwe-122"},
        "heap-buffer-overflow": {"buffer-overflow", "heap-overflow", "heap-buffer-overflow", "possible-buffer-overflow", "cwe-120", "cwe-122"},
        "possible-buffer-overflow": {"buffer-overflow", "heap-overflow", "heap-buffer-overflow", "possible-buffer-overflow", "cwe-120", "cwe-122"},
        "cwe-122": {"buffer-overflow", "heap-overflow", "heap-buffer-overflow", "possible-buffer-overflow", "cwe-120", "cwe-122"},
        "stack-overflow": {"buffer-overflow", "stack-overflow", "stack-buffer-overflow", "cwe-120", "cwe-121"},
        "stack-buffer-overflow": {"buffer-overflow", "stack-overflow", "stack-buffer-overflow", "cwe-120", "cwe-121"},
        "cwe-121": {"buffer-overflow", "stack-overflow", "stack-buffer-overflow", "cwe-120", "cwe-121"},
        "format-string": {"format-string", "format-string-vulnerability", "cwe-134"},
        "format-string-vulnerability": {"format-string", "format-string-vulnerability", "cwe-134"},
        "cwe-134": {"format-string", "format-string-vulnerability", "cwe-134"},
    }
    return aliases.get(normalized, {normalized})


def embed_harness_package_files(agent_e_result: dict[str, Any]) -> None:
    """
    Include generated harness package contents in the HTTP response.

    In Docker deployment the agent container and backend worker do not share the
    agent's harness directory, so returning only filesystem paths is not enough
    for the dynamic verification stage.
    """
    for package in agent_e_result.get("harness_packages", []):
        package_dir = Path(str(package.get("package_dir", "")))
        files: dict[str, str] = {}
        seeds: dict[str, str] = {}

        for name in ("afl_harness.c", "libfuzzer_harness.c", "Makefile", "README.md", "harness_config.json"):
            path = package_dir / name
            if path.is_file():
                files[name] = path.read_text(encoding="utf-8", errors="replace")

        seeds_dir = package_dir / "seeds"
        if seeds_dir.is_dir():
            for seed_path in sorted(seeds_dir.iterdir()):
                if seed_path.is_file():
                    seeds[seed_path.name] = base64.b64encode(seed_path.read_bytes()).decode("ascii")

        package["embedded_files"] = files
        package["embedded_seed_files_b64"] = seeds
