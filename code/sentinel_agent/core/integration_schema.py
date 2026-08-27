"""
Backend integration schema adapters for SENTINEL agent outputs.

The agent pipeline keeps rich research-oriented structures internally. These
helpers expose the flatter JSON shapes required by sentinel_backend's
INTEGRATION_GUIDE.md without breaking the existing report flow.
"""


SEVERITY_VALUES = {"critical", "high", "medium", "low", "unknown"}

CWE_TO_BACKEND_VULN_TYPE = {
    "CWE-416": "use_after_free",
    "CWE-415": "double_free",
    "CWE-120": "buffer_overflow",
    "CWE-122": "buffer_overflow",
    "CWE-121": "buffer_overflow",
}

VULN_TYPE_DISPLAY = {
    "use_after_free": "Use After Free",
    "double_free": "Double Free",
    "buffer_overflow": "Buffer Overflow",
}


def severity_from_risk(risk):
    risk = str(risk or "unknown").lower()
    return risk if risk in SEVERITY_VALUES else "unknown"


def cvss_from_vulnerability(vuln):
    score = vuln.get("severity_score")
    if score is None:
        score = vuln.get("cvss_score")
    try:
        return float(score) if score is not None else None
    except Exception:
        return None


def nvd_url_from_vulnerability(vuln):
    cve_id = vuln.get("cve_id") or vuln.get("id")
    if cve_id and str(cve_id).startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    refs = vuln.get("references") or []
    return refs[0] if refs else None


def to_backend_components(agent_a_result):
    """
    Convert Agent A's rich component records into backend ComponentRisk rows.

    If a component has no matched CVE/OSV item, we still emit one row with
    unknown severity so the backend can show that the component was detected.
    """
    rows = []
    for comp in agent_a_result.get("components", []):
        vulns = comp.get("matched_vulnerabilities") or comp.get("matched_cves") or []

        if not vulns:
            rows.append({
                "library_name": comp.get("library_name") or comp.get("name"),
                "version": comp.get("version", "unknown"),
                "cve_id": None,
                "cvss_score": None,
                "severity": severity_from_risk(comp.get("risk_level")),
                "description": "Component detected; no version-matched OSV vulnerability was returned.",
                "nvd_url": None,
            })
            continue

        for vuln in vulns:
            rows.append({
                "library_name": comp.get("library_name") or comp.get("name"),
                "version": comp.get("version", "unknown"),
                "cve_id": vuln.get("cve_id") or vuln.get("id"),
                "cvss_score": cvss_from_vulnerability(vuln),
                "severity": severity_from_risk(vuln.get("risk_level")),
                "description": vuln.get("summary") or vuln.get("details") or "",
                "nvd_url": nvd_url_from_vulnerability(vuln),
            })

    return {"components": rows}


def _finding_semantic_text(finding):
    parts = [
        finding.get("vulnerability_type"),
        finding.get("cwe_id"),
        finding.get("trigger_condition"),
        finding.get("code_context"),
        finding.get("suggested_fix"),
        finding.get("function"),
    ]
    evidence = finding.get("evidence") or []
    if isinstance(evidence, list):
        parts.extend(evidence)
    else:
        parts.append(evidence)
    return " ".join(str(part) for part in parts if part).lower()


def _has_uaf_signal(text):
    compact = text.replace("-", " ").replace("_", " ")
    return (
        "cwe 416" in compact
        or "use after free" in compact
        or "uaf" in compact
        or "after free" in compact
        or "uses" in compact and "after free" in compact
        or "freed" in compact and ("used again" in compact or "reused" in compact or "dereference" in compact)
        or "释放后" in text and "使用" in text
    )


def _has_double_free_signal(text):
    compact = text.replace("-", " ").replace("_", " ")
    return (
        "cwe 415" in compact
        or "double free" in compact
        or "freed again" in compact
        or "free twice" in compact
        or "重复释放" in text
    )


def to_backend_vuln_type(finding):
    cwe = finding.get("cwe_id")
    semantic_text = _finding_semantic_text(finding)
    if _has_double_free_signal(semantic_text):
        return "double_free"
    if _has_uaf_signal(semantic_text):
        return "use_after_free"

    raw = str(finding.get("vulnerability_type") or "unknown").lower()
    if cwe in {"CWE-120", "CWE-121", "CWE-122"} or "overflow" in raw:
        return "buffer_overflow"
    return CWE_TO_BACKEND_VULN_TYPE.get(cwe, raw.replace(" ", "_"))


def code_context_from_finding(finding):
    evidence = finding.get("evidence") or []
    if evidence:
        return "\n".join(str(item) for item in evidence[:6])
    return finding.get("code_context") or ""


def to_backend_vulnerabilities(agent_c_result):
    rows = []
    for finding in agent_c_result.get("static_findings", []):
        line_range = finding.get("line_range") or [None, None]
        line_number = line_range[0] if isinstance(line_range, list) and line_range else None
        vuln_type = to_backend_vuln_type(finding)
        rows.append({
            "vuln_type": vuln_type,
            "vuln_type_display": VULN_TYPE_DISPLAY.get(vuln_type, finding.get("vulnerability_type", "Unknown")),
            "file_path": finding.get("file"),
            "line_number": line_number,
            "code_context": code_context_from_finding(finding),
            "trigger_cond": finding.get("trigger_condition", ""),
            "fix_advice": finding.get("suggested_fix", ""),
            "confidence": finding.get("confidence"),
            "source_slice_id": finding.get("source_slice_id"),
            "hypothesis_id": finding.get("hypothesis_id"),
            "finding_id": finding.get("finding_id"),
            "trace_summary": " -> ".join(finding.get("cross_function_trace") or finding.get("dataflow_trace") or []),
            "dynamic_status": finding.get("dynamic_status", "untriggered"),
            "final_status": finding.get("final_status", "need_review"),
        })
    return {"vulnerabilities": rows}
