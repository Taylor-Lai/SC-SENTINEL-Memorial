from pathlib import Path

from core.integration_schema import to_backend_components, to_backend_vulnerabilities
from core.json_utils import save_json
from core.risk_level import max_risk


def run_agent_g(project_name, agent_a_result, agent_b_result, agent_c_result,
                agent_d_result, agent_e_result, agent_f_result, output_dir="outputs"):
    evidence_by_finding = {
        item.get("finding_id"): item
        for item in agent_f_result.get("evidence_links", [])
    }
    packages_by_finding = {
        pkg.get("finding_id"): pkg
        for pkg in agent_e_result.get("harness_packages", [])
    }
    hypotheses_by_id = {
        hyp.get("hypothesis_id"): hyp
        for hyp in agent_c_result.get("hypotheses", [])
    }

    final_findings = []
    for finding in agent_d_result.get("static_findings", []):
        evidence_link = evidence_by_finding.get(finding.get("finding_id"), {})
        package = packages_by_finding.get(finding.get("finding_id"))
        hypothesis = hypotheses_by_id.get(finding.get("hypothesis_id"))
        final_findings.append({
            **finding,
            "dynamic_status": evidence_link.get("dynamic_status", "untriggered"),
            "evidence_level": evidence_link.get("evidence_level", "weak"),
            "dynamic_evidence_sources": evidence_link.get("evidence_sources", []),
            "asan_evidence": evidence_link.get("matched_asan"),
            "afl_evidence": evidence_link.get("matched_afl"),
            "ebpf_evidence": evidence_link.get("matched_ebpf", []),
            "package_id": package.get("package_id") if package else None,
            "trace": build_trace(finding, hypothesis, package, evidence_link),
            "trace_summary": build_trace_summary(finding, hypothesis, package, evidence_link),
            "final_status": final_status(evidence_link.get("dynamic_status", "untriggered")),
            "final_conclusion": conclusion(
                evidence_link.get("dynamic_status", "untriggered"),
                evidence_link.get("evidence_level", "weak"),
                evidence_link.get("evidence_sources", []),
            )
        })

    dependency_only_risks = [
        comp for comp in agent_a_result.get("components", [])
        if comp.get("risk_level") in {"critical", "high"} and not comp.get("matched_vulnerabilities") == []
    ]

    overall_risk = "unknown"
    for comp in agent_a_result.get("components", []):
        overall_risk = max_risk(overall_risk, comp.get("risk_level"))
    for finding in final_findings:
        overall_risk = max_risk(overall_risk, finding.get("risk_level"))

    report = {
        "agent": "Agent G - Final Risk Decision and Report Agent",
        "project_name": project_name,
        "status": "completed",
        "overall_risk": overall_risk,
        "summary": {
            "total_components": len(agent_a_result.get("components", [])),
            "total_slices": len(agent_b_result.get("slices", [])),
            "total_hypotheses": len(agent_c_result.get("hypotheses", [])),
            "total_static_findings": len(agent_d_result.get("static_findings", [])),
            "total_harness_packages": len(agent_e_result.get("harness_packages", [])),
            "confirmed_findings": sum(1 for f in final_findings if f["dynamic_status"] == "confirmed"),
            "need_review_findings": sum(1 for f in final_findings if f["dynamic_status"] == "need_review"),
            "untriggered_findings": sum(1 for f in final_findings if f["dynamic_status"] == "untriggered"),
            "dependency_risk_only": len(dependency_only_risks),
            "asan_confirmed_findings": sum(
                1 for f in final_findings
                if (f.get("asan_evidence") or {}).get("dynamic_status") == "confirmed"
            ),
            "llm_mode": agent_d_result.get("audit_mode", "rule_fallback_only"),
            "llm_available": agent_d_result.get("summary", {}).get("llm_available", False),
        },
        "component_risks": agent_a_result.get("components", []),
        "dependency_risk_only": dependency_only_risks,
        "hypotheses": agent_c_result.get("hypotheses", []),
        "final_findings": final_findings,
        "backend_components": to_backend_components(agent_a_result)["components"],
        "backend_vulnerabilities": to_backend_vulnerabilities({"static_findings": final_findings})["vulnerabilities"],
        "recommendations": [
            "Prioritize findings confirmed by ASan/AFL++/eBPF runtime evidence.",
            "Review high-risk dependency CVEs before release.",
            "Use generated harness packages as reproducible validation artifacts.",
            "Treat untriggered high-confidence findings as review candidates, not confirmed vulnerabilities.",
            "Do not interpret ordinary allocator or free activity as eBPF confirmation unless the event carries an explicit strong-signal marker.",
        ],
        "agent_summaries": {
            "agent_a": agent_a_result.get("summary", {}),
            "agent_b": agent_b_result.get("summary", {}),
            "agent_c": agent_c_result.get("summary", {}),
            "agent_d": agent_d_result.get("summary", {}),
            "agent_e": agent_e_result.get("summary", {}),
            "agent_f": agent_f_result.get("summary", {}),
        }
    }

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    save_json(report, output_dir / "final_report.json")
    (output_dir / "final_report.md").write_text(to_markdown(report), encoding="utf-8")

    return {
        "agent": "Agent G - Final Risk Decision and Report Agent",
        "final_report": report,
        "summary": report["summary"],
    }


def build_trace(finding, hypothesis, package, evidence_link):
    return {
        "source_slice_id": finding.get("source_slice_id"),
        "hypothesis_id": finding.get("hypothesis_id"),
        "finding_id": finding.get("finding_id"),
        "package_id": package.get("package_id") if package else None,
        "dynamic_status": evidence_link.get("dynamic_status", "untriggered"),
        "evidence_sources": evidence_link.get("evidence_sources", []),
        "hypothesis_reason": (hypothesis or {}).get("reason"),
        "cross_function_trace": finding.get("cross_function_trace") or (hypothesis or {}).get("cross_function_trace", []),
        "dataflow_trace": finding.get("dataflow_trace") or (hypothesis or {}).get("dataflow_trace", []),
    }


def build_trace_summary(finding, hypothesis, package, evidence_link):
    pieces = [
        f"slice={finding.get('source_slice_id')}",
        f"hypothesis={finding.get('hypothesis_id')}",
        f"finding={finding.get('finding_id')}",
    ]
    if package:
        pieces.append(f"harness={package.get('package_id')}")
    pieces.append(f"dynamic={evidence_link.get('dynamic_status', 'untriggered')}")
    trace = finding.get("cross_function_trace") or (hypothesis or {}).get("cross_function_trace", [])
    if trace:
        pieces.append("trace=" + " | ".join(trace[:3]))
    return " -> ".join(pieces)


def final_status(dynamic_status):
    if dynamic_status == "confirmed":
        return "confirmed"
    if dynamic_status == "need_review":
        return "need_review"
    return "untriggered"


def conclusion(dynamic_status, evidence_level, evidence_sources):
    source_text = ", ".join(evidence_sources) if evidence_sources else "no runtime evidence"
    if dynamic_status == "confirmed":
        return f"This suspected vulnerability is dynamically confirmed by {source_text}. Evidence level: {evidence_level}."
    if dynamic_status == "need_review":
        return f"This suspected vulnerability has limited runtime evidence from {source_text} and needs manual review."
    return "This suspected vulnerability was not triggered in the current dynamic validation run."


def to_markdown(report):
    lines = []
    lines.append(f"# SENTINEL Final Audit Report: {report['project_name']}")
    lines.append("")
    lines.append(f"- Overall Risk: **{report['overall_risk']}**")
    lines.append(f"- Total Components: {report['summary']['total_components']}")
    lines.append(f"- Total Slices: {report['summary']['total_slices']}")
    lines.append(f"- Total Hypotheses: {report['summary']['total_hypotheses']}")
    lines.append(f"- Total Static Findings: {report['summary']['total_static_findings']}")
    lines.append(f"- Harness Packages: {report['summary']['total_harness_packages']}")
    lines.append(f"- Confirmed Findings: {report['summary']['confirmed_findings']}")
    lines.append(f"- ASan Confirmed Findings: {report['summary']['asan_confirmed_findings']}")
    lines.append("")

    lines.append("## Seven-Agent Trace")
    lines.append("")
    lines.append("```text")
    lines.append("Agent A -> Agent B -> Agent C -> Agent D -> Agent E -> Agent F -> Agent G")
    lines.append("dependency -> slice -> hypothesis -> finding -> harness -> evidence -> decision")
    lines.append("```")
    lines.append("")

    lines.append("## Component Risks")
    if not report["component_risks"]:
        lines.append("No dependency risks were inferred.")
    else:
        for comp in report["component_risks"]:
            lines.append(f"### {comp.get('name')}")
            lines.append(f"- Version: {comp.get('version', 'unknown')}")
            lines.append(f"- Risk: {comp.get('risk_level', 'unknown')}")
            lines.append(f"- Confidence: {comp.get('component_confidence', 'unknown')}")
            profile = comp.get("risk_profile") or {}
            if profile:
                lines.append(f"- Known CVEs: {profile.get('known_cve_count')}")
                lines.append(f"- Memory-safety CVEs: {profile.get('memory_safety_cve_count')}")
                lines.append(f"- Recommended Action: {profile.get('recommended_action')}")
            lines.append("")

    lines.append("## Final Findings")
    if not report["final_findings"]:
        lines.append("No static findings were generated.")
    else:
        for f in report["final_findings"]:
            lines.append(f"### {f['finding_id']} - {f['vulnerability_type']}")
            lines.append(f"- File: `{f['file']}`")
            lines.append(f"- Function: `{f['function']}`")
            lines.append(f"- CWE: `{f['cwe_id']}`")
            lines.append(f"- Hypothesis: `{f.get('hypothesis_id')}`")
            lines.append(f"- Slice: `{f.get('source_slice_id')}`")
            lines.append(f"- Harness Package: `{f.get('package_id') or 'none'}`")
            lines.append(f"- Dynamic Status: **{f['dynamic_status']}**")
            lines.append(f"- Evidence Level: {f['evidence_level']}")
            lines.append(f"- Evidence Sources: {', '.join(f.get('dynamic_evidence_sources', [])) or 'none'}")
            lines.append(f"- Trigger Condition: {f.get('trigger_condition', '')}")
            lines.append(f"- Fix Suggestion: {f.get('suggested_fix', '')}")
            lines.append(f"- Final Conclusion: {f['final_conclusion']}")
            lines.append("")
    return "\n".join(lines)
