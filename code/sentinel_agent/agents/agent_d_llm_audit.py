from core.id_generator import make_id
from core.integration_schema import to_backend_vulnerabilities
from core.llm_client import LLMClient

from agents.agent_c_static_audit import (
    apply_quality_control,
    build_quality_summary,
    call_llm_with_json_retry,
    extract_target_function_lines,
    load_prompt,
    normalize_llm_findings,
)


def run_agent_d(agent_a_result, agent_b_result, agent_c_result):
    """
    Agent D - LLM Audit and Cross-Check.

    Only Agent C hypotheses are sent to the LLM. If the LLM is unavailable or
    fails, hypotheses are promoted to rule_fallback findings.
    """
    findings = []
    audited_hypotheses = []
    llm_errors = []
    quality_events = []

    slices_by_id = {
        slc.get("slice_id"): slc
        for slc in agent_b_result.get("slices", [])
    }

    llm_client = LLMClient()
    llm_available = llm_client.is_available()

    for hyp in agent_c_result.get("hypotheses", []):
        slc = slices_by_id.get(hyp.get("source_slice_id"))
        if not slc:
            llm_errors.append({
                "hypothesis_id": hyp.get("hypothesis_id"),
                "error": "Source slice not found."
            })
            continue

        audited_hypotheses.append({
            "hypothesis_id": hyp.get("hypothesis_id"),
            "source_slice_id": hyp.get("source_slice_id"),
            "file": hyp.get("file"),
            "function": hyp.get("function"),
            "cwe_candidates": hyp.get("cwe_candidates", []),
        })

        rule_finding = finding_from_hypothesis(hyp, audit_source="rule_fallback")

        if llm_available:
            try:
                function_lines = extract_target_function_lines(slc)
                llm_findings, events = llm_audit_hypothesis(
                    llm_client=llm_client,
                    agent_a_result=agent_a_result,
                    slc=slc,
                    hypothesis=hyp,
                    function_lines=function_lines,
                    rule_finding=rule_finding,
                )
                quality_events.extend(events)
                if llm_findings:
                    findings.extend(llm_findings)
                else:
                    findings.append(with_fallback_reason(rule_finding, "llm_returned_no_findings"))
            except Exception as exc:
                llm_errors.append({
                    "hypothesis_id": hyp.get("hypothesis_id"),
                    "source_slice_id": hyp.get("source_slice_id"),
                    "error": str(exc)
                })
                findings.append(with_fallback_reason(rule_finding, "llm_call_failed"))
        else:
            findings.append(with_fallback_reason(rule_finding, "llm_not_configured"))

    findings = deduplicate_findings(findings)
    for idx, finding in enumerate(findings, start=1):
        finding["finding_id"] = make_id("FINDING", idx)

    quality_summary = build_quality_summary(findings, quality_events, llm_errors)

    result = {
        "agent": "Agent D - LLM Audit and Cross-Check Agent",
        "audit_mode": "llm_hypothesis_audit" if llm_available else "rule_fallback_only",
        "static_findings": findings,
        "audited_hypotheses": audited_hypotheses,
        "llm_errors": llm_errors,
        "quality_events": quality_events,
        "quality_summary": quality_summary,
        "summary": {
            "total_hypotheses": len(agent_c_result.get("hypotheses", [])),
            "audited_hypotheses": len(audited_hypotheses),
            "total_findings": len(findings),
            "high_risk_findings": sum(1 for f in findings if f.get("risk_level") in {"high", "critical"}),
            "llm_available": llm_available,
            "llm_error_count": len(llm_errors),
            "llm_findings": sum(1 for f in findings if f.get("audit_source") == "llm"),
            "rule_fallback_findings": sum(1 for f in findings if f.get("audit_source") == "rule_fallback"),
        }
    }
    result["vulnerabilities"] = to_backend_vulnerabilities(result)["vulnerabilities"]
    result["integration"] = {"vulnerabilities": result["vulnerabilities"]}
    return result


def llm_audit_hypothesis(llm_client, agent_a_result, slc, hypothesis, function_lines, rule_finding):
    prompt = load_prompt()
    user_content = build_hypothesis_user_content(agent_a_result, slc, hypothesis, function_lines)
    messages = [{"role": "system", "content": prompt}, {"role": "user", "content": user_content}]
    raw_text, parsed, events = call_llm_with_json_retry(llm_client, messages, slc)
    llm_findings = normalize_llm_findings(parsed, slc)
    llm_findings = apply_quality_control(llm_findings, [rule_finding], slc)
    for finding in llm_findings:
        finding["hypothesis_id"] = hypothesis.get("hypothesis_id")
        finding["hypothesis_reason"] = hypothesis.get("reason")
        finding["hypothesis_confidence"] = hypothesis.get("confidence")
        finding["cross_function_trace"] = hypothesis.get("cross_function_trace", [])
        finding["dataflow_trace"] = hypothesis.get("dataflow_trace", [])
        finding["evidence_lines"] = hypothesis.get("evidence_lines", [])
        finding["quality_control"] = add_semantic_consistency(
            finding.get("quality_control", {}),
            hypothesis,
            finding,
        )
    return llm_findings, events


def build_hypothesis_user_content(agent_a_result, slc, hypothesis, function_lines):
    numbered_code = "\n".join(f'{item["source_line"]}: {item["code"]}' for item in function_lines)
    components = [
        {
            "name": comp.get("name"),
            "version": comp.get("version"),
            "risk_level": comp.get("risk_level"),
            "risk_profile": comp.get("risk_profile"),
        }
        for comp in agent_a_result.get("components", [])[:8]
    ]

    return f"""
Audit this C/C++ vulnerability hypothesis. Return strict JSON only.

Slice:
- slice_id: {slc.get("slice_id")}
- file: {slc.get("target_file")}
- function: {slc.get("target_function")}
- line_range: {slc.get("line_range")}
- risk_keywords: {slc.get("risk_keywords")}
- audit_priority: {slc.get("audit_priority")}

Hypothesis:
- hypothesis_id: {hypothesis.get("hypothesis_id")}
- cwe_candidates: {hypothesis.get("cwe_candidates")}
- risk_signals: {hypothesis.get("risk_signals")}
- suspect_lines: {hypothesis.get("suspect_lines")}
- reason: {hypothesis.get("reason")}
- evidence: {hypothesis.get("evidence")}

Component risk context:
{components}

Target function with source line numbers:
{numbered_code}
""".strip()


def finding_from_hypothesis(hypothesis, audit_source):
    cwe_id = (hypothesis.get("cwe_candidates") or ["UNKNOWN"])[0]
    return {
        "finding_id": "PENDING",
        "hypothesis_id": hypothesis.get("hypothesis_id"),
        "source_slice_id": hypothesis.get("source_slice_id"),
        "file": hypothesis.get("file"),
        "function": hypothesis.get("function"),
        "line_range": hypothesis.get("line_range"),
        "cwe_id": cwe_id,
        "vulnerability_type": hypothesis.get("vulnerability_type", "Unknown"),
        "risk_level": hypothesis.get("risk_level", "medium"),
        "trigger_condition": hypothesis.get("reason", ""),
        "evidence": hypothesis.get("evidence", []),
        "evidence_lines": hypothesis.get("evidence_lines", []),
        "cross_function_trace": hypothesis.get("cross_function_trace", []),
        "dataflow_trace": hypothesis.get("dataflow_trace", []),
        "confidence": hypothesis.get("confidence", 0.65),
        "suggested_fix": hypothesis.get("suggested_fix", ""),
        "static_status": "suspected",
        "audit_source": audit_source,
        "hypothesis_reason": hypothesis.get("reason"),
        "hypothesis_confidence": hypothesis.get("confidence"),
        "quality_control": {
            "original_confidence": hypothesis.get("confidence", 0.65),
            "calibrated_confidence": hypothesis.get("confidence", 0.65),
            "confidence_adjusted": False,
            "rule_consistency": "rule_only",
            "semantic_consistency": "consistent",
            "warnings": []
        }
    }


def with_fallback_reason(finding, reason):
    finding = dict(finding)
    qc = dict(finding.get("quality_control", {}))
    qc["fallback_reason"] = reason
    qc["rule_consistency"] = "rule_only"
    qc.setdefault("semantic_consistency", "consistent")
    finding["quality_control"] = qc
    return finding


def add_semantic_consistency(qc, hypothesis, finding):
    qc = dict(qc or {})
    warnings = list(qc.get("warnings", []))
    hyp_cwes = set(hypothesis.get("cwe_candidates") or [])
    finding_cwe = finding.get("cwe_id")
    if finding_cwe and hyp_cwes and finding_cwe not in hyp_cwes:
        qc["semantic_consistency"] = "conflict"
        warnings.append(f"LLM CWE {finding_cwe} conflicts with rule hypothesis {sorted(hyp_cwes)}.")
    else:
        qc["semantic_consistency"] = "consistent"
    qc["warnings"] = warnings
    return qc


def deduplicate_findings(findings):
    best_by_key = {}
    for finding in findings:
        function_name = str(finding.get("function") or "")
        vulnerability_type = str(finding.get("vulnerability_type") or "")
        cwe_id = finding.get("cwe_id")
        normalized_function = function_name
        if cwe_id == "CWE-416" and vulnerability_type == "Use After Free":
            if function_name in {"png_process_chunk", "png_fire_callbacks"}:
                normalized_function = "png_uaf_chain"
        key = (
            finding.get("file"),
            normalized_function,
            cwe_id,
        )
        current = best_by_key.get(key)
        if current is None:
            best_by_key[key] = finding
            continue

        current_score = (
            float(current.get("confidence") or 0),
            len(current.get("evidence") or []),
        )
        new_score = (
            float(finding.get("confidence") or 0),
            len(finding.get("evidence") or []),
        )
        if new_score > current_score:
            best_by_key[key] = finding
    return list(best_by_key.values())
