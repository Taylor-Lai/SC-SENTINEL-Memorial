def run_agent_f(agent_d_result, agent_e_result, asan_result=None, afl_result=None, ebpf_log=None):
    """
    Agent F - Dynamic Evidence Attribution.

    Matches static findings and harness packages with ASan/AFL++/eBPF evidence.
    """
    asan_result = asan_result or {}
    afl_result = afl_result or {"crash_found": False}
    ebpf_log = ebpf_log or {"events": []}
    packages_by_finding = {
        pkg.get("finding_id"): pkg
        for pkg in agent_e_result.get("harness_packages", [])
    }

    evidence_links = []
    for finding in agent_d_result.get("static_findings", []):
        package = packages_by_finding.get(finding.get("finding_id"))
        matched_asan = match_asan_evidence(finding, asan_result)
        matched_afl = match_afl_evidence(finding, afl_result)
        matched_ebpf = match_ebpf_events(finding, ebpf_log)
        dynamic_status, evidence_level, evidence_sources = judge_dynamic_status(
            finding=finding,
            asan_evidence=matched_asan,
            afl_evidence=matched_afl,
            ebpf_evidence=matched_ebpf,
        )
        evidence_links.append({
            "finding_id": finding.get("finding_id"),
            "hypothesis_id": finding.get("hypothesis_id"),
            "source_slice_id": finding.get("source_slice_id"),
            "package_id": package.get("package_id") if package else None,
            "dynamic_status": dynamic_status,
            "evidence_level": evidence_level,
            "evidence_sources": evidence_sources,
            "matched_asan": matched_asan,
            "matched_afl": matched_afl,
            "matched_ebpf": matched_ebpf,
        })

    return {
        "agent": "Agent F - Dynamic Evidence Attribution Agent",
        "evidence_links": evidence_links,
        "summary": {
            "total_findings": len(agent_d_result.get("static_findings", [])),
            "total_links": len(evidence_links),
            "confirmed_findings": sum(1 for item in evidence_links if item.get("dynamic_status") == "confirmed"),
            "need_review_findings": sum(1 for item in evidence_links if item.get("dynamic_status") == "need_review"),
            "asan_confirmed_findings": sum(
                1 for item in evidence_links
                if (item.get("matched_asan") or {}).get("dynamic_status") == "confirmed"
            ),
        }
    }


def judge_dynamic_status(finding, asan_evidence, afl_evidence, ebpf_evidence):
    sources = []
    if asan_evidence and asan_evidence.get("dynamic_status") == "confirmed":
        sources.append("ASAN")
    if afl_evidence and afl_evidence.get("crash_found"):
        sources.append("AFL++")
    if ebpf_evidence and ebpf_has_strong_signal(ebpf_evidence):
        sources.append("eBPF")

    if "ASAN" in sources:
        if "AFL++" in sources or "eBPF" in sources:
            return "confirmed", "strong", sources
        return "confirmed", "high", sources
    if "AFL++" in sources and "eBPF" in sources:
        return "confirmed", "strong", sources
    if "AFL++" in sources or "eBPF" in sources:
        return "need_review", "medium", sources
    return "untriggered", "weak", sources


def match_asan_evidence(finding, asan_result):
    if not asan_result:
        return None
    results_by_id = asan_result.get("results_by_finding_id", {})
    item = results_by_id.get(finding.get("finding_id"))
    if item and evidence_matches_finding(item, finding):
        return item
    for candidate in asan_result.get("results", []):
        if evidence_matches_finding(candidate, finding):
            return candidate
    return None


def evidence_matches_finding(evidence, finding):
    if not evidence:
        return False
    if not cwe_matches(evidence.get("cwe_id"), finding.get("cwe_id")):
        return False
    target_fn = evidence.get("target_function")
    if target_fn and target_fn != finding.get("function"):
        return False
    target_file = evidence.get("target_file")
    if target_file and target_file != finding.get("file"):
        return False
    return True


def match_afl_evidence(finding, afl_result):
    if not afl_result or not afl_result.get("crash_found"):
        return None
    if not afl_text_matches_cwe(afl_result, finding.get("cwe_id")):
        return None
    return {
        "crash_found": afl_result.get("crash_found"),
        "crash_file": afl_result.get("crash_file"),
        "signal": afl_result.get("signal"),
        "asan_bug_type": afl_result.get("asan_bug_type"),
        "stderr_excerpt": afl_result.get("stderr_excerpt"),
        "notes": afl_result.get("notes", "AFL++ evidence."),
    }


def afl_text_matches_cwe(afl_result, cwe_id):
    text = " ".join(
        str(afl_result.get(key, ""))
        for key in ("stderr_excerpt", "notes", "crash_file", "asan_bug_type", "vulnerability_type")
    ).lower()
    keywords = {
        "CWE-416": ["use-after-free", "heap-use-after-free", "uaf"],
        "CWE-415": ["double-free", "double free"],
        "CWE-120": ["heap-buffer-overflow", "stack-buffer-overflow", "buffer-overflow", "buffer overflow"],
        "CWE-122": ["heap-buffer-overflow", "heap overflow", "buffer-overflow"],
        "CWE-121": ["stack-buffer-overflow", "stack overflow", "buffer-overflow"],
        "CWE-134": ["format-string", "format string", "%n"],
    }.get(cwe_id, [])
    return any(keyword in text for keyword in keywords)


def match_ebpf_events(finding, ebpf_log):
    if not ebpf_log:
        return []
    cwe = finding.get("cwe_id")
    desired = {
        "CWE-416": {"use_after_free", "use_after_free_suspected"},
        "CWE-415": {"double_free", "double_free_suspected"},
        "CWE-120": {"heap_overflow", "heap_overflow_suspected", "stack_overflow", "stack_write_suspected", "out_of_bounds"},
        "CWE-122": {"heap_overflow", "heap_overflow_suspected", "out_of_bounds"},
        "CWE-121": {"stack_overflow", "stack_write_suspected", "out_of_bounds"},
        "CWE-134": {"format_string", "format_string_suspected", "out_of_bounds"},
    }.get(cwe, set())
    matched = []
    for ev in ebpf_log.get("events", []):
        event_name = normalize_ebpf_event_name(ev)
        if event_name in desired and ebpf_event_is_strong(ev):
            matched.append(ev)
    return matched


def ebpf_has_strong_signal(ebpf_evidence):
    return bool(ebpf_evidence)


def normalize_ebpf_event_name(event):
    return str(event.get("event_type") or event.get("event") or "").strip().lower()


def ebpf_event_is_strong(event):
    severity = str(event.get("severity") or event.get("level") or "").strip().lower()
    if severity in {"high", "critical", "confirmed"}:
        return True
    return bool(event.get("access_type") or event.get("stacktrace") or event.get("trace"))


def cwe_matches(evidence_cwe, finding_cwe):
    if evidence_cwe == finding_cwe:
        return True
    buffer_cwes = {"CWE-120", "CWE-121", "CWE-122"}
    return evidence_cwe in buffer_cwes and finding_cwe in buffer_cwes
