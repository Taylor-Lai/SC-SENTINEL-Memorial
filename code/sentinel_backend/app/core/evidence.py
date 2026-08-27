"""Evidence classification and report-level risk scoring.

The static audit proposes candidates.  Only runtime signals may promote a
candidate to confirmed, while a fuzzing run that did not reproduce a crash is
kept distinct from a proven false positive.
"""
from collections.abc import Iterable
from dataclasses import dataclass

from app.models.component_risk import Severity
from app.models.vulnerability import VerifyStatus


@dataclass(frozen=True)
class VulnerabilityProfile:
    cwe_id: str
    severity: Severity
    display_name: str


_PROFILES = {
    "use_after_free": VulnerabilityProfile("CWE-416", Severity.CRITICAL, "Use After Free"),
    "uaf": VulnerabilityProfile("CWE-416", Severity.CRITICAL, "Use After Free"),
    "double_free": VulnerabilityProfile("CWE-415", Severity.HIGH, "Double Free"),
    "heap_overflow": VulnerabilityProfile("CWE-122", Severity.CRITICAL, "Heap Overflow"),
    "stack_overflow": VulnerabilityProfile("CWE-121", Severity.CRITICAL, "Stack Overflow"),
    "buffer_overflow": VulnerabilityProfile("CWE-120", Severity.HIGH, "Buffer Overflow"),
    "format_string": VulnerabilityProfile("CWE-134", Severity.HIGH, "Format String"),
}


def normalize_vulnerability_type(value: str | None) -> str:
    normalized = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "use_after_free_(uaf)": "use_after_free",
        "use_after_free": "use_after_free",
        "heap_buffer_overflow": "heap_overflow",
        "stack_buffer_overflow": "stack_overflow",
        "double_free_vulnerability": "double_free",
        "format_string_vulnerability": "format_string",
    }
    return aliases.get(normalized, normalized)


def vulnerability_profile(value: str | None) -> VulnerabilityProfile:
    normalized = normalize_vulnerability_type(value)
    return _PROFILES.get(
        normalized,
        VulnerabilityProfile("CWE-000", Severity.UNKNOWN, str(value or "Unknown")),
    )


def evidence_sources(vulnerability) -> list[str]:
    """Return conservative, observable evidence sources for one finding."""
    sources = ["static"]
    log = str(getattr(vulnerability, "afl_log", None) or "")
    lowered = log.lower()
    if "addresssanitizer" in lowered or "[asan]" in lowered:
        sources.append("asan")
    if "afl" in lowered or "crash" in lowered:
        sources.append("afl")
    if getattr(vulnerability, "ebpf_events", None):
        sources.append("ebpf")
    return sources


def evidence_grade(vulnerability) -> str:
    sources = set(evidence_sources(vulnerability))
    status = getattr(vulnerability, "verify_status", VerifyStatus.UNVERIFIED)
    if status == VerifyStatus.CONFIRMED:
        runtime_sources = sources - {"static"}
        return "corroborated" if len(runtime_sources) >= 2 else "runtime_confirmed"
    if status == VerifyStatus.NOT_REPRODUCED:
        return "not_reproduced"
    if status == VerifyStatus.FALSE_POSITIVE:
        return "dismissed"
    if "ebpf" in sources:
        return "partial_evidence"
    return "candidate"


def calculate_report_risk(vulnerabilities: Iterable, components: Iterable) -> tuple[int, str]:
    score = 0
    for vulnerability in vulnerabilities:
        profile = vulnerability_profile(getattr(vulnerability, "vuln_type", None))
        base = {
            Severity.CRITICAL: 24,
            Severity.HIGH: 16,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
            Severity.UNKNOWN: 6,
        }[profile.severity]
        status = getattr(vulnerability, "verify_status", VerifyStatus.UNVERIFIED)
        multiplier = {
            VerifyStatus.CONFIRMED: 1.0,
            VerifyStatus.UNVERIFIED: 0.45,
            VerifyStatus.NOT_REPRODUCED: 0.2,
            VerifyStatus.FALSE_POSITIVE: 0.0,
        }[status]
        score += round(base * multiplier)

    for component in components:
        severity = getattr(component, "severity", Severity.UNKNOWN)
        score += {
            Severity.CRITICAL: 12,
            Severity.HIGH: 8,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.UNKNOWN: 0,
        }[severity]

    score = min(100, score)
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"
    return score, level
