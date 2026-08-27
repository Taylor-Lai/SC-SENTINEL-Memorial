from types import SimpleNamespace

from app.core.evidence import (
    calculate_report_risk,
    evidence_grade,
    evidence_sources,
    vulnerability_profile,
)
from app.models.component_risk import Severity
from app.models.vulnerability import VerifyStatus


def finding(status=VerifyStatus.UNVERIFIED, log=None, events=None, vuln_type="use_after_free"):
    return SimpleNamespace(
        verify_status=status,
        afl_log=log,
        ebpf_events=events or [],
        vuln_type=vuln_type,
    )


def test_multisource_runtime_finding_is_corroborated():
    item = finding(
        status=VerifyStatus.CONFIRMED,
        log="[ASAN] AddressSanitizer heap-use-after-free\n[AFL++] crash saved",
        events=[{"event": "use_after_free"}],
    )

    assert evidence_sources(item) == ["static", "asan", "afl", "ebpf"]
    assert evidence_grade(item) == "corroborated"


def test_bounded_no_crash_is_not_false_positive():
    item = finding(status=VerifyStatus.NOT_REPRODUCED)
    assert evidence_grade(item) == "not_reproduced"


def test_profiles_and_report_risk_are_deterministic():
    assert vulnerability_profile("UAF").cwe_id == "CWE-416"
    vulnerabilities = [
        finding(status=VerifyStatus.CONFIRMED, vuln_type="use_after_free"),
        finding(status=VerifyStatus.UNVERIFIED, vuln_type="double_free"),
    ]
    components = [SimpleNamespace(severity=Severity.CRITICAL)]

    score, level = calculate_report_risk(vulnerabilities, components)
    assert score == 43
    assert level == "medium"
