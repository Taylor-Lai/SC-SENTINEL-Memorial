"""
Risk inference utilities for dependency vulnerability results.

Why this file exists:
OSV OSS-Fuzz records often do not contain CVSS scores.
If we only rely on severity_score, many memory corruption reports become "unknown".
For a C/C++ supply-chain audit system, this is too weak.

This module infers risk from vulnerability text when numeric severity is missing.
"""

CRITICAL_KEYWORDS = [
    "remote code execution",
    "rce",
    "arbitrary code execution",
]

HIGH_KEYWORDS = [
    "heap-use-after-free",
    "use-after-free",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "stack-use-after-return",
    "double-free",
    "buffer overflow",
    "memory corruption",
    "out-of-bounds write",
    "write overflow",
]

MEDIUM_KEYWORDS = [
    "null-dereference",
    "null pointer dereference",
    "out-of-bounds read",
    "integer overflow",
    "use-of-uninitialized-value",
]

LOW_KEYWORDS = [
    "memory leak",
    "denial of service",
]


def infer_risk_from_text(summary="", details=""):
    text = f"{summary or ''}\n{details or ''}".lower()

    if any(keyword in text for keyword in CRITICAL_KEYWORDS):
        return "critical"

    if any(keyword in text for keyword in HIGH_KEYWORDS):
        return "high"

    if any(keyword in text for keyword in MEDIUM_KEYWORDS):
        return "medium"

    if any(keyword in text for keyword in LOW_KEYWORDS):
        return "low"

    return "unknown"


def normalize_vulnerability_risk(vuln):
    """
    If vuln already has numeric severity-derived risk, keep it.
    Otherwise infer risk from summary/details text.
    """
    current = vuln.get("risk_level", "unknown")

    if current and current != "unknown":
        return vuln

    inferred = infer_risk_from_text(
        summary=vuln.get("summary", ""),
        details=vuln.get("details", "")
    )

    vuln = dict(vuln)
    vuln["risk_level"] = inferred
    vuln["risk_inference"] = "text_keyword" if inferred != "unknown" else "unknown"
    return vuln
