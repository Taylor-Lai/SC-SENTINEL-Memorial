from core.integration_schema import to_backend_components
from core.risk_level import max_risk
from cve.dependency_parser import (
    deduplicate_evidence,
    get_ignored_headers,
    infer_components,
)
from cve.osv_client import query_osv_package
from cve.nvd_client import query_nvd_package
from cve.risk_inference import normalize_vulnerability_risk


def run_agent_a(source_files, metadata_files):
    """
    Agent A - Dependency Risk Identification

    Part 2.1 upgraded version:
    - Keeps Part 2 dependency parsing and OSV/NVD query.
    - Infers risk from vulnerability text when CVSS/severity is missing.
    - Splits full vulnerability list and top risk list.
    - Avoids "component has memory corruption records but risk remains unknown".
    """
    components = infer_components(source_files, metadata_files)

    enriched = []
    for component in components:
        name = component["name"]
        version = component.get("version", "unknown")
        purl_name = component.get("purl_name", name)
        ecosystem_candidates = component.get("ecosystem_candidates", [])
        nvd_products = component.get("nvd_products", [])

        version_known = bool(version and version != "unknown")
        # A component name alone is not enough to assert CVE exposure.  OSV can
        # evaluate an affected-version range when the manifest declares a
        # version; NVD keyword search cannot.  Never persist keyword matches as
        # component risk, otherwise a modern project is polluted with every
        # historical CVE that happens to mention a library name.
        osv_vulns = (
            query_osv_package(
                purl_name,
                version=version,
                ecosystem_candidates=ecosystem_candidates,
            )
            if version_known
            else []
        )
        nvd_vulns = (
            query_nvd_package(name, version, nvd_products=nvd_products)
            if version_known
            else []
        )

        matched = deduplicate_vulnerabilities(osv_vulns + nvd_vulns)
        matched = [normalize_vulnerability_risk(v) for v in matched]
        matched = sort_vulnerabilities_by_risk(matched)
        if version_known:
            for item in matched:
                item["match_confidence"] = "version_matched"

        risk = "unknown"
        for item in matched:
            risk = max_risk(risk, item.get("risk_level", "unknown"))

        evidence = deduplicate_evidence(component.get("evidence", []))
        evidence = [annotate_evidence_type(item) for item in evidence]
        source_types = sorted({item.get("source") for item in evidence if item.get("source")})
        risk_profile = build_component_risk_profile(matched, risk)
        component_confidence = infer_component_confidence(evidence)
        component_origin = infer_component_origin(evidence)
        version_confidence = infer_version_confidence(version, evidence)

        enriched.append({
            "name": name,
            "library_name": name,
            "version": version,
            "version_confidence": version_confidence,
            "purl_name": purl_name,
            "component_confidence": component_confidence,
            "component_origin": component_origin,
            "source_types": source_types,
            "evidence": evidence,

            # Full list for backend / report export.
            "matched_vulnerabilities": matched,

            # Compatibility with existing Agent E/report code.
            "matched_cves": matched,

            # Short list for frontend table preview.
            "top_vulnerabilities": matched[:5],

            "risk_level": risk,
            "risk_profile": risk_profile,
            "recommended_action": risk_profile["recommended_action"],
            "summary": {
                "vulnerability_count": len(matched),
                "highest_risk": risk,
                "high_or_critical_count": sum(
                    1 for v in matched if v.get("risk_level") in {"high", "critical"}
                ),
                "queried_sources": ["OSV", "NVD"] if version_known else [],
                "version_status": "declared" if version_known else "unresolved",
            }
        })

    result = {
        "agent": "Agent A - Dependency Risk Identification",
        "components": enriched,
        "components_rich": enriched,
        "summary": {
            "total_components": len(enriched),
            "high_risk_components": sum(
                1 for c in enriched if c.get("risk_level") in {"high", "critical"}
            ),
            "queried_sources": ["OSV", "NVD"]
        },
        "ignored_headers": get_ignored_headers(),
    }
    result["integration"] = to_backend_components(result)
    return result


def deduplicate_vulnerabilities(vulns):
    seen = set()
    result = []
    for vuln in vulns:
        key = vuln.get("cve_id") or vuln.get("id") or vuln.get("summary")
        if key in seen:
            continue
        seen.add(key)
        result.append(vuln)
    return result


def sort_vulnerabilities_by_risk(vulns):
    order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "unknown": 0
    }
    return sorted(
        vulns,
        key=lambda v: (
            order.get(v.get("risk_level", "unknown"), 0),
            v.get("published") or ""
        ),
        reverse=True
    )


def annotate_evidence_type(item):
    item = dict(item)
    source = str(item.get("source") or "").lower()
    evidence = str(item.get("evidence") or "").lower()

    if source == "include":
        evidence_type = "include"
    elif source in {"vcpkg.json", "conanfile.txt"}:
        evidence_type = "package_manifest"
    elif evidence.startswith("-l"):
        evidence_type = "link_flag"
    elif source in {"cmakelists.txt", "makefile"}:
        evidence_type = "build_file"
    else:
        evidence_type = "metadata"

    item["evidence_type"] = evidence_type
    return item


def infer_component_confidence(evidence_items):
    evidence_types = {item.get("evidence_type") for item in evidence_items}
    score = 0.35
    if "package_manifest" in evidence_types:
        score += 0.35
    if "build_file" in evidence_types:
        score += 0.25
    if "include" in evidence_types:
        score += 0.20
    if "link_flag" in evidence_types:
        score += 0.20
    if len(evidence_items) >= 2:
        score += 0.10
    return round(min(score, 0.98), 2)


def infer_component_origin(evidence_items):
    evidence_types = {item.get("evidence_type") for item in evidence_items}
    if "package_manifest" in evidence_types:
        return "third_party_manifest"
    if "link_flag" in evidence_types or "build_file" in evidence_types:
        return "third_party_build_link"
    if "include" in evidence_types:
        return "known_third_party_include"
    return "metadata"


def infer_version_confidence(version, evidence_items):
    if not version or version == "unknown":
        return 0.2
    for item in evidence_items:
        if item.get("version_hint") == version:
            if item.get("evidence_type") == "package_manifest":
                return 0.95
            return 0.8
    return 0.55


def build_component_risk_profile(vulnerabilities, risk_level):
    memory_keywords = [
        "buffer overflow", "overflow", "out-of-bounds", "out of bounds",
        "use after free", "use-after-free", "double free", "memory corruption",
        "heap", "stack", "format string"
    ]
    known_cve_count = len(vulnerabilities)
    memory_safety_cve_count = 0
    highest_cvss = None

    for vuln in vulnerabilities:
        score = vuln.get("severity_score") or vuln.get("cvss_score")
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None
        if score is not None:
            highest_cvss = score if highest_cvss is None else max(highest_cvss, score)

        text = " ".join(str(vuln.get(key, "")) for key in ("summary", "details", "cve_id", "id")).lower()
        if any(keyword in text for keyword in memory_keywords):
            memory_safety_cve_count += 1

    return {
        "known_cve_count": known_cve_count,
        "memory_safety_cve_count": memory_safety_cve_count,
        "highest_cvss": highest_cvss,
        "risk_level": risk_level,
        "recommended_action": recommended_action(risk_level, memory_safety_cve_count),
    }


def recommended_action(risk_level, memory_safety_cve_count):
    if risk_level in {"critical", "high"} and memory_safety_cve_count:
        return "Prioritize upgrade or patch before release; memory-safety CVEs are present."
    if risk_level in {"critical", "high"}:
        return "Review high-risk CVEs and upgrade the component if a fixed version exists."
    if risk_level == "medium":
        return "Review exposure and schedule dependency upgrade."
    if risk_level == "low":
        return "Track the component and upgrade during routine maintenance."
    return "Component detected; monitor OSV/NVD results and verify the declared version."
