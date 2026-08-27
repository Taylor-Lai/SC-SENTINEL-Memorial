"""Version-aware NVD lookup for native dependency components.

NVD is queried through an exact CPE name constructed from the declared
vendor/product/version. A CVE is retained only when one of its vulnerable CPE
entries also matches the declared component version range.
"""

import json
import re
import urllib.parse
import urllib.request

from cve.cve_cache import get_cache, set_cache
from cve.risk_inference import normalize_vulnerability_risk

NVD_QUERY_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"


def query_nvd_package(component_name, version, nvd_products=None, timeout=12):
    if not version or version == "unknown" or not nvd_products:
        return []

    # Query by component first, then apply the authoritative CPE range locally.
    # NVD's exact cpeName filter misses CVEs published with wildcard/range CPEs.
    cache_key = f"nvd:v4:version-filtered:{component_name}:{version}:{nvd_products}"
    cached = get_cache(cache_key)
    if cached is not None:
        return cached

    try:
        query = urllib.parse.urlencode({
            "keywordSearch": component_name,
            "resultsPerPage": 2000,
            "startIndex": 0,
        })
        data = _get_json(f"{NVD_QUERY_URL}?{query}", timeout)
        matches = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            if cpe_configuration_matches(cve.get("configurations", []), version, nvd_products):
                matches.append(normalize_nvd_vulnerability(cve))
        result = deduplicate_vulnerabilities(matches)
    except Exception:
        # Supply-chain enrichment must never stop source audit if NVD is rate
        # limited or unavailable. Cache an empty bounded result for this run.
        result = []

    set_cache(cache_key, result)
    return result


def _get_json(url, timeout):
    request = urllib.request.Request(url, headers={"User-Agent": "SC-SENTINEL/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def cpe_configuration_matches(configurations, version, products):
    product_set = {(str(v).lower(), str(p).lower()) for v, p in products}
    for node in _walk_nodes(configurations):
        for match in node.get("cpeMatch", []) or []:
            if not match.get("vulnerable", False):
                continue
            vendor, product = _cpe_vendor_product(match.get("criteria", ""))
            if (vendor, product) not in product_set:
                continue
            if _version_in_cpe_range(version, match):
                return True
    return False


def _walk_nodes(nodes):
    for node in nodes or []:
        yield node
        yield from _walk_nodes(node.get("nodes", []))


def _cpe_vendor_product(criteria):
    parts = str(criteria).split(":")
    if len(parts) < 5 or parts[0:2] != ["cpe", "2.3"]:
        return "", ""
    return parts[3].replace("\\\\", "").lower(), parts[4].replace("\\\\", "").lower()


def _version_in_cpe_range(version, match):
    exact = _cpe_version(match.get("criteria", ""))
    if exact not in {"", "*", "-"} and _compare_versions(version, exact) != 0:
        return False

    start_including = match.get("versionStartIncluding")
    start_excluding = match.get("versionStartExcluding")
    end_including = match.get("versionEndIncluding")
    end_excluding = match.get("versionEndExcluding")
    if start_including and _compare_versions(version, start_including) < 0:
        return False
    if start_excluding and _compare_versions(version, start_excluding) <= 0:
        return False
    if end_including and _compare_versions(version, end_including) > 0:
        return False
    if end_excluding and _compare_versions(version, end_excluding) >= 0:
        return False
    return True


def _cpe_version(criteria):
    parts = str(criteria).split(":")
    return parts[5] if len(parts) > 5 else "*"


def _compare_versions(left, right):
    """Small dependency-free comparator for native versions such as 1.1.1k."""
    def tokens(value):
        return [int(part) if part.isdigit() else part.lower() for part in re.findall(r"\d+|[A-Za-z]+", str(value))]
    a, b = tokens(left), tokens(right)
    for x, y in zip(a, b):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        return -1 if str(x) < str(y) else 1
    if len(a) == len(b):
        return 0
    return -1 if len(a) < len(b) else 1


def normalize_nvd_vulnerability(cve):
    metrics = cve.get("metrics", {}) or {}
    metric = next(iter(metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []) or metrics.get("cvssMetricV2", [])), {})
    cvss = metric.get("cvssData", {}).get("baseScore")
    descriptions = cve.get("descriptions", []) or []
    summary = next((item.get("value") for item in descriptions if item.get("lang") == "en"), "")
    result = {
        "source": "NVD",
        "id": cve.get("id"),
        "cve_id": cve.get("id"),
        "summary": summary,
        "details": summary,
        "severity_score": cvss,
        "risk_level": str(metric.get("baseSeverity") or "unknown").lower(),
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "references": [ref.get("url") for ref in cve.get("references", []) if ref.get("url")][:5],
        "match_confidence": "cpe_version_matched",
    }
    return normalize_vulnerability_risk(result)


def deduplicate_vulnerabilities(vulnerabilities):
    seen, result = set(), []
    for vuln in vulnerabilities:
        key = vuln.get("cve_id") or vuln.get("id")
        if key and key not in seen:
            seen.add(key)
            result.append(vuln)
    return result
