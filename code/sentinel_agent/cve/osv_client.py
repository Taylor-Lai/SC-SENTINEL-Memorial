import json
import urllib.request

from cve.cve_cache import get_cache, set_cache
from cve.risk_inference import normalize_vulnerability_risk

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def query_osv_package(component_name, version=None, ecosystem_candidates=None, timeout=8):
    """
    Query OSV.dev for package vulnerabilities.

    Notes:
    - OSV is strongest when ecosystem + package + version are known.
    - For C/C++ libraries, ecosystem is often not as standardized as PyPI/npm.
    - We try configured ecosystem candidates, then return normalized results.
    """
    ecosystem_candidates = ecosystem_candidates or ["OSS-Fuzz"]
    all_results = []

    for ecosystem in ecosystem_candidates:
        cache_key = f"osv:{ecosystem}:{component_name}:{version or 'unknown'}"
        cached = get_cache(cache_key)
        if cached is not None:
            all_results.extend(cached)
            continue

        payload = {
            "package": {
                "name": component_name,
                "ecosystem": ecosystem
            }
        }
        if version and version != "unknown":
            payload["version"] = version

        try:
            data = _post_json(OSV_QUERY_URL, payload, timeout=timeout)
            vulns = data.get("vulns", [])
            normalized = [normalize_osv_vuln(v, ecosystem) for v in vulns]
            set_cache(cache_key, normalized)
            all_results.extend(normalized)
        except Exception:
            # Do not break the pipeline if OSV is unavailable.
            set_cache(cache_key, [])
            continue

    return deduplicate_vulnerabilities(all_results)


def _post_json(url, payload, timeout=8):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def normalize_osv_vuln(vuln, ecosystem):
    aliases = vuln.get("aliases", [])
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)

    severity_score = extract_osv_severity_score(vuln)
    risk_level = score_to_risk(severity_score)

    result = {
        "source": "OSV",
        "ecosystem": ecosystem,
        "id": vuln.get("id"),
        "cve_id": cve_id,
        "aliases": aliases,
        "summary": vuln.get("summary") or vuln.get("details", "")[:200],
        "details": vuln.get("details", ""),
        "modified": vuln.get("modified"),
        "published": vuln.get("published"),
        "severity_score": severity_score,
        "risk_level": risk_level,
        "references": [
            ref.get("url")
            for ref in vuln.get("references", [])
            if ref.get("url")
        ][:5]
    }

    return normalize_vulnerability_risk(result)


def extract_osv_severity_score(vuln):
    severities = vuln.get("severity") or []
    for sev in severities:
        score = sev.get("score")
        if not score:
            continue
        try:
            return float(score)
        except ValueError:
            continue

    sev_text = (vuln.get("database_specific") or {}).get("severity")
    mapping = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.5,
        "LOW": 2.5
    }
    if sev_text:
        return mapping.get(str(sev_text).upper())

    return None


def score_to_risk(score):
    if score is None:
        return "unknown"
    try:
        score = float(score)
    except Exception:
        return "unknown"

    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def deduplicate_vulnerabilities(vulns):
    seen = set()
    result = []
    for v in vulns:
        key = v.get("cve_id") or v.get("id") or v.get("summary")
        if key in seen:
            continue
        seen.add(key)
        result.append(v)
    return result
