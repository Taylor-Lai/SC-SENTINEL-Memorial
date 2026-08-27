RISK_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def max_risk(*levels):
    levels = [x for x in levels if x]
    if not levels:
        return "unknown"
    return max(levels, key=lambda x: RISK_ORDER.get(x, 0))

def cvss_to_risk_level(cvss):
    if cvss is None:
        return "unknown"
    cvss = float(cvss)
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "unknown"
