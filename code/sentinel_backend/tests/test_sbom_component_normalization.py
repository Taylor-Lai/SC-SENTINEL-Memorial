from app.worker.sbom_task import _flatten_component_risks


def test_flatten_rich_agent_a_components_keeps_each_cve():
    rows = _flatten_component_risks([
        {
            "name": "curl",
            "library_name": "curl",
            "version": "8.11.1",
            "risk_level": "high",
            "matched_vulnerabilities": [
                {
                    "cve_id": "CVE-2025-0725",
                    "severity_score": 7.3,
                    "risk_level": "high",
                    "summary": "buffer overflow",
                },
                {
                    "cve_id": "CVE-2026-10536",
                    "severity_score": 9.8,
                    "risk_level": "critical",
                    "summary": "use after free",
                },
            ],
        }
    ])

    assert [row["cve_id"] for row in rows] == [
        "CVE-2025-0725",
        "CVE-2026-10536",
    ]
    assert rows[1]["severity"] == "critical"


def test_flatten_keeps_component_without_cve_visible_in_sbom():
    component = {"library_name": "zlib", "version": "1.2.13", "severity": "unknown"}

    assert _flatten_component_risks([component]) == [component]
