from agents import agent_a_dependency


def _vulnerability(index: int) -> dict:
    return {
        "source": "OSV",
        "id": f"OSV-{index}",
        "summary": "buffer overflow",
        "risk_level": "high",
        "published": f"2026-01-{(index % 28) + 1:02d}",
    }


def test_known_versions_do_not_mix_in_keyword_only_nvd_matches(monkeypatch) -> None:
    monkeypatch.setattr(
        agent_a_dependency,
        "infer_components",
        lambda *_: [{
            "name": "openssl",
            "version": "1.1.1t",
            "purl_name": "openssl",
            "ecosystem_candidates": ["OSS-Fuzz"],
            "evidence": [],
        }],
    )
    monkeypatch.setattr(
        agent_a_dependency,
        "query_osv_package",
        lambda *_args, **_kwargs: [_vulnerability(1)],
    )

    result = agent_a_dependency.run_agent_a([], [])

    matches = result["components"][0]["matched_vulnerabilities"]
    assert len(matches) == 1
    assert matches[0]["match_confidence"] == "version_matched"


def test_unknown_versions_do_not_create_cve_matches(monkeypatch) -> None:
    monkeypatch.setattr(
        agent_a_dependency,
        "infer_components",
        lambda *_: [{
            "name": "libxml2",
            "version": "unknown",
            "purl_name": "libxml2",
            "ecosystem_candidates": ["OSS-Fuzz"],
            "evidence": [],
        }],
    )
    def unexpected_osv_call(*_args, **_kwargs):
        raise AssertionError("version-less OSV lookup must not run")

    monkeypatch.setattr(agent_a_dependency, "query_osv_package", unexpected_osv_call)

    result = agent_a_dependency.run_agent_a([], [])

    matches = result["components"][0]["matched_vulnerabilities"]
    assert matches == []
    assert result["components"][0]["summary"]["version_status"] == "unresolved"
