from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.services.sandbox_manager import _container_security_options, run_sandbox_verification


def test_default_sandbox_policy_is_unprivileged_and_offline() -> None:
    policy = _container_security_options(
        allow_privileged=False,
        network_disabled=True,
        pids_limit=128,
    )

    assert policy["privileged"] is False
    assert policy["network_disabled"] is True
    assert policy["cap_drop"] == ["ALL"]
    assert policy["read_only"] is True
    assert policy["pids_limit"] == 128
    assert "no-new-privileges:true" in policy["security_opt"]
    assert "/tmp" in policy["tmpfs"]
    assert "/sentinel-work" not in policy["tmpfs"]


def test_privileged_policy_requires_explicit_opt_in() -> None:
    policy = _container_security_options(
        allow_privileged=True,
        network_disabled=True,
        pids_limit=128,
    )

    assert policy["privileged"] is True
    assert policy["security_opt"] == ["seccomp=unconfined"]


def test_missing_finding_harness_never_starts_generic_fuzzer() -> None:
    with TemporaryDirectory() as scratch:
        source = Path(scratch) / "project"
        source.mkdir()
        with patch("app.services.sandbox_manager._get_docker_client") as docker_client:
            result = run_sandbox_verification("task-id", str(source))
        assert "动态验证未执行" in (result.error or "")
        assert result.package_results == []
        docker_client.assert_not_called()
