from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.services.sandbox_manager import (
    _container_security_options,
    _run_asan_seed_probe,
    _run_harness_package,
    run_sandbox_verification,
)


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


def test_asan_seed_crash_does_not_skip_afl_and_default_skips_ebpf() -> None:
    class Container:
        commands = []

        def exec_run(self, command, demux=False):
            self.commands.append(command[-1])
            return 0, b""

    container = Container()
    package = {"package_id": "HARNESS-0001", "finding_id": "FIND-0001", "target_file": "source.c", "cwe_id": "CWE-134"}
    with (
        patch("app.services.sandbox_manager._run_format_string_probe", return_value=([{"event": "format_string_suspected"}], "probe log")),
        patch("app.services.sandbox_manager._run_asan_seed_probe", return_value=(True, "ERROR: AddressSanitizer", 1)),
        patch("app.services.sandbox_manager._parse_afl_crashes", return_value=(True, "[AFL++] crash_count=1", {"execs_done": "1"})),
        patch("app.services.sandbox_manager._read_container_text", return_value=""),
        patch("app.services.sandbox_manager._start_ebpf_for_pid") as start_ebpf,
    ):
        result = _run_harness_package(container, package, 15)

    assert result["crash_found"] is True
    assert "[ASan]" in result["afl_crash_log"]
    assert "[AFL++] crash_count=1" in result["afl_crash_log"]
    assert result["probe_suspected"] is True
    assert result["ebpf_events"] == []
    assert any("afl-fuzz" in command and "-i fuzz_seeds" in command for command in container.commands)
    start_ebpf.assert_not_called()


def test_asan_probe_requires_sanitizer_diagnostic() -> None:
    class Container:
        def exec_run(self, command, demux=False):
            assert "fuzz_seeds" in command[-1]
            return 0, b""

    with patch("app.services.sandbox_manager._read_container_text", return_value="target printed heap-use-after-free"):
        confirmed, _, safe_count = _run_asan_seed_probe(Container(), "/harness", "/harness/logs")
    assert confirmed is False
    assert safe_count == 0


def test_all_crashing_seeds_keep_asan_result_without_starting_afl() -> None:
    class Container:
        commands = []

        def exec_run(self, command, demux=False):
            self.commands.append(command[-1])
            return 0, b""

    container = Container()
    package = {"package_id": "HARNESS-0001", "finding_id": "FIND-0001", "target_file": "source.c"}
    with patch("app.services.sandbox_manager._run_asan_seed_probe", return_value=(True, "ERROR: AddressSanitizer", 0)):
        result = _run_harness_package(container, package, 15)

    assert result["crash_found"] is True
    assert "没有非崩溃初始种子" in result["error"]
    assert all("afl-fuzz" not in command for command in container.commands)
