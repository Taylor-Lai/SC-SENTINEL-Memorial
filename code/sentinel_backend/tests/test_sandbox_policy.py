from app.services.sandbox_manager import _container_security_options


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
