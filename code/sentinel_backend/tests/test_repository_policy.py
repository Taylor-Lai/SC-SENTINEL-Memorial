from app.services.repository_policy import is_allowed_remote_repository_url


def test_repository_allowlist() -> None:
    assert is_allowed_remote_repository_url("https://github.com/openai/example.git")
    assert is_allowed_remote_repository_url("git@gitlab.com:team/project.git")


def test_repository_allowlist_rejects_arbitrary_hosts_and_paths() -> None:
    assert not is_allowed_remote_repository_url("https://127.0.0.1/internal.git")
    assert not is_allowed_remote_repository_url("https://evil.example/project.git")
    assert not is_allowed_remote_repository_url("file:///etc/passwd")
